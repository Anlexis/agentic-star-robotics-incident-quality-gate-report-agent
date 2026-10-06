"""AgentCore Platform v1.0"""

# MFG-C2-058 — Domain injection screen (S-2 extension).
#
# The framework's own injection policy runs first, on the RAW request text, and
# blocks what it recognises. This module covers what it does not, measured
# against the installed SDK rather than assumed:
#
#   1. `<<SYS>>` scores no findings at all. `<|system|>` and `<|endoftext|>`
#      likewise. The framework matches `<|im_start|>` / `<|im_end|>` by name and
#      `[INST]` / `[SYS]` in square brackets — the class is wider than the
#      members it enumerates, so it is screened here as a class.
#
#   2. The framework scans the request BEFORE it is parsed. This agent's caller
#      data is a JSON document, so `"<|im_start|>"` contains no
#      literal marker until json.loads runs. Measured on this template: such a
#      payload passed the framework scan and the marker reached the rendered
#      report. A post-parse scan is the only thing that can see it.
#
#   3. The framework scans VALUES. A marker sitting in a KEY is not scanned by
#      it and is not scanned by the credential detector either. Keys steer this
#      agent's classifier, so keys are screened here.
#
#   4. A sanitiser is not a refusal. Stripping markup out of a directive leaves
#      the directive behind as ordinary prose and destroys the evidence that it
#      was an attack. Every string is therefore screened BOTH as received and
#      after markup removal: tokens are caught before a strip could remove them,
#      and directives spliced with markup ("ig<b>nore all previous...") are
#      caught after the strip re-assembles them.
#
# The screen FAILS CLOSED: any finding rejects the request. It reports a
# closed-set reason label and never the matched text.

from __future__ import annotations

import re
import unicodedata
import urllib.parse
from typing import Any, Final, List

#: Depth ceiling for the recursive walk. A deeply nested document is itself a
#: structural attack; refusing it is cheaper than recursing into it.
MAX_SCAN_DEPTH: Final[int] = 12

#: Node ceiling for the recursive walk, for the same reason.
MAX_SCAN_NODES: Final[int] = 5_000

_ZERO_WIDTH_RE: Final[re.Pattern[str]] = re.compile("[\\u200b\\u200c\\u200d\\ufeff\\u00ad]")

#: Markup strip used only to produce the SECOND view of each string.
_MARKUP_RE: Final[re.Pattern[str]] = re.compile(r"<[^<>]{0,200}>")

_PATTERNS: Final[List[tuple[str, re.Pattern[str]]]] = [
    # Chat-template control tokens, screened as a CLASS rather than by name:
    # any `<|...|>` pipe-delimited marker, however it is spelled.
    ("chat_control_token", re.compile(r"<\s*\|[^|<>]{0,64}\|\s*>")),
    # Llama-family instruction and system markers, in either bracket style.
    ("chat_control_token", re.compile(r"\[/?\s*(?:INST|SYS)\s*\]", re.IGNORECASE)),
    ("chat_control_token", re.compile(r"<<\s*/?\s*SYS\s*>>", re.IGNORECASE)),
    # Turn-boundary forgery in tag form.
    ("chat_control_token", re.compile(r"<\s*/?\s*(?:system|user|assistant)\s*>", re.IGNORECASE)),
    # Markdown-heading turn forgery.
    ("chat_control_token", re.compile(r"#{2,}\s*(?:system|instruction|assistant)\b", re.IGNORECASE)),
    # Instruction-override directives, kept narrow enough not to fire on an
    # engineer writing "ignore the previous reading".
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?"
            r"(?:previous|prior|above|earlier|preceding)\s+"
            r"(?:instruction|prompt|rule|direction|context|message)",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as)\s+(?:a|an)?\s*"
            r"(?:different|new|unrestricted|unfiltered|jailbroken|admin|root|superuser)\b",
            re.IGNORECASE,
        ),
    ),
    ("instruction_override", re.compile(r"\bjailbreak(?:ing|ed)?\b", re.IGNORECASE)),
]


def _normalise(text: str) -> str:
    """Undo the obfuscations that would otherwise defeat a literal match."""
    text = urllib.parse.unquote(text)
    text = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH_RE.sub("", text)


def screen_text(text: str) -> List[str]:
    """Return the reason labels found in one string, as received and stripped."""
    if not text:
        return []
    found: List[str] = []
    received = _normalise(text)
    # The second view: markup removed, so a directive spliced with tags is
    # re-assembled into the plain phrasing the patterns above recognise.
    stripped = _MARKUP_RE.sub("", received)
    for view in (received, stripped):
        for label, pattern in _PATTERNS:
            if label not in found and pattern.search(view):
                found.append(label)
    return found


def screen_value(value: Any, _depth: int = 0, _budget: List[int] | None = None) -> List[str]:
    """Screen a parsed JSON-like value depth-first, KEYS as well as values.

    Keys are screened because they are not covered by any framework scan and
    because this agent reads mapping keys as classification signals. The walk is
    bounded on both depth and node count and refuses rather than recurses when
    either ceiling is reached.
    """
    if _budget is None:
        _budget = [MAX_SCAN_NODES]
    if _depth > MAX_SCAN_DEPTH:
        return ["structure_too_deep"]
    if _budget[0] <= 0:
        return ["structure_too_large"]
    _budget[0] -= 1

    if isinstance(value, str):
        return screen_text(value)
    if isinstance(value, dict):
        found: List[str] = []
        for key, nested in value.items():
            if isinstance(key, str):
                for reason in screen_text(key):
                    if reason not in found:
                        found.append(reason)
            for reason in screen_value(nested, _depth + 1, _budget):
                if reason not in found:
                    found.append(reason)
        return found
    if isinstance(value, (list, tuple)):
        found = []
        for item in value:
            for reason in screen_value(item, _depth + 1, _budget):
                if reason not in found:
                    found.append(reason)
        return found
    return []
