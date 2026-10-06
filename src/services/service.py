"""AgentCore Platform v1.0"""

# MFG-C2-058 — Domain contract for one robotics incident record.
#
# Service layer: the shape of the caller's data and the bounds every field is
# held to. No business logic, no routing, no credentials — the classification,
# severity and drafting rules live in src/nodes/.
#
# This module is the single definition of the caller contract. The HTTP adapter
# (src/api/server.py) and the ingest node (src/nodes/telemetry_parse_node.py)
# both import from here so the bound enforced at the edge and the bound enforced
# inside the pipeline cannot drift apart.
#
# Two properties the bounds exist to hold:
#
#   1. Structural caps. One incident record is one incident. Without caps a
#      caller can hand over 500 error codes or 30 000 characters of note text
#      and the rendered report grows without limit.
#   2. Inert rendering. Values that reach the rendered Markdown report are
#      constrained to a character set that cannot express Markdown structure —
#      no newline, no '#', no '-' at the start of a line. A robot identifier is
#      caller data; if it can carry a line break it can forge a report section,
#      and this report is read as a safety document.
#
# A value that does not satisfy its bound is REPLACED, never echoed and never
# truncated-then-rendered: the report says the field was unusable and the
# data-quality section records which field it was.

from __future__ import annotations

import math
import re
from typing import Any, Dict, Final, List, Tuple

# ---------------------------------------------------------------------------
# Request-level bounds (enforced by the HTTP adapter and re-checked on ingest)
# ---------------------------------------------------------------------------

#: Smallest useful incident record — an empty request is rejected at S-1.
MIN_INPUT_CHARS: Final[int] = 1

#: One incident's telemetry export. Comfortably above a real Genesis-World
#: record (a few KB) and far below anything that could be an upload.
MAX_INPUT_CHARS: Final[int] = 32_000

#: Caller context keys this agent declares. The adapter DROPS everything else
#: before invoke() — an ignored key is still in the mapping handed to the graph
#: and still reaches the first node's result, where the framework's output scan
#: sees it. Ignoring is not stripping.
CALLER_CONTEXT_FIELDS: Final[frozenset[str]] = frozenset({"channel", "site_id", "locale", "requested_by_role"})

# ---------------------------------------------------------------------------
# Structural caps on one incident record
# ---------------------------------------------------------------------------

MAX_ERROR_CODES: Final[int] = 32
MAX_JOINT_STATES: Final[int] = 64
MAX_SENSOR_READINGS: Final[int] = 64
MAX_FREE_TEXT_CHARS: Final[int] = 4_000
MAX_SIGNALS_RENDERED: Final[int] = 24

#: Hard ceiling on the rendered report. The report is assembled from bounded
#: parts, so this is a backstop rather than the primary control.
MAX_REPORT_CHARS: Final[int] = 20_000

# ---------------------------------------------------------------------------
# Inert rendering alphabet
# ---------------------------------------------------------------------------

MAX_IDENTIFIER_CHARS: Final[int] = 32
MAX_ERROR_CODE_CHARS: Final[int] = 24

#: Robot / line / model identifiers as rendered into the report. Letters,
#: digits, '.', '_', '-' and single interior spaces only. No newline, no '#',
#: no '|', no '*', no leading '-' — none of the characters that would let a
#: caller-supplied identifier become a heading, a table row or a list item.
_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?: [A-Za-z0-9._-]+)*$")

#: Controller error codes. Upper-case by convention after normalisation.
_ERROR_CODE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9][A-Z0-9._-]*$")

#: Event windows are timestamps and intervals — "2026-09-01T10:00Z/…T10:05Z",
#: "…+09:00" — so ':' '/' and '+' join the alphabet for this field only. None
#: of the three can open Markdown structure on a line that cannot contain a
#: newline; the characters that can (# - | * ` [ ) stay excluded.
_EVENT_WINDOW_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]*(?: [A-Za-z0-9._:+/-]+)*$")

#: Sensor / joint keys are rendered nowhere today, but they are read as
#: classification signals, so they are held to the same inert alphabet before
#: they can influence a severity call.
_SIGNAL_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")

#: Substituted for any identifier that fails its bound. Chosen so it reads as a
#: statement about the data rather than as a value.
UNUSABLE_IDENTIFIER: Final[str] = "(not supplied in a usable form)"

#: Substituted for the whole identifier when the platform's input filter has
#: already replaced it. A redaction sentinel is not an extracted value and must
#: never be reported as one.
REDACTED_IDENTIFIER: Final[str] = "(redacted before processing)"

#: The sentinel the platform's S-2 input filter writes over matched personal
#: data. Title-case robot models ("Yaskawa Motoman") and operator-style robot
#: names match its person-name pattern, so this arrives on ordinary records.
MASK_SENTINEL: Final[str] = "[MASKED]"


def is_masked(value: str) -> bool:
    """Whether a value is, or contains, the platform redaction sentinel."""
    return MASK_SENTINEL in value


def clean_identifier(raw: Any, max_chars: int = MAX_IDENTIFIER_CHARS) -> Tuple[str, str]:
    """Return ``(value, reason)`` for one caller identifier.

    ``reason`` is empty when the value was usable. Otherwise ``value`` is a
    fixed placeholder and ``reason`` is a closed-set label naming why — never
    the offending text, which is caller data and must not be reflected.
    """
    if raw is None:
        return "", ""
    if not isinstance(raw, str):
        return UNUSABLE_IDENTIFIER, "not_a_string"
    value = raw.strip()
    if not value:
        return "", ""
    if is_masked(value):
        return REDACTED_IDENTIFIER, "redacted_by_input_filter"
    if len(value) > max_chars:
        return UNUSABLE_IDENTIFIER, "too_long"
    if not _IDENTIFIER_RE.match(value):
        return UNUSABLE_IDENTIFIER, "disallowed_characters"
    return value, ""


def clean_event_window(raw: Any, max_chars: int = 64) -> Tuple[str, str]:
    """Return ``(value, reason)`` for the event window — a timestamp or interval.

    Same contract as clean_identifier, over the timestamp alphabet.
    """
    if raw is None:
        return "", ""
    if not isinstance(raw, str):
        return UNUSABLE_IDENTIFIER, "not_a_string"
    value = raw.strip()
    if not value:
        return "", ""
    if is_masked(value):
        return REDACTED_IDENTIFIER, "redacted_by_input_filter"
    if len(value) > max_chars:
        return UNUSABLE_IDENTIFIER, "too_long"
    if not _EVENT_WINDOW_RE.match(value):
        return UNUSABLE_IDENTIFIER, "disallowed_characters"
    return value, ""


def clean_error_codes(raw: Any) -> Tuple[List[str], List[str]]:
    """Normalise the error-code list. Returns ``(codes, reasons)``.

    Codes are upper-cased, deduplicated in first-seen order, held to the inert
    alphabet and capped. Rejected entries are counted by reason, never echoed.
    """
    reasons: List[str] = []
    if raw is None:
        return [], reasons
    items = raw if isinstance(raw, list) else [raw]
    if len(items) > MAX_ERROR_CODES:
        reasons.append("error_codes_truncated")
        items = items[:MAX_ERROR_CODES]

    codes: List[str] = []
    seen: set[str] = set()
    dropped = 0
    for item in items:
        if not isinstance(item, (str, int)):
            dropped += 1
            continue
        text = str(item).strip().upper()
        if not text:
            continue
        if len(text) > MAX_ERROR_CODE_CHARS or not _ERROR_CODE_RE.match(text):
            dropped += 1
            continue
        if text in seen:
            continue
        seen.add(text)
        codes.append(text)
    if dropped:
        reasons.append("error_codes_rejected")
    return codes, reasons


def clean_free_text(raw: Any) -> Tuple[str, List[str]]:
    """Bound the free-text incident note. Never rendered; read as signal only."""
    reasons: List[str] = []
    if raw is None:
        return "", reasons
    if not isinstance(raw, str):
        return "", ["free_text_rejected"]
    text = raw.strip()
    if len(text) > MAX_FREE_TEXT_CHARS:
        text = text[:MAX_FREE_TEXT_CHARS]
        reasons.append("free_text_truncated")
    return text, reasons


def clean_signal_keys(raw: Any, cap: int) -> Tuple[Dict[str, Any], List[str]]:
    """Bound a caller-supplied mapping whose KEYS become classification signals.

    Values are carried through untouched — nothing compares them — but the key
    set is capped and held to the inert alphabet, because a key is what steers
    the classifier.
    """
    reasons: List[str] = []
    if not isinstance(raw, dict):
        return {}, (["sensor_readings_rejected"] if raw not in (None, {}) else [])
    out: Dict[str, Any] = {}
    dropped = 0
    for key in list(raw)[:cap]:
        if isinstance(key, str) and _SIGNAL_KEY_RE.match(key):
            out[key] = raw[key]
        else:
            dropped += 1
    if len(raw) > cap:
        reasons.append("sensor_readings_truncated")
    if dropped:
        reasons.append("sensor_readings_rejected")
    return out, reasons


def finite_in_range(raw: Any, low: float, high: float, default: float) -> float:
    """Parse a number and hold it to ``[low, high]``, failing CLOSED.

    ``float("nan")`` and ``float("inf")`` parse without error, and every
    comparison against NaN is False — so a bare range check silently admits
    them. Non-finite and out-of-range values both fall back to ``default``
    rather than travelling on.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    if value < low or value > high:
        return default
    return value


class Service:
    """Domain service.

    This template computes its report from the caller's own record and reads no
    external system, so the service layer carries the contract rather than an
    integration. A fork that adds a maintenance-history or parts-catalogue
    lookup puts the client here, behind a method, and leaves the nodes calling
    it rather than reaching for a client directly.
    """

    @staticmethod
    def contract() -> Dict[str, Any]:
        """The caller-facing bounds, as data — used by docs and by tests."""
        return {
            "min_input_chars": MIN_INPUT_CHARS,
            "max_input_chars": MAX_INPUT_CHARS,
            "max_error_codes": MAX_ERROR_CODES,
            "max_error_code_chars": MAX_ERROR_CODE_CHARS,
            "max_joint_states": MAX_JOINT_STATES,
            "max_sensor_readings": MAX_SENSOR_READINGS,
            "max_free_text_chars": MAX_FREE_TEXT_CHARS,
            "max_identifier_chars": MAX_IDENTIFIER_CHARS,
            "max_report_chars": MAX_REPORT_CHARS,
            "caller_context_fields": sorted(CALLER_CONTEXT_FIELDS),
        }
