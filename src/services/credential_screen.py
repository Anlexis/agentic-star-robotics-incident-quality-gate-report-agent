"""AgentCore Platform v1.0"""

# MFG-C2-058 — Credential screen: ONE definition, used by both gates.
#
# The screen is the UNION of this template's patterns and the framework's own
# detector. Measured against the installed SDK, the two sets do not describe the
# same things:
#
#   framework only : aws_key (AKIA...), stripe_key (sk_live_/sk_test_...),
#                    conn_string (postgresql://, mysql://, mongodb://, redis://)
#   local only     : credential_assignment (password=, secret=, api_key=, ...),
#                    pk- and ak- prefixed keys
#   both           : sk- keys, JWT, Bearer tokens
#
# Wider is safe; narrower is a bypass — in both directions:
#
#   * Dropping the local patterns to "delegate" to the framework looks like a
#     tightening and is a NARROWING. The framework's patterns describe
#     credential FORMATS and match nothing of the `password=hunter2` shape.
#
#   * Dropping the framework patterns is worse. The framework's S-3 gate scans
#     every value of every node result and RAISES on a finding. Anything it
#     catches that we miss makes it raise inside our own node, the wrapper
#     returns a bare error partial, our clearing is discarded, and
#     AgentBaseGraph.get_output() then falls back to state["result"] — shipping
#     the ungated report. A detector gap is a containment bypass.
#
# Screening the same classes on the way IN as on the way OUT is deliberate. A
# credential-shaped value in an incident record cannot produce a successful run
# either way: it lands in the first node's result and the framework raises there,
# before any of this template's code executes, which surfaces as an opaque error
# with a traceback and nothing pointing at the field. Refusing at the entry gate
# converts that into a readable refusal.
#
# No function here ever returns the matched text — only a closed-set class
# label. An error message that quotes the credential it just blocked has not
# blocked it.

from __future__ import annotations

import re
from typing import Any, Final, List, Optional, Tuple

from framework.security.credential_detector import (
    detect_credentials,
    detect_credentials_in_value,
)

#: Patterns the framework detector does NOT carry. Kept for that reason, not as
#: a re-implementation of what it does carry.
_LOCAL_PATTERNS: Final[List[Tuple[str, re.Pattern[str]]]] = [
    # Vendor-prefixed API keys. The framework covers sk-; pk- and ak- are ours.
    ("api_key", re.compile(r"\b(?:sk|pk|ak)-[A-Za-z0-9]{16,}", re.IGNORECASE)),
    # JWT with all three segments (the framework matches the header alone).
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # Bearer token in an Authorization-like context.
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/]{20,}", re.IGNORECASE)),
    # Credential ASSIGNMENTS. The framework carries no equivalent — its patterns
    # describe credential formats and `password=hunter2hunter2` has no format.
    (
        "credential_assignment",
        re.compile(
            r"\b(?:password|passwd|secret|api_key|token|access_key|private_key)\s*[:=]\s*\S{8,}",
            re.IGNORECASE,
        ),
    ),
]


def local_only_classes() -> List[str]:
    """The classes this template adds beyond the framework detector."""
    return sorted({name for name, _ in _LOCAL_PATTERNS})


def screen_text(content: str) -> Optional[str]:
    """Return the credential class found in one string, or None when clean."""
    if not isinstance(content, str) or not content:
        return None
    for name, pattern in _LOCAL_PATTERNS:
        if pattern.search(content):
            return name
    findings = detect_credentials(content)
    if findings:
        return str(findings[0]["type"])
    return None


def screen_value(value: Any) -> Optional[str]:
    """Return the credential class found anywhere in a JSON-like value.

    The framework half is delegated to detect_credentials_in_value, which is
    defined as the union over a mapping's values and a sequence's items — so a
    per-field call and a whole-document call refuse exactly the same set. That
    identity is what lets a caller name the offending field without widening or
    narrowing the block set.
    """
    if isinstance(value, str):
        return screen_text(value)
    if isinstance(value, dict):
        for nested in value.values():
            found = screen_value(nested)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for item in value:
            found = screen_value(item)
            if found:
                return found
    else:
        return None
    findings = detect_credentials_in_value(value)
    return str(findings[0]["type"]) if findings else None
