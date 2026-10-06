"""AgentCore Platform v1.0"""

# MFG-C2-058 — PreProcessNode (outer pre_process slot; S-1/S-2 input gate).
#
# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Read input_context via state.get("input_context", {}) — read-only
#  - Never import from mediator/, api/, or other agents
#
# This node is the pipeline's entry gate and carries the manifest's declared
# trust level. Every node behind it is reachable only through it.
#
# Two gates run here, in this order, and both fail CLOSED:
#
#   _extra_security_gate_input()  — the domain injection screen. It runs BEFORE
#       execute(), which is the point: a request that fails it never reaches any
#       domain code. The framework's own injection policy has already run by
#       then, on the raw request; this screen covers the classes it does not
#       (see src/services/injection_screen.py) and, critically, screens the
#       PARSED document, where JSON escapes have become the characters they
#       encode.
#
#   execute() — S-1 shape and size, then the S-2 surface identifier redaction.
#
# Note on the redaction below: it is a defence-in-depth surface pass, not the
# containment boundary. The platform's own input filter has already masked what
# it recognises by the time this runs, and the report is assembled from
# validated fields rather than from this text.

import json
import re
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.services import credential_screen
from src.services.injection_screen import screen_text, screen_value
from src.services.service import MAX_INPUT_CHARS, MIN_INPUT_CHARS

# Surface-level operator-PII / identifier patterns redacted before
# validated_input is written.
_PII_PATTERNS: List[re.Pattern[str]] = [
    # E-mail addresses.
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    # Japanese phone numbers (loose): 0XX-XXXX-XXXX / 0XXXXXXXXXX.
    re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b"),
    # Operator / employee badge identifiers (e.g. EMP-123456, OP123456).
    re.compile(r"\b(?:EMP|OP|BADGE)-?\d{4,}\b", re.IGNORECASE),
]
_PII_REPLACEMENT = "[REDACTED]"

#: Returned to the caller on every entry-gate refusal.
#:
#: Two reasons it is set rather than left absent. It is what the caller reads:
#: a refusal that surfaces as status=error with a null output tells them nothing,
#: and error_log is not projected into the response envelope. And it is truthy,
#: which closes AgentBaseGraph.get_output()'s fallback — that fallback answers an
#: absent or falsy formatted_output with state["result"], so an ungated report
#: sitting in state would ship inside the error envelope of a refused request.
#:
#: The text is fixed. It names no field, quotes no input and reveals no
#: threshold, because everything the gate rejected is caller-controlled and a
#: refusal that echoes its input is a reflection channel.
_REFUSED_NOTICE = (
    "[REQUEST REFUSED] The incident record was rejected by the input safety gate "
    "and no report was generated. Resubmit the telemetry without embedded "
    "instructions or credential-like strings."
)


def _surface_strip_pii(text: str) -> str:
    """Redact obvious operator-PII / identifier tokens from a free-text string."""
    for pattern in _PII_PATTERNS:
        text = pattern.sub(_PII_REPLACEMENT, text)
    return text


def screen_request(user_input: str) -> List[str]:
    """Screen one request as text and, when it parses, as a document.

    Both views are needed and neither subsumes the other. The text view catches
    a marker written literally. The document view catches a marker written as a
    JSON escape — which is invisible to any scan that runs before json.loads,
    including the framework's — and catches markers sitting in KEYS, which no
    framework scan looks at.

    Credential shapes are refused here for a different reason. A
    credential-shaped value in an incident record cannot produce a successful
    run either way: the ingest node puts it in its own result, the framework's
    output gate scans every value of every result and raises, and the caller
    receives an opaque error with nothing naming the field. Refusing at the
    entry gate makes the same outcome readable. The screen is the union of this
    template's patterns and the framework's, defined once in
    src/services/credential_screen.py.
    """
    reasons: List[str] = list(screen_text(user_input))
    found = credential_screen.screen_text(user_input)
    if found:
        reasons.append(f"credential_shape:{found}")

    try:
        parsed = json.loads(user_input)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return reasons

    for reason in screen_value(parsed):
        if reason not in reasons:
            reasons.append(reason)
    found = credential_screen.screen_value(parsed)
    if found and f"credential_shape:{found}" not in reasons:
        reasons.append(f"credential_shape:{found}")
    return reasons


class PreProcessNode(FunctionNode):
    """S-1/S-2 input gate: validate and screen input before main processing.

    Rejects empty, oversized and injection-bearing robotics-incident input
    before the inner domain workflow graph runs, and redacts operator
    identifiers so no obvious operator PII reaches the inner pipeline.
    """

    # The manifest's declared entry contract. Every node behind this one sits at
    # ANONYMOUS: they are not independently addressable, and requiring more of
    # them than the entry point requires would refuse callers the manifest
    # admits — which is exactly how this agent used to fail every request.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_input(self, state: AgentState) -> AgentState:
        """Domain S-2 extension — refuse an injection-bearing request.

        Runs before execute(). Rejection is signalled through state, per the
        gate contract; the reason is a closed-set label and the offending text
        is never reflected back to the caller or into the audit payload.
        """
        user_input = state.get("user_input", "")
        if not isinstance(user_input, str) or not user_input:
            return state

        reasons = screen_request(user_input)
        if not reasons:
            return state

        emit_trace_event(
            "robotics_incident_request_refused",
            {"gate": "s2_injection_screen", "reasons": reasons},
            state,
        )
        state = dict(state)
        state["status"] = AgentStatus.ERROR.value
        state["formatted_output"] = _REFUSED_NOTICE
        state["result"] = _REFUSED_NOTICE
        state["error_log"] = [
            *state.get("error_log", []),
            "PreProcessNode [S-2]: request refused by the input safety gate " f"({', '.join(reasons)})",
        ]
        return state

    def execute(self, state: AgentState) -> Dict[str, Any]:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only
        if not isinstance(input_context, dict):
            input_context = {}

        if not user_input or not isinstance(user_input, str) or not user_input.strip():
            return {
                "status": AgentStatus.ERROR.value,
                "formatted_output": _REFUSED_NOTICE,
                "result": _REFUSED_NOTICE,
                "error_log": ["PreProcessNode: user_input is empty or missing"],
            }

        stripped = user_input.strip()
        if len(stripped) < MIN_INPUT_CHARS or len(stripped) > MAX_INPUT_CHARS:
            # Size is stated as a bound, not as the offending length, so the
            # refusal cannot be used to measure what the filter accepted.
            return {
                "status": AgentStatus.ERROR.value,
                "formatted_output": _REFUSED_NOTICE,
                "result": _REFUSED_NOTICE,
                "error_log": [
                    "PreProcessNode: incident record outside the accepted size "
                    f"({MIN_INPUT_CHARS}-{MAX_INPUT_CHARS} characters)"
                ],
            }

        validated_input = _surface_strip_pii(stripped)

        # S-4 domain audit: a robotics-incident report request was accepted and
        # surface-screened (no operator PII in the payload).
        emit_trace_event(
            "robotics_incident_request_accepted",
            {"input_chars": len(validated_input)},
            state,
        )

        enriched_context: Dict[str, Any] = {
            "source": "ManufacturingRoboticsIncidentClassificationQualityGateReportAgent",
            "channel": str(input_context.get("channel", "unknown"))[:64],
        }
        return {
            "validated_input": validated_input,
            "enriched_context": enriched_context,
            "status": AgentStatus.SUCCESS.value,
        }
