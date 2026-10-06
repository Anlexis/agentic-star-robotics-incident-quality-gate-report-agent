"""AgentCore Platform v1.0"""

# MFG-C2-058 — IncidentClassifyNode
# Domain node 2: classify the robotics incident by type (mechanical failure,
# software fault, safety boundary breach, calibration error) from the
# normalised telemetry record.
#
# The classification is DETERMINISTIC: rules over the structured telemetry, not
# model output. That is a property, not a limitation — the same telemetry must
# yield the same severity between shifts for the report to be usable in a safety
# review, and a rule table is something a plant engineer can read and amend.
# The manifest declares generation_mode: deterministic to match.
#
# Wired by the inner graph (DomainWorkflowGraph).
# Returns only changed state keys (partial dict).

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json
from src.services.service import MAX_SIGNALS_RENDERED

logger = logging.getLogger(__name__)

# Incident type -> error-code prefixes and keyword signals that imply it.
# Evaluated in order; safety_boundary_breach is checked first (highest concern).
_CLASSIFICATION_RULES: List[Dict[str, Any]] = [
    {
        "type": "safety_boundary_breach",
        "code_prefixes": ("SAF", "ESTOP", "BND", "ZONE"),
        "keywords": ("boundary", "estop", "e-stop", "intrusion", "guard", "zone", "collision"),
    },
    {
        "type": "calibration_error",
        "code_prefixes": ("CAL", "TCP", "ZERO"),
        "keywords": ("calibration", "tcp", "offset", "zero point", "drift", "misalign"),
    },
    {
        "type": "software_fault",
        "code_prefixes": ("SW", "FW", "CTRL", "COMM", "NET"),
        "keywords": ("firmware", "software", "controller", "exception", "timeout", "watchdog", "comm"),
    },
    {
        "type": "mechanical_failure",
        "code_prefixes": ("MEC", "MOT", "SRV", "AXIS", "GEAR", "BRK"),
        "keywords": ("motor", "servo", "gearbox", "bearing", "overheat", "torque", "brake", "vibration"),
    },
]

#: Confidence floor and ceiling. Confidence grows with the number of matched
#: signals and is capped short of certainty: a rule match is evidence for a
#: classification, never proof of one, and a report that claimed 1.0 would be
#: overstating what a keyword match can support.
_CONFIDENCE_BASE = 0.5
_CONFIDENCE_PER_SIGNAL = 0.15
_CONFIDENCE_CEILING = 0.95


def _collect_text_signals(telemetry: Dict[str, Any]) -> str:
    """Build a lowercase haystack from the free-text note and sensor keys.

    Both are caller data, already bounded and held to the inert alphabet by the
    ingest node — the haystack is read, never rendered.
    """
    parts: List[str] = [str(telemetry.get("free_text", ""))]
    parts.extend(str(k) for k in telemetry.get("sensor_reading_keys", []) or [])
    return " ".join(parts).lower()


def _score_rule(rule: Dict[str, Any], error_codes: List[str], haystack: str) -> List[str]:
    """Return the list of matched signals for one classification rule."""
    matched: List[str] = []
    for code in error_codes:
        for prefix in rule["code_prefixes"]:
            if code.startswith(prefix):
                matched.append(f"code:{code}")
                break
    for kw in rule["keywords"]:
        if kw in haystack:
            matched.append(f"kw:{kw}")
    return matched


class IncidentClassifyNode(FunctionNode):
    """Classify the robotics incident type from normalised telemetry.

    Input state keys:
        parsed_telemetry: normalised telemetry record (from TelemetryParseNode)

    Output state keys (partial dict):
        incident_classification: {"incident_type": str, "confidence": float,
                                  "signals": [...], "candidate_types": [...]}
    """

    # Reachable only behind PreProcessNode's S-1 gate.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        telemetry: Dict[str, Any] = from_json(state.get("parsed_telemetry"), {})
        error_codes: List[str] = [str(c) for c in telemetry.get("error_codes", [])]
        haystack = _collect_text_signals(telemetry)

        candidate_types: List[Dict[str, Any]] = []
        for rule in _CLASSIFICATION_RULES:
            matched = _score_rule(rule, error_codes, haystack)
            if matched:
                candidate_types.append({"type": rule["type"], "signal_count": len(matched), "signals": matched})

        if candidate_types:
            best = max(candidate_types, key=lambda c: c["signal_count"])
            incident_type = best["type"]
            # Capped: the report renders the signal list, and an unbounded list
            # is an unbounded report section.
            signals = best["signals"][:MAX_SIGNALS_RENDERED]
            confidence = min(
                _CONFIDENCE_BASE + _CONFIDENCE_PER_SIGNAL * best["signal_count"],
                _CONFIDENCE_CEILING,
            )
        else:
            incident_type = "unknown"
            signals = []
            confidence = 0.0

        incident_classification: Dict[str, Any] = {
            "incident_type": incident_type,
            "confidence": round(confidence, 3),
            "signals": signals,
            "candidate_types": [c["type"] for c in candidate_types],
        }

        # S-4 domain audit: incident classified.
        emit_trace_event(
            "robotics_incident_classified",
            {
                "incident_type": incident_type,
                "confidence": incident_classification["confidence"],
                "candidate_count": len(candidate_types),
            },
            state,
        )

        logger.info(
            "IncidentClassifyNode: type=%s, confidence=%.2f, %d candidates",
            incident_type,
            confidence,
            len(candidate_types),
        )

        return {
            "incident_classification": to_json(incident_classification),
        }
