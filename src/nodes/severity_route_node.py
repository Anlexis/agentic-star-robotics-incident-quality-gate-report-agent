"""AgentCore Platform v1.0"""

# MFG-C2-058 — SeverityRouteNode
# Domain node 3: determine the incident severity level (CRITICAL / HIGH /
# MEDIUM / LOW) and the quality-gate routing decision from the classification
# and telemetry.
#
# This node reads the one runtime parameter an operator is expected to tune:
# low_confidence_threshold, declared in config/config.yaml. It arrives here in
# state, seeded by the inner graph from the config the outer graph was built
# with — see src/graph/domain_workflow_graph.py for the whole path. Before the
# migration the nodes took an `execute(state, config=None)` argument that the
# framework never supplies, so every declared value was silently the default.
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
from src.services.service import finite_in_range

logger = logging.getLogger(__name__)

# Baseline severity by incident type. A safety boundary breach is always
# treated as the most serious.
_BASE_SEVERITY_BY_TYPE: Dict[str, str] = {
    "safety_boundary_breach": "CRITICAL",
    "mechanical_failure": "HIGH",
    "software_fault": "MEDIUM",
    "calibration_error": "MEDIUM",
    "unknown": "LOW",
}

# Severity ordering for escalation comparisons.
_SEVERITY_ORDER: List[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Quality-gate routing decision per severity.
_QUALITY_GATE_BY_SEVERITY: Dict[str, str] = {
    "CRITICAL": "line_stop_and_safety_review",
    "HIGH": "hold_unit_and_engineering_review",
    "MEDIUM": "flag_for_scheduled_maintenance",
    "LOW": "log_and_monitor",
}

# Error-code prefixes that force at least HIGH regardless of base severity.
_ESCALATING_CODE_PREFIXES = ("SAF", "ESTOP", "BND", "ZONE", "BRK")

#: Used when config declares nothing, and when it declares something unusable.
DEFAULT_LOW_CONFIDENCE_THRESHOLD = 0.5


def _escalate(current: str, floor: str) -> str:
    """Raise `current` to at least `floor` on the severity ladder."""
    if _SEVERITY_ORDER.index(floor) > _SEVERITY_ORDER.index(current):
        return floor
    return current


class SeverityRouteNode(FunctionNode):
    """Resolve severity and the quality-gate routing decision.

    Input state keys:
        incident_classification: classification record (from IncidentClassifyNode)
        parsed_telemetry:        telemetry record (for escalating error codes)
        runtime_limits:          declared runtime parameters (from config.yaml)

    Output state keys (partial dict):
        severity_level: {"severity": str, "quality_gate": str,
                         "escalate": bool, "rationale": [...]}
    """

    # Reachable only behind PreProcessNode's S-1 gate.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        classification: Dict[str, Any] = from_json(state.get("incident_classification"), {})
        telemetry: Dict[str, Any] = from_json(state.get("parsed_telemetry"), {})
        limits: Dict[str, Any] = from_json(state.get("runtime_limits"), {}) or {}

        incident_type = str(classification.get("incident_type", "unknown"))
        # Confidence travels through a JSON string field, so it is parsed rather
        # than trusted: NaN and Infinity both parse cleanly and then compare
        # False against every bound, which would silently skip the escalation
        # below. finite_in_range falls back to 0.0 instead.
        confidence = finite_in_range(classification.get("confidence", 0.0), 0.0, 1.0, 0.0)
        threshold = finite_in_range(
            limits.get("low_confidence_threshold", DEFAULT_LOW_CONFIDENCE_THRESHOLD),
            0.0,
            1.0,
            DEFAULT_LOW_CONFIDENCE_THRESHOLD,
        )
        error_codes: List[str] = [str(c) for c in telemetry.get("error_codes", [])]

        rationale: List[str] = []
        severity = _BASE_SEVERITY_BY_TYPE.get(incident_type, "LOW")
        rationale.append(f"Base severity for '{incident_type}' is {severity}.")

        # Escalate on safety-critical error codes.
        for code in error_codes:
            if any(code.startswith(p) for p in _ESCALATING_CODE_PREFIXES):
                new_sev = _escalate(severity, "HIGH")
                if new_sev != severity:
                    rationale.append(f"A safety-critical error code was reported — escalated to {new_sev}.")
                    severity = new_sev
                break

        # Low-confidence classifications are escalated one step for safe review,
        # but never above HIGH (a genuine CRITICAL is already locked in above).
        if 0.0 < confidence < threshold and severity in ("LOW", "MEDIUM"):
            new_sev = _escalate(severity, "MEDIUM" if severity == "LOW" else "HIGH")
            rationale.append(
                f"Classification confidence {confidence:.2f} is below the configured "
                f"threshold {threshold:.2f} — escalated to {new_sev} for review."
            )
            severity = new_sev

        quality_gate = _QUALITY_GATE_BY_SEVERITY.get(severity, "log_and_monitor")
        escalate = severity in ("CRITICAL", "HIGH")

        severity_level: Dict[str, Any] = {
            "severity": severity,
            "quality_gate": quality_gate,
            "escalate": escalate,
            "confidence": round(confidence, 3),
            "low_confidence_threshold": round(threshold, 3),
            "rationale": rationale,
        }

        # S-4 domain audit: severity + routing decided.
        emit_trace_event(
            "robotics_incident_severity_routed",
            {
                "severity": severity,
                "quality_gate": quality_gate,
                "escalate": escalate,
                "low_confidence_threshold": round(threshold, 3),
            },
            state,
        )

        logger.info(
            "SeverityRouteNode: severity=%s, gate=%s, escalate=%s, threshold=%.2f",
            severity,
            quality_gate,
            escalate,
            threshold,
        )

        return {
            "severity_level": to_json(severity_level),
        }
