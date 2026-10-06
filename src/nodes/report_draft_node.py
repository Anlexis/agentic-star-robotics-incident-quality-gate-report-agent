"""AgentCore Platform v1.0"""

# MFG-C2-058 — ReportDraftNode
# Domain node 4: draft the structured robotics incident report from the
# classification, severity routing and telemetry — summary, classification,
# severity, root cause, and recommended corrective actions.
#
# Deterministic section synthesis from the structured upstream facts. Every
# value interpolated into a section body has already been through the ingest
# node's bounds, so nothing that reaches this renderer can carry a newline, a
# heading marker or a list bullet.
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

# Recommended corrective actions per incident type (engineering playbook).
_CORRECTIVE_ACTIONS_BY_TYPE: Dict[str, List[str]] = {
    "safety_boundary_breach": [
        "Stop the line and physically secure the affected cell before re-entry.",
        "Verify safety-zone scanners and interlocks against the guarding standard in force.",
        "Conduct a root-cause safety review before resuming automated operation.",
    ],
    "mechanical_failure": [
        "Isolate the affected axis / actuator and inspect for wear or overheating.",
        "Replace the failed mechanical component and re-run the axis calibration.",
        "Schedule preventive maintenance for sibling units on the same line.",
    ],
    "software_fault": [
        "Capture controller logs and firmware version for the affected window.",
        "Apply the validated firmware/control patch and re-run the regression suite.",
        "Add a watchdog / timeout guard for the faulting control path.",
    ],
    "calibration_error": [
        "Re-run the TCP / zero-point calibration procedure on the affected robot.",
        "Verify tool offsets against the master reference before production resume.",
        "Tighten the calibration-drift monitoring threshold for early detection.",
    ],
    "unknown": [
        "Collect additional telemetry and route to a robotics engineer for triage.",
        "Hold the affected unit pending manual diagnosis.",
    ],
}

#: Rendered wherever an identifier was not supplied at all. Distinct from the
#: ingest node's placeholders, which say the value WAS supplied and was not
#: usable — a reader needs to be able to tell those two cases apart.
_UNSPECIFIED = "(unspecified)"


def _draft_root_cause(incident_type: str, signals: List[str], error_code_count: int) -> str:
    """Compose a deterministic root-cause narrative from the matched signals.

    Signals are the classifier's own labels — a closed keyword set and error
    codes already held to the inert alphabet — so they are safe to render. The
    codes themselves are summarised by count rather than listed again; they
    already appear in the telemetry section the reviewer is reading alongside.
    """
    type_label = incident_type.replace("_", " ")
    code_part = f" {error_code_count} controller error code(s) were reported." if error_code_count else ""
    signal_part = f" Supporting signals: {', '.join(signals[:MAX_SIGNALS_RENDERED])}." if signals else ""
    return (
        f"The incident is consistent with a {type_label}.{code_part}{signal_part} "
        "This root cause is derived from the normalised telemetry and the "
        "classification result; confirm against the physical unit during review."
    )


def _format_actions(actions: List[str]) -> str:
    """Render the corrective-action list as Markdown bullet lines."""
    return "\n".join(f"- {a}" for a in actions)


class ReportDraftNode(FunctionNode):
    """Draft the structured robotics incident report (deterministic synthesis).

    Input state keys:
        incident_classification: classification record (from IncidentClassifyNode)
        severity_level:          severity + routing (from SeverityRouteNode)
        parsed_telemetry:        telemetry record (for identifiers + code count)

    Output state keys (partial dict):
        report_draft: {section_key: drafted prose} (no operator PII)
    """

    # Reachable only behind PreProcessNode's S-1 gate.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        classification: Dict[str, Any] = from_json(state.get("incident_classification"), {})
        severity_level: Dict[str, Any] = from_json(state.get("severity_level"), {})
        telemetry: Dict[str, Any] = from_json(state.get("parsed_telemetry"), {})

        incident_type = str(classification.get("incident_type", "unknown"))
        confidence = classification.get("confidence", 0.0)
        signals: List[str] = [str(s) for s in classification.get("signals", [])]
        severity = str(severity_level.get("severity", "LOW"))
        quality_gate = str(severity_level.get("quality_gate", "log_and_monitor"))
        robot_id = str(telemetry.get("robot_id", "")) or _UNSPECIFIED
        line_id = str(telemetry.get("line_id", "")) or _UNSPECIFIED
        error_codes: List[str] = [str(c) for c in telemetry.get("error_codes", [])]
        data_quality: List[str] = [str(f) for f in telemetry.get("data_quality", [])]
        # The severity node's own reasoning, rendered rather than discarded. A
        # reviewer asked to stop a line needs to see WHY the severity was
        # assigned — including which configured threshold was in force — and
        # every entry is composed by this template from closed-set values.
        rationale: List[str] = [str(r) for r in severity_level.get("rationale", [])]

        summary = (
            f"Robot {robot_id} on line {line_id} reported an incident classified as "
            f"'{incident_type}' (confidence {confidence}). Assigned severity "
            f"{severity}; quality-gate action: {quality_gate}."
        )

        actions = _CORRECTIVE_ACTIONS_BY_TYPE.get(incident_type, _CORRECTIVE_ACTIONS_BY_TYPE["unknown"])

        report_draft: Dict[str, str] = {
            "summary": summary,
            "classification": (f"Incident type: {incident_type.replace('_', ' ')} " f"(confidence {confidence})."),
            "severity": (
                f"Severity {severity}. Quality-gate routing: {quality_gate}. "
                f"Escalation required: {bool(severity_level.get('escalate', False))}."
            ),
            "telemetry": (
                f"Reported controller error codes: {', '.join(error_codes)}."
                if error_codes
                else "No controller error codes were reported."
            ),
            "root_cause": _draft_root_cause(incident_type, signals, len(error_codes)),
            "corrective_actions": _format_actions(actions),
        }

        if rationale:
            report_draft["severity_rationale"] = _format_actions(rationale)

        # A reader must be able to see that a field was rejected — otherwise the
        # report reads as complete when part of its input was discarded.
        if data_quality:
            report_draft["data_quality"] = _format_actions(
                [f"Input field not usable as supplied: `{flag}`" for flag in data_quality]
            )

        # S-4 domain audit: report draft generated.
        emit_trace_event(
            "robotics_incident_report_drafted",
            {
                "incident_type": incident_type,
                "severity": severity,
                "section_count": len(report_draft),
            },
            state,
        )

        logger.info(
            "ReportDraftNode: drafted %d sections (type=%s, severity=%s)",
            len(report_draft),
            incident_type,
            severity,
        )

        return {
            "report_draft": to_json(report_draft),
        }
