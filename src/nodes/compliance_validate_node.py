"""AgentCore Platform v1.0"""

# MFG-C2-058 — ComplianceValidateNode
# Domain node 5 (terminal): check the drafted incident report against the
# robotics-safety completeness checklist, append the checklist result, and
# render the final structured report (Markdown).
#
# Two things this node deliberately does NOT do.
#
# It does not claim regulatory conformance. The checklist establishes that the
# report CONTAINS the elements a safety review needs — a classification, a
# severity, corrective actions, and a safety-review routing for the most serious
# incidents. Whether the plant is compliant is a judgement made by a reviewer
# reading this report, not by this agent. The rendered verdict therefore reads
# "checklist COMPLETE / INCOMPLETE", not "compliance PASS". A template published
# without warranty cannot also certify a regulator's standard.
#
# It does not fail the run when the checklist is incomplete. An incomplete
# checklist is the report's own finding and the reviewer needs to see it — but
# returning AgentStatus.ERROR made the inner graph raise SubgraphError, which
# discarded the rendered report entirely. Measured before the change: an
# unrecognised fault code produced status=error and output=None, so an engineer
# reporting an unfamiliar fault received nothing at all. ERROR is now reserved
# for a genuine processing failure; an incomplete checklist is SUCCESS carrying
# an explicit compliance_status of "incomplete".
#
# S-3 posture: the rendered report contains only the derived classification,
# severity, root-cause and corrective-action prose plus the checklist result —
# no raw telemetry stream and no operator PII.
#
# Wired by the inner graph (DomainWorkflowGraph).
# Returns only changed state keys (partial dict).

import logging
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json
from src.services.service import MAX_REPORT_CHARS

logger = logging.getLogger(__name__)

# Robotics-safety report-completeness checklist. Each item: (key, label,
# whether it is required). A report is complete when all required items pass.
_CHECKLIST: List[Dict[str, Any]] = [
    {
        "key": "classification_present",
        "label": "Incident type is classified",
        "required": True,
    },
    {
        "key": "severity_assigned",
        "label": "Severity level assigned on the four-level scale",
        "required": True,
    },
    {
        "key": "corrective_actions_present",
        "label": "Corrective actions are recommended",
        "required": True,
    },
    {
        "key": "safety_review_routed",
        "label": "Safety-critical incidents are routed to a safety review",
        "required": True,
    },
]

# Ordered (key, title) sections rendered into the final report.
_REPORT_SECTIONS: List[Dict[str, str]] = [
    {"key": "summary", "title": "Summary / 概要"},
    {"key": "classification", "title": "Incident Classification / インシデント分類"},
    {"key": "severity", "title": "Severity & Quality Gate / 深刻度・品質ゲート"},
    {"key": "severity_rationale", "title": "Severity Rationale / 深刻度の根拠"},
    {"key": "telemetry", "title": "Reported Telemetry / 報告テレメトリ"},
    {"key": "root_cause", "title": "Root Cause / 根本原因"},
    {"key": "corrective_actions", "title": "Corrective Actions / 是正措置"},
    {"key": "data_quality", "title": "Input Data Quality / 入力データ品質"},
]

#: Truncation notice appended if the assembled report exceeds the cap. The cap
#: is a backstop — every part is bounded upstream — but a report that grew past
#: it must say so rather than end mid-sentence.
_TRUNCATION_NOTICE = (
    "\n\n---\n\n*This report was truncated at the configured length limit. "
    "Review the incident record directly for the omitted detail.*"
)


def _run_checklist(
    classification: Dict[str, Any],
    severity_level: Dict[str, Any],
    report_draft: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Evaluate the completeness checklist against the assembled report."""
    incident_type = str(classification.get("incident_type", "unknown"))
    severity = str(severity_level.get("severity", "LOW"))
    quality_gate = str(severity_level.get("quality_gate", ""))

    checks: List[Dict[str, Any]] = []
    for item in _CHECKLIST:
        key = item["key"]
        if key == "classification_present":
            passed = incident_type != "unknown"
        elif key == "severity_assigned":
            passed = severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        elif key == "corrective_actions_present":
            passed = bool(str(report_draft.get("corrective_actions", "")).strip())
        elif key == "safety_review_routed":
            # Safety-critical (CRITICAL) incidents must route to a safety review.
            passed = "safety_review" in quality_gate if severity == "CRITICAL" else True
        else:
            passed = True
        checks.append({"key": key, "label": item["label"], "required": item["required"], "passed": passed})
    return checks


def _render_report(
    report_draft: Dict[str, Any],
    checks: List[Dict[str, Any]],
    robot_id: str,
    complete: bool,
) -> str:
    """Render the final structured incident report as Markdown."""
    lines: List[str] = []
    lines.append("# Robotics Incident Report")
    lines.append("")
    lines.append(f"**Robot ID:** {robot_id or '(unspecified)'}")
    lines.append(f"**Generated:** {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("**Report completeness checklist:** " f"{'COMPLETE' if complete else 'INCOMPLETE — needs review'}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for section in _REPORT_SECTIONS:
        body = str(report_draft.get(section["key"], "")).strip()
        if not body:
            continue
        lines.append(f"## {section['title']}")
        lines.append("")
        lines.append(body)
        lines.append("")

    lines.append("## Completeness Checklist / 記載事項チェック")
    lines.append("")
    for check in checks:
        mark = "x" if check["passed"] else " "
        lines.append(f"- [{mark}] {check['label']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by MFG-C2-058. The checklist above records whether this "
        "report contains the elements a robotics-safety review needs. It is not "
        "a determination of regulatory compliance, and no review or warranty is "
        "implied — a qualified reviewer makes that judgement.*"
    )
    rendered = "\n".join(lines)
    if len(rendered) > MAX_REPORT_CHARS:
        keep = MAX_REPORT_CHARS - len(_TRUNCATION_NOTICE)
        rendered = rendered[:keep] + _TRUNCATION_NOTICE
    return rendered


class ComplianceValidateNode(FunctionNode):
    """Check the report against the completeness checklist and render it.

    Input state keys:
        report_draft:            section-keyed draft (from ReportDraftNode)
        incident_classification: classification record (from IncidentClassifyNode)
        severity_level:          severity + routing (from SeverityRouteNode)
        parsed_telemetry:        telemetry record (for robot id)

    Output state keys (partial dict):
        compliance_validated_report: final rendered Markdown report
        compliance_status:           "complete" | "incomplete"
        status:                      AgentStatus.SUCCESS (see module docstring)
    """

    # Reachable only behind PreProcessNode's S-1 gate.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        report_draft: Dict[str, Any] = from_json(state.get("report_draft"), {})
        classification: Dict[str, Any] = from_json(state.get("incident_classification"), {})
        severity_level: Dict[str, Any] = from_json(state.get("severity_level"), {})
        telemetry: Dict[str, Any] = from_json(state.get("parsed_telemetry"), {})
        robot_id = str(telemetry.get("robot_id", ""))

        checks = _run_checklist(classification, severity_level, report_draft)
        required_failures = [c for c in checks if c["required"] and not c["passed"]]
        complete = not required_failures

        compliance_validated_report = _render_report(report_draft, checks, robot_id, complete)

        # S-4 domain audit: checklist evaluated + final report rendered.
        emit_trace_event(
            "robotics_incident_compliance_validated",
            {
                "complete": complete,
                "failed_checks": [c["key"] for c in required_failures],
                "report_chars": len(compliance_validated_report),
            },
            state,
        )

        logger.info(
            "ComplianceValidateNode: complete=%s, %d unmet required items, %d chars",
            complete,
            len(required_failures),
            len(compliance_validated_report),
        )

        return {
            "compliance_validated_report": compliance_validated_report,
            "compliance_status": "complete" if complete else "incomplete",
            "status": AgentStatus.SUCCESS.value,
        }
