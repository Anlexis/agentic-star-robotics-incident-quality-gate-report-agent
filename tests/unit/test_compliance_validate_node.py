# MFG-C2-058 — Unit tests: ComplianceValidateNode (terminal domain node).
#
# Two properties this module pins beyond the checklist arithmetic:
#
#  1. An incomplete checklist is NOT a failed run. Returning AgentStatus.ERROR
#     made the inner graph raise SubgraphError, which discarded the rendered
#     report — so the reviewer who most needed it received nothing.
#  2. The rendered verdict does not claim regulatory conformance. The checklist
#     establishes that the report contains what a safety review needs.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from framework.schemas.agent_status import AgentStatus
from src.nodes.compliance_validate_node import ComplianceValidateNode
from src.schemas.state import to_json
from src.services.service import MAX_REPORT_CHARS


def _validate(
    incident_type="mechanical_failure",
    severity="HIGH",
    quality_gate="hold_unit_and_engineering_review",
    corrective_actions="- Isolate the axis.",
    robot_id="RBT-4471",
    extra_sections=None,
):
    draft = {
        "summary": "Robot RBT-4471 reported a mechanical failure.",
        "classification": "Incident type: mechanical failure.",
        "severity": f"Severity {severity}.",
        "telemetry": "Reported controller error codes: MOT-2201.",
        "root_cause": "Consistent with a mechanical failure.",
        "corrective_actions": corrective_actions,
    }
    draft.update(extra_sections or {})
    state = {
        "report_draft": to_json(draft),
        "incident_classification": to_json({"incident_type": incident_type, "confidence": 0.8}),
        "severity_level": to_json({"severity": severity, "quality_gate": quality_gate}),
        "parsed_telemetry": to_json({"robot_id": robot_id}),
    }
    return ComplianceValidateNode().execute(state)


class TestCompletePath:
    def test_rendered_report_is_markdown_with_a_header(self):
        report = _validate()["compliance_validated_report"]
        assert report.startswith("# Robotics Incident Report")
        assert "**Robot ID:** RBT-4471" in report

    def test_checklist_is_rendered_with_every_item(self):
        report = _validate()["compliance_validated_report"]
        assert "## Completeness Checklist" in report
        assert report.count("- [x]") == 4
        assert "- [ ]" not in report

    def test_complete_report_is_marked_complete(self):
        result = _validate()
        assert result["compliance_status"] == "complete"
        assert "COMPLETE" in result["compliance_validated_report"]

    def test_every_drafted_section_is_rendered(self):
        report = _validate(extra_sections={"data_quality": "- Input field not usable"})["compliance_validated_report"]
        for title in (
            "Summary",
            "Incident Classification",
            "Severity & Quality Gate",
            "Reported Telemetry",
            "Root Cause",
            "Corrective Actions",
            "Input Data Quality",
        ):
            assert title in report


class TestIncompletePath:
    """Incomplete is a finding in the report, not a failed run."""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"incident_type": "unknown"},
            {"corrective_actions": "   "},
            {"severity": "CRITICAL", "quality_gate": "log_and_monitor"},
        ],
    )
    def test_incomplete_still_returns_success_and_the_report(self, kwargs):
        result = _validate(**kwargs)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["compliance_status"] == "incomplete"
        assert result["compliance_validated_report"].startswith("# Robotics Incident Report")

    def test_unmet_items_are_visible_as_unticked_boxes(self):
        report = _validate(incident_type="unknown")["compliance_validated_report"]
        assert "- [ ] Incident type is classified" in report
        assert "INCOMPLETE — needs review" in report

    def test_critical_routed_to_a_safety_review_passes_that_item(self):
        result = _validate(severity="CRITICAL", quality_gate="line_stop_and_safety_review")
        assert result["compliance_status"] == "complete"


class TestNoRegulatoryConformanceClaim:
    """A template shipped without warranty cannot certify a regulator's standard."""

    def test_verdict_is_about_report_completeness(self):
        report = _validate()["compliance_validated_report"]
        assert "Report completeness checklist:" in report
        assert "Compliance:** PASS" not in report

    def test_footer_disclaims_review_and_conformance(self):
        report = _validate()["compliance_validated_report"]
        assert "not" in report and "regulatory compliance" in report
        assert "no review or warranty is" in report


class TestReportCap:
    def test_report_is_capped_and_says_so(self):
        result = _validate(corrective_actions="- " + ("x" * (MAX_REPORT_CHARS * 2)))
        report = result["compliance_validated_report"]
        assert len(report) <= MAX_REPORT_CHARS
        assert "truncated" in report


class TestDegradedInputs:
    def test_missing_upstream_state_still_renders_a_report(self):
        result = ComplianceValidateNode().execute({})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["compliance_status"] == "incomplete"
        assert result["compliance_validated_report"].startswith("# Robotics Incident Report")
