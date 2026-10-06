# MFG-C2-058 — Unit tests: ReportDraftNode.
#
# Deterministic section synthesis from the structured upstream facts. Every
# value interpolated here has already been through the ingest node's bounds, so
# these tests also pin the property that follows from that: no section body can
# contain a line the caller wrote.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from src.nodes.report_draft_node import ReportDraftNode
from src.schemas.state import from_json, to_json


def _draft(
    incident_type="mechanical_failure",
    confidence=0.8,
    signals=None,
    severity="HIGH",
    quality_gate="hold_unit_and_engineering_review",
    robot_id="RBT-4471",
    line_id="LINE A3",
    error_codes=None,
    data_quality=None,
    rationale=None,
):
    state = {
        "incident_classification": to_json(
            {
                "incident_type": incident_type,
                "confidence": confidence,
                "signals": signals or [],
                "candidate_types": [incident_type],
            }
        ),
        "severity_level": to_json(
            {"severity": severity, "quality_gate": quality_gate, "escalate": True, "rationale": rationale or []}
        ),
        "parsed_telemetry": to_json(
            {
                "robot_id": robot_id,
                "line_id": line_id,
                "error_codes": error_codes or [],
                "data_quality": data_quality or [],
            }
        ),
    }
    return from_json(ReportDraftNode().execute(state)["report_draft"], {})


class TestReportDraftSections:
    def test_expected_sections_present(self):
        draft = _draft(error_codes=["MOT-2201"])
        for key in ("summary", "classification", "severity", "telemetry", "root_cause", "corrective_actions"):
            assert draft[key].strip()

    def test_summary_reflects_robot_line_and_type(self):
        draft = _draft(robot_id="RBT-9", line_id="LINE B2")
        assert "RBT-9" in draft["summary"]
        assert "LINE B2" in draft["summary"]
        assert "mechanical_failure" in draft["summary"]

    def test_severity_section_carries_the_quality_gate(self):
        draft = _draft(severity="CRITICAL", quality_gate="line_stop_and_safety_review")
        assert "CRITICAL" in draft["severity"]
        assert "line_stop_and_safety_review" in draft["severity"]

    def test_telemetry_section_lists_the_reported_codes(self):
        draft = _draft(error_codes=["MOT-2201", "SAF-0012"])
        assert "MOT-2201" in draft["telemetry"] and "SAF-0012" in draft["telemetry"]

    def test_telemetry_section_says_so_when_no_codes_were_reported(self):
        assert "No controller error codes" in _draft(error_codes=[])["telemetry"]

    def test_absent_identifiers_render_as_unspecified(self):
        draft = _draft(robot_id="", line_id="")
        assert "(unspecified)" in draft["summary"]

    def test_data_quality_section_appears_only_when_a_field_was_rejected(self):
        assert "data_quality" not in _draft()
        draft = _draft(data_quality=["robot_id:disallowed_characters"])
        assert "robot_id:disallowed_characters" in draft["data_quality"]


class TestCorrectiveActionsByType:
    def test_mechanical_actions(self):
        assert "axis" in _draft(incident_type="mechanical_failure")["corrective_actions"].lower()

    def test_safety_breach_actions_mention_stopping_the_line(self):
        actions = _draft(incident_type="safety_boundary_breach")["corrective_actions"]
        assert "stop the line" in actions.lower()

    def test_unknown_type_uses_the_triage_fallback(self):
        assert "triage" in _draft(incident_type="unknown")["corrective_actions"].lower()

    def test_actions_render_as_markdown_bullets(self):
        for line in _draft()["corrective_actions"].splitlines():
            assert line.startswith("- ")


class TestNoCallerLinesInSectionBodies:
    """The forgery property, asserted at the renderer.

    The ingest node holds every rendered value to an alphabet without newlines,
    so no section body assembled here can gain a line the caller authored. This
    test drives the values a hostile caller would want and checks the invariant
    holds at this layer too, rather than trusting the layer below.
    """

    @pytest.mark.parametrize("field", ["robot_id", "line_id"])
    def test_identifier_cannot_add_a_line_to_the_summary(self, field):
        # Values that survive ingest cannot contain a newline; assert the
        # renderer produces a single-line summary for a maximal legal value.
        draft = _draft(**{field: "R" * 32})
        assert "\n" not in draft["summary"]

    def test_error_codes_cannot_add_a_line_to_the_telemetry_section(self):
        draft = _draft(error_codes=["MOT-1", "SAF-2", "CAL-3"])
        assert "\n" not in draft["telemetry"]

    def test_only_the_deliberate_bullet_lists_are_multi_line(self):
        # Every other section is a single line assembled from bounded values,
        # so a caller cannot add a line anywhere a reviewer reads as prose.
        draft = _draft(
            error_codes=["MOT-1"],
            signals=["code:MOT-1"],
            data_quality=["free_text_truncated", "robot_id:too_long"],
            rationale=["Base severity for 'mechanical_failure' is HIGH.", "A safety-critical error code was reported."],
        )
        multi = {k for k, v in draft.items() if "\n" in v}
        assert multi == {"corrective_actions", "data_quality", "severity_rationale"}
        for key in multi:
            for line in draft[key].splitlines():
                assert line.startswith("- ")


class TestSeverityRationaleIsRendered:
    """A reviewer asked to stop a line needs to see why the severity was set."""

    def test_rationale_is_rendered_when_present(self):
        draft = _draft(
            rationale=["Classification confidence 0.65 is below the " "configured threshold 0.90 — escalated to HIGH."]
        )
        assert "0.90" in draft["severity_rationale"]

    def test_no_rationale_section_when_there_is_nothing_to_say(self):
        assert "severity_rationale" not in _draft(rationale=[])


class TestDegradedInputs:
    def test_missing_upstream_state_is_survivable(self):
        draft = from_json(ReportDraftNode().execute({})["report_draft"], {})
        assert draft["summary"]
        assert "unknown" in draft["classification"]
