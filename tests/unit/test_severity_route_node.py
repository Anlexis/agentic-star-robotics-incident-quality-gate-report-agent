# MFG-C2-058 — Unit Tests: SeverityRouteNode (inner domain node 3)
#
# Resolves incident severity (CRITICAL/HIGH/MEDIUM/LOW) + the quality-gate
# routing decision per MHLW/METI posture, from the classification + telemetry.
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from src.nodes.severity_route_node import SeverityRouteNode
from src.schemas.state import from_json, to_json


def _route(incident_type, confidence=0.8, error_codes=None, limits=None):
    state = {
        "incident_classification": to_json(
            {"incident_type": incident_type, "confidence": confidence, "signals": [], "candidate_types": []}
        ),
        "parsed_telemetry": to_json(
            {"robot_id": "R-1", "error_codes": error_codes or [], "joint_state_count": 0, "sensor_reading_keys": []}
        ),
    }
    if limits is not None:
        state["runtime_limits"] = to_json(limits)
    return from_json(SeverityRouteNode().execute(state)["severity_level"])


class TestBaseSeverity:
    def test_safety_breach_is_critical(self):
        rec = _route("safety_boundary_breach")
        assert rec["severity"] == "CRITICAL"
        assert rec["quality_gate"] == "line_stop_and_safety_review"
        assert rec["escalate"] is True

    def test_mechanical_failure_is_high(self):
        rec = _route("mechanical_failure")
        assert rec["severity"] == "HIGH"
        assert rec["quality_gate"] == "hold_unit_and_engineering_review"
        assert rec["escalate"] is True

    def test_software_fault_is_medium(self):
        rec = _route("software_fault")
        assert rec["severity"] == "MEDIUM"
        assert rec["quality_gate"] == "flag_for_scheduled_maintenance"
        assert rec["escalate"] is False

    def test_calibration_error_is_medium(self):
        rec = _route("calibration_error")
        assert rec["severity"] == "MEDIUM"

    def test_unknown_is_low(self):
        # confidence 0.8 avoids the low-confidence escalation branch.
        rec = _route("unknown", confidence=0.8)
        assert rec["severity"] == "LOW"
        assert rec["quality_gate"] == "log_and_monitor"
        assert rec["escalate"] is False


class TestEscalation:
    def test_safety_critical_code_escalates_software_fault_to_high(self):
        # software_fault base = MEDIUM; an ESTOP code forces at least HIGH.
        rec = _route("software_fault", error_codes=["ESTOP-1"])
        assert rec["severity"] == "HIGH"
        assert any("safety-critical" in r for r in rec["rationale"])

    def test_brake_code_escalates_calibration_to_high(self):
        rec = _route("calibration_error", error_codes=["BRK-9"])
        assert rec["severity"] == "HIGH"

    def test_low_confidence_escalates_unknown_to_medium(self):
        # 0 < confidence < 0.5 with base LOW -> MEDIUM for safe review.
        rec = _route("unknown", confidence=0.3)
        assert rec["severity"] == "MEDIUM"
        assert any("confidence" in r for r in rec["rationale"])

    def test_low_confidence_escalates_medium_to_high(self):
        rec = _route("software_fault", confidence=0.2)
        assert rec["severity"] == "HIGH"

    def test_critical_not_downgraded_by_low_confidence(self):
        rec = _route("safety_boundary_breach", confidence=0.1)
        assert rec["severity"] == "CRITICAL"


class TestRationale:
    def test_rationale_is_non_empty_list(self):
        rec = _route("mechanical_failure")
        assert isinstance(rec["rationale"], list) and rec["rationale"]


class TestDeclaredThresholdIsLoadBearing:
    """The declared low_confidence_threshold must change the answer.

    Before the migration this node read an `execute(state, config=None)`
    argument the framework never supplies, so every declared value was silently
    the built-in default. These assertions fail if that regresses.
    """

    def test_default_applies_when_nothing_is_declared(self):
        rec = _route("calibration_error", confidence=0.65)
        assert rec["severity"] == "MEDIUM"
        assert rec["low_confidence_threshold"] == 0.5

    def test_raising_the_threshold_escalates_the_same_incident(self):
        rec = _route("calibration_error", confidence=0.65, limits={"low_confidence_threshold": 0.9})
        assert rec["severity"] == "HIGH"
        assert rec["low_confidence_threshold"] == 0.9
        assert any("0.90" in r for r in rec["rationale"])

    def test_lowering_the_threshold_stops_escalating(self):
        rec = _route("unknown", confidence=0.3, limits={"low_confidence_threshold": 0.1})
        assert rec["severity"] == "LOW"


class TestNonFiniteFailsClosed:
    """NaN compares False against every bound, so a bare range check admits it
    silently and the escalation below never runs.

    NaN and Infinity are injected as raw JSON tokens rather than through
    to_json(), which refuses them by design — this is how they could actually
    arrive: Python's json.loads accepts the non-standard literals on the way
    back in.
    """

    @staticmethod
    def _route_raw_confidence(token: str) -> dict:
        state = {
            "incident_classification": '{"incident_type": "calibration_error", "confidence": ' + token + "}",
            "parsed_telemetry": to_json({"robot_id": "R-1", "error_codes": []}),
        }
        return from_json(SeverityRouteNode().execute(state)["severity_level"])

    @pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_confidence_falls_back_rather_than_skipping_the_branch(self, token):
        rec = self._route_raw_confidence(token)
        assert rec["confidence"] == 0.0
        assert rec["severity"] == "MEDIUM"

    @pytest.mark.parametrize("bad", ["NaN", None, "abc"])
    def test_unparseable_confidence_falls_back(self, bad):
        rec = _route("calibration_error", confidence=bad)
        assert rec["confidence"] == 0.0
        assert rec["severity"] == "MEDIUM"

    @pytest.mark.parametrize("token", ["NaN", "Infinity"])
    def test_non_finite_declared_threshold_falls_back_to_the_default(self, token):
        state = {
            "incident_classification": to_json({"incident_type": "calibration_error", "confidence": 0.65}),
            "parsed_telemetry": to_json({"robot_id": "R-1", "error_codes": []}),
            "runtime_limits": '{"low_confidence_threshold": ' + token + "}",
        }
        rec = from_json(SeverityRouteNode().execute(state)["severity_level"])
        assert rec["low_confidence_threshold"] == 0.5
        assert rec["severity"] == "MEDIUM"

    @pytest.mark.parametrize("bad", [5.0, -1.0, "abc", None])
    def test_out_of_range_declared_threshold_falls_back_to_the_default(self, bad):
        rec = _route("calibration_error", confidence=0.65, limits={"low_confidence_threshold": bad})
        assert rec["low_confidence_threshold"] == 0.5
        assert rec["severity"] == "MEDIUM"
