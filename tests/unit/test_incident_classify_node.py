# MFG-C2-058 — Unit tests: IncidentClassifyNode.
#
# The classification is deterministic by design — the same telemetry must yield
# the same answer between shifts for the report to be usable in a safety review.
# These tests pin that determinism and the rule table behind it.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from src.nodes.incident_classify_node import IncidentClassifyNode
from src.schemas.state import from_json, to_json
from src.services.service import MAX_SIGNALS_RENDERED


def _classify(**telemetry) -> dict:
    record = {
        "robot_id": "R1",
        "error_codes": [],
        "free_text": "",
        "sensor_reading_keys": [],
        "data_quality": [],
    }
    record.update(telemetry)
    result = IncidentClassifyNode().execute({"parsed_telemetry": to_json(record)})
    return from_json(result["incident_classification"], {})


class TestClassifyByErrorCode:
    @pytest.mark.parametrize(
        "code,want",
        [
            ("SAF-0012", "safety_boundary_breach"),
            ("ESTOP-1", "safety_boundary_breach"),
            ("CAL-4", "calibration_error"),
            ("TCP-1", "calibration_error"),
            ("SW-9", "software_fault"),
            ("COMM-2", "software_fault"),
            ("MEC-014", "mechanical_failure"),
            ("MOT-2201", "mechanical_failure"),
        ],
    )
    def test_code_prefix_selects_the_type(self, code, want):
        assert _classify(error_codes=[code])["incident_type"] == want


class TestClassifyByKeyword:
    def test_keyword_in_free_text_classifies(self):
        assert _classify(free_text="servo motor overheat")["incident_type"] == "mechanical_failure"

    def test_sensor_reading_key_contributes_a_signal(self):
        result = _classify(sensor_reading_keys=["torque_nm"])
        assert result["incident_type"] == "mechanical_failure"
        assert any(s.startswith("kw:") for s in result["signals"])


class TestConfidenceAndCandidates:
    def test_confidence_scales_with_signal_count(self):
        one = _classify(error_codes=["MOT-1"])["confidence"]
        many = _classify(error_codes=["MOT-1", "SRV-2"], free_text="motor torque brake")["confidence"]
        assert many > one

    def test_confidence_capped_below_certainty(self):
        result = _classify(
            error_codes=["MOT-1", "SRV-2", "AXIS-3", "GEAR-4", "BRK-5"],
            free_text="motor servo gearbox bearing overheat torque brake vibration",
        )
        assert result["confidence"] == 0.95

    def test_unknown_when_no_signal_matches(self):
        result = _classify(error_codes=["XYZ-1"])
        assert result["incident_type"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["signals"] == []

    def test_safety_breach_wins_when_it_has_the_most_signals(self):
        result = _classify(error_codes=["SAF-1", "ZONE-2"], free_text="guard intrusion; motor")
        assert result["incident_type"] == "safety_boundary_breach"

    def test_signal_list_is_capped(self):
        result = _classify(
            error_codes=[f"MOT-{i:03d}" for i in range(MAX_SIGNALS_RENDERED + 20)],
        )
        assert len(result["signals"]) <= MAX_SIGNALS_RENDERED


class TestDeterminism:
    def test_same_telemetry_yields_the_same_answer(self):
        args = {"error_codes": ["CAL-4"], "free_text": "tcp offset drift"}
        assert _classify(**args) == _classify(**args)

    def test_missing_telemetry_is_survivable(self):
        result = IncidentClassifyNode().execute({})
        assert from_json(result["incident_classification"], {})["incident_type"] == "unknown"
