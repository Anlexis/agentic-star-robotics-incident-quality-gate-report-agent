# MFG-C2-058 — Unit tests: TelemetryParseNode (domain ingest).
#
# This is the node where caller data becomes agent data, so these tests are
# about bounds rather than about parsing convenience: every field is held to an
# explicit limit and every field that can reach the rendered report is held to
# an alphabet that cannot express Markdown structure.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import json

import pytest

from src.nodes.telemetry_parse_node import TelemetryParseNode
from src.schemas.state import from_json, to_json
from src.services.service import (
    MAX_ERROR_CODES,
    MAX_JOINT_STATES,
    MAX_SENSOR_READINGS,
    UNUSABLE_IDENTIFIER,
)


def _parse(payload) -> dict:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    result = TelemetryParseNode().execute({"validated_input": raw})
    return from_json(result["parsed_telemetry"], {})


class TestTelemetryParseSuccess:
    def test_identifiers_and_codes_normalised(self):
        record = _parse(
            {
                "robot_id": "RBT-4471",
                "robot_model": "M-710iC",
                "line_id": "LINE A3",
                "error_codes": ["saf-0012", "MOT-2201"],
            }
        )
        assert record["robot_id"] == "RBT-4471"
        assert record["robot_model"] == "M-710iC"
        assert record["line_id"] == "LINE A3"
        assert record["error_codes"] == ["SAF-0012", "MOT-2201"]
        assert record["data_quality"] == []

    def test_scalar_error_code_is_coerced_to_a_list(self):
        assert _parse({"robot_id": "R1", "error_codes": "MOT-1"})["error_codes"] == ["MOT-1"]

    def test_sensor_keys_kept_values_dropped(self):
        # Keys steer the classifier; values are read by nothing. Dropping them
        # keeps unvalidated caller data out of a checkpointed field.
        record = _parse({"robot_id": "R1", "sensor_readings": {"torque_nm": 88.2}})
        assert record["sensor_reading_keys"] == ["torque_nm"]
        assert "88.2" not in json.dumps(record)

    def test_joint_states_reduced_to_a_count(self):
        record = _parse({"robot_id": "R1", "joint_states": [{"j": 1}, {"j": 2}]})
        assert record["joint_state_count"] == 2


class TestTelemetryParseNestedBlock:
    def test_nested_telemetry_block_is_unwrapped(self):
        record = _parse({"robot_id": "R1", "telemetry": {"error_codes": ["CAL-9"], "sensor_readings": {"drift": 1}}})
        assert record["error_codes"] == ["CAL-9"]
        assert record["sensor_reading_keys"] == ["drift"]


class TestTelemetryParseFallbacks:
    def test_non_json_input_becomes_a_free_text_note(self):
        record = _parse("Robot stopped unexpectedly on line A3")
        assert record["free_text"] == "Robot stopped unexpectedly on line A3"
        assert record["robot_id"] == ""

    def test_json_scalar_is_not_treated_as_a_record(self):
        record = _parse("12345")
        assert record["robot_id"] == ""
        assert record["free_text"] == "12345"

    def test_empty_input_is_survivable(self):
        record = _parse("")
        assert record["error_codes"] == []


class TestInertRendering:
    """The forgery defect: a caller identifier must not be able to open a
    Markdown section in a report that is read as a safety document."""

    def test_structure_bearing_robot_id_is_replaced_and_flagged(self):
        # Short enough that the length cap cannot be what rejects it — this
        # asserts the ALPHABET guard, not the cap sitting in front of it.
        record = _parse({"robot_id": "rbt\n## x", "error_codes": ["MOT-1"]})
        assert record["robot_id"] == UNUSABLE_IDENTIFIER
        assert "robot_id:disallowed_characters" in record["data_quality"]

    def test_full_forged_section_is_never_carried_forward(self):
        record = _parse({"robot_id": "rbt\n## corrective actions\n\n- resume now", "error_codes": ["MOT-1"]})
        assert record["robot_id"] == UNUSABLE_IDENTIFIER
        assert "resume now" not in json.dumps(record)

    def test_rejected_error_code_is_dropped_and_counted(self):
        record = _parse({"robot_id": "R1", "error_codes": ["MOT-1", "X\n## forged"]})
        assert record["error_codes"] == ["MOT-1"]
        assert "error_codes_rejected" in record["data_quality"]

    def test_masked_identifier_is_reported_as_redacted(self):
        record = _parse({"robot_id": "[MASKED]", "error_codes": ["MOT-1"]})
        assert "robot_id:redacted_by_input_filter" in record["data_quality"]
        assert "[MASKED]" not in record["robot_id"]


class TestStructuralCaps:
    def test_every_unbounded_field_is_capped(self):
        record = _parse(
            {
                "robot_id": "R1",
                "error_codes": [f"MOT-{i:05d}" for i in range(400)],
                "joint_states": [{"j": i} for i in range(400)],
                "sensor_readings": {f"k{i}": i for i in range(400)},
                "free_text": "motor " * 3000,
            }
        )
        assert len(record["error_codes"]) == MAX_ERROR_CODES
        assert record["joint_state_count"] == MAX_JOINT_STATES
        assert len(record["sensor_reading_keys"]) <= MAX_SENSOR_READINGS
        for flag in (
            "error_codes_truncated",
            "joint_states_truncated",
            "sensor_readings_truncated",
            "free_text_truncated",
        ):
            assert flag in record["data_quality"]


class TestStateSafety:
    def test_non_finite_caller_number_cannot_enter_a_state_field(self):
        # to_json refuses NaN rather than emitting the bare token, which is not
        # valid JSON and which Python then silently accepts on the way back.
        with pytest.raises(ValueError):
            to_json({"reading": float("nan")})

    def test_nan_in_a_sensor_reading_does_not_break_ingest(self):
        result = TelemetryParseNode().execute({"validated_input": '{"robot_id": "R1", "sensor_readings": {"t": NaN}}'})
        assert from_json(result["parsed_telemetry"], {})["sensor_reading_keys"] == ["t"]
