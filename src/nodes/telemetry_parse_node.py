"""AgentCore Platform v1.0"""

# MFG-C2-058 — TelemetryParseNode
# Domain node 1: parse the robotics telemetry payload, normalise sensor
# readings, error codes and joint states into a structured telemetry record
# before any classification runs.
#
# This is the ingest node: the one place where caller data becomes agent data.
# Every field is held to an explicit bound from src/services/service.py, and
# every field that can reach the rendered report is held to an alphabet that
# cannot express Markdown structure.
#
# The reason that matters here rather than at the renderer: the report is read
# as a safety document, and a caller-supplied robot identifier carrying a
# newline used to be able to open a heading of its own. A forged
# "Corrective Actions" section instructing an operator to resume a line is a
# physical-safety consequence, not a formatting bug.
#
# Rejected values are REPLACED with a fixed placeholder and counted in
# data_quality. They are never echoed — a refusal that quotes the input is a
# reflection channel — and never silently truncated into the report.
#
# Wired by the inner graph (DomainWorkflowGraph).
# Returns only changed state keys (partial dict).

import json
import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import to_json
from src.services.service import (
    MAX_JOINT_STATES,
    MAX_SENSOR_READINGS,
    clean_error_codes,
    clean_event_window,
    clean_free_text,
    clean_identifier,
    clean_signal_keys,
)

logger = logging.getLogger(__name__)


def _parse_payload(validated_input: str) -> Any:
    """Parse validated_input as JSON if it is a JSON document.

    Telemetry is normally exported as a JSON object. Input that is not JSON is
    carried as a free-text incident note so the pipeline still produces a
    (sparser) report — the note is read for classification signals but is never
    rendered into the report body.
    """
    if isinstance(validated_input, str):
        try:
            return json.loads(validated_input)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return {"robot_id": "", "free_text": validated_input}
    return validated_input


def _as_list(value: Any) -> List[Any]:
    """Coerce a value into a list (single scalars become one-element lists)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class TelemetryParseNode(FunctionNode):
    """Parse, bound and normalise one robotics telemetry record.

    Input state keys:
        validated_input: screened robotics-incident payload (from PreProcessNode)

    Output state keys (partial dict):
        parsed_telemetry: normalised telemetry record (no operator PII, every
                          rendered field held to the inert alphabet)
    """

    # Reachable only behind PreProcessNode, which carries the manifest's declared
    # entry contract and has already run the S-1 gate for this request.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        validated_input = state.get("validated_input") or state.get("user_input", "")

        payload = _parse_payload(validated_input)
        if not isinstance(payload, dict):
            logger.warning(
                "TelemetryParseNode: payload is not an object (type=%s)",
                type(payload).__name__,
            )
            payload = {"robot_id": "", "free_text": str(payload)}

        # Telemetry blocks may be nested under "telemetry".
        telemetry_block = payload.get("telemetry", {})
        if not isinstance(telemetry_block, dict):
            telemetry_block = {}

        data_quality: List[str] = []

        def _field(name: str) -> Any:
            return payload.get(name, telemetry_block.get(name))

        robot_id, reason = clean_identifier(_field("robot_id"))
        if reason:
            data_quality.append(f"robot_id:{reason}")
        robot_model, reason = clean_identifier(_field("robot_model"), max_chars=48)
        if reason:
            data_quality.append(f"robot_model:{reason}")
        line_id, reason = clean_identifier(_field("line_id"))
        if reason:
            data_quality.append(f"line_id:{reason}")
        event_window, reason = clean_event_window(_field("event_window"))
        if reason:
            data_quality.append(f"event_window:{reason}")

        error_codes, reasons = clean_error_codes(_field("error_codes"))
        data_quality.extend(reasons)

        raw_joints = _as_list(_field("joint_states"))
        joint_state_count = len(raw_joints)
        if joint_state_count > MAX_JOINT_STATES:
            data_quality.append("joint_states_truncated")
            raw_joints = raw_joints[:MAX_JOINT_STATES]
            joint_state_count = MAX_JOINT_STATES

        sensor_readings, reasons = clean_signal_keys(_field("sensor_readings"), MAX_SENSOR_READINGS)
        data_quality.extend(reasons)

        free_text, reasons = clean_free_text(_field("free_text"))
        data_quality.extend(reasons)

        parsed_telemetry: Dict[str, Any] = {
            "robot_id": robot_id,
            "robot_model": robot_model,
            "line_id": line_id,
            "event_window": event_window,
            "error_codes": error_codes,
            "joint_state_count": joint_state_count,
            "sensor_reading_keys": sorted(sensor_readings),
            "free_text": free_text,
            "data_quality": data_quality,
        }

        # S-4 domain audit: telemetry parsed, bounded and normalised. Counts and
        # closed-set reason labels only — no caller values in the audit payload.
        emit_trace_event(
            "robotics_telemetry_parsed",
            {
                "error_code_count": len(error_codes),
                "joint_state_count": joint_state_count,
                "sensor_reading_count": len(sensor_readings),
                "data_quality_flags": data_quality,
            },
            state,
        )

        logger.info(
            "TelemetryParseNode: %d error codes, %d joint states, %d data-quality flags",
            len(error_codes),
            joint_state_count,
            len(data_quality),
        )

        return {
            "parsed_telemetry": to_json(parsed_telemetry),
        }
