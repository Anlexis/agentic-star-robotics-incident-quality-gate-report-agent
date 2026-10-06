"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.
#
# ADR-005 (msgpack safety): structured fields (dict / list[dict]) are stored
# as JSON STRINGS, not bare Python containers — a bare dict/list in a
# checkpointed State field is a gate-state-safety violation. Producers
# serialize with to_json() on write; consumers deserialize with from_json()
# on read.
#
# MFG-C2-058 — Manufacturing Robotics Incident Classification & Quality Gate
# Report Agent.  Two-layer nested Cat 2 graph: outer backbone (AgentBaseGraph)
# + inner domain workflow (BaseGraph).  Fields below cover both layers.
#
# Safety / PII note: raw robotics telemetry (sensor streams, operator
# identifiers) is NOT persisted to State.  PreProcessNode screens the input and
# TelemetryParseNode keeps only the derived, bounded signal record — sensor and
# joint VALUES are counted and their keys retained, but the values themselves
# are dropped at ingest because nothing downstream reads them and an
# unvalidated caller value in a checkpointed field is a liability with no
# purpose.

import json
import math
from typing import Any, Optional

from framework.schemas.agent_state import AgentState


def _reject_non_finite(value: Any) -> Any:
    """Raise on NaN / Infinity so they cannot enter a State field.

    json.dumps emits bare `NaN` and `Infinity` tokens by default. Those are not
    valid JSON, so a field written with one is a field no conforming reader can
    parse — and Python's own json.loads accepts them again, which is what makes
    the breakage silent. Rejecting at the boundary keeps every State field
    parseable by anything.
    """
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite number cannot be stored in a State field")
    return value


def to_json(value: Any) -> Optional[str]:
    """Serialize a dict/list State field to a JSON string (ADR-005 msgpack safety).

    None passes through unchanged so an 'unset' field stays distinguishable
    from an empty container.
    """
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, allow_nan=False, default=_reject_non_finite)


def from_json(value: Optional[str], default: Any = None) -> Any:
    """Deserialize a JSON-string State field back to its dict/list.

    None / empty / malformed input -> the supplied ``default`` so a missing or
    corrupt field is non-fatal for the consuming node.
    """
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


class State(AgentState):
    """Flat TypedDict for MFG-C2-058.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, etc.) are inherited from AgentState.
    """

    # ------------------------------------------------------------------
    # Outer layer — PreProcessNode / RoboticsIncidentGraphNode.merge_output
    # ------------------------------------------------------------------

    # Screened, surface-sanitized robotics incident payload produced by
    # PreProcessNode (S-1/S-2).  Raw telemetry is NOT persisted beyond this.
    validated_input: Optional[str]

    # ------------------------------------------------------------------
    # Inner layer — seeded by DomainWorkflowGraph._extra_initial_state()
    # ------------------------------------------------------------------

    # Declared runtime parameters, bounded, carried from config/config.yaml.
    # JSON STRING (to_json) of {"low_confidence_threshold": float, ...}.
    # This is how config reaches a FunctionNode: the framework calls
    # execute(state) with no config argument, so state is the only channel.
    runtime_limits: Optional[str]

    # ------------------------------------------------------------------
    # Inner layer — domain nodes (DomainWorkflowGraph)
    # ------------------------------------------------------------------

    # TelemetryParseNode output.
    # JSON STRING (to_json) of the bounded telemetry record:
    # {"robot_id": str, "robot_model": str, "line_id": str, "event_window": str,
    #  "error_codes": [str], "joint_state_count": int,
    #  "sensor_reading_keys": [str], "free_text": str, "data_quality": [str]}
    # Every identifier here is held to the inert alphabet in
    # src/services/service.py, so no value in this record can carry Markdown
    # structure into the rendered report. data_quality carries closed-set
    # labels naming any field that was rejected — never the rejected value.
    parsed_telemetry: Optional[str]

    # IncidentClassifyNode output.
    # JSON STRING (to_json) of the classification record:
    # {"incident_type": str, "confidence": float, "signals": [str],
    #  "candidate_types": [...]}
    # incident_type is one of: mechanical_failure | software_fault |
    # safety_boundary_breach | calibration_error | unknown.
    incident_classification: Optional[str]

    # SeverityRouteNode output.
    # JSON STRING (to_json) of the severity + quality-gate routing decision:
    # {"severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", "quality_gate": str,
    #  "escalate": bool, "confidence": float,
    #  "low_confidence_threshold": float, "rationale": [str]}
    severity_level: Optional[str]

    # ReportDraftNode output.
    # JSON STRING (to_json) of the structured incident-report draft, section-keyed.
    report_draft: Optional[str]

    # ComplianceValidateNode output (terminal).
    # Final rendered robotics incident report (Markdown).  Surfaced via
    # merge_output and gated by PostProcessNode (S-3), which clears this field
    # too on a violation — a cleared `result` alone would leave the inner
    # graph's copy of the report intact.
    compliance_validated_report: Optional[str]

    # "complete" | "incomplete" — whether the report satisfied every required
    # checklist item. Carried as its own field rather than as an error status:
    # an incomplete checklist is the report's finding, not a failed run, and
    # signalling it as ERROR used to discard the report the reviewer needed.
    compliance_status: Optional[str]

    # ------------------------------------------------------------------
    # Tracing / audit — framework-managed; do NOT write from node code
    # ------------------------------------------------------------------

    trace_id: Optional[str]
    correlation_id: Optional[str]
    # node_history inherited from AgentState; listed here for clarity
    # node_history: Optional[List[str]]
