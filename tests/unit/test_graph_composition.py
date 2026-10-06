# MFG-C2-058 — Unit Tests: nested Cat-2 graph composition (end-to-end)
#
# Drives the REAL outer agent (MfgC2058Agent / Graph) end-to-end via the
# AgentBaseGraph compile-on-first-use invoke() path — the same pattern used by
# the CoE-passed a peer template reference. The inner DomainWorkflowGraph runs all 5
# domain nodes; ComplianceValidateNode sets status=SUCCESS on a compliant
# report, which the outer merge_output maps to the outer state so the backbone
# routes main -> post_process -> finalize.
#
# e2e ROUTING NOTE (verified here, asserted below): because the terminal
# ComplianceValidateNode emits status=SUCCESS for a compliant incident, the
# outer route() (AgentBaseGraph) returns "post_process" — so a successful run
# DOES traverse the S-3 PostProcessNode gate end-to-end (PostProcessNode appears
# in node_history). A non-compliant payload would make the inner graph return
# status=ERROR, which RoboticsIncidentGraphNode (error_strategy="propagate")
# re-raises as SubgraphError — so the error case is exercised directly against
# the nodes, never by driving the whole agent into an exception.
#
# Deterministic — the nodes synthesize the report rule-based (no LLM, no
# network). framework.* / src.* imports only.

import json


from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext

from src.graph.graph import MfgC2058Agent, Graph
from src.graph.domain_workflow_graph import DomainWorkflowGraph
from src.schemas.state import State


# Compliant incident: a mechanical failure (known type) with a clear error code
# → classification_present + severity_assigned + corrective_actions_present all
# pass, severity HIGH (not CRITICAL) so safety_review_routed auto-passes.
_PAYLOAD = json.dumps(
    {
        "robot_id": "R-LINE3-07",
        "robot_model": "FANUC-M20",
        "line_id": "LINE3",
        "event_window": "2025-06-01T10:00Z..2025-06-01T10:05Z",
        "error_codes": ["MEC-014", "MOT-009"],
        "joint_states": [{"j1": 12.4}, {"j2": -8.1}],
        "sensor_readings": {"torque": 91.0, "temp_c": 78.5, "vibration": 0.42},
        "free_text": "Servo motor overheating with abnormal torque on axis 1.",
    },
    ensure_ascii=False,
)


class TestOuterGraphConstruction:
    def test_state_schema_is_state(self):
        assert MfgC2058Agent().state_schema is State

    def test_compile_fills_all_backbone_slots(self):
        agent = MfgC2058Agent()
        agent.compile()
        for slot in ("initialize", "pre_process", "main", "post_process", "finalize"):
            assert agent._nodes.get(slot) is not None, f"backbone slot not filled: {slot}"


class TestInnerGraphConstruction:
    def test_inner_graph_registers_five_domain_nodes(self):
        inner = DomainWorkflowGraph()
        inner.register_nodes()
        assert set(inner._nodes.keys()) == {
            "telemetry_parse",
            "incident_classify",
            "severity_route",
            "report_draft",
            "compliance_validate",
        }

    def test_inner_graph_name_and_schema(self):
        inner = DomainWorkflowGraph()
        assert inner.name == "mfg_c2_058_robotics_incident_workflow"
        assert inner.state_schema is State

    def test_inner_graph_get_output_shape(self):
        inner = DomainWorkflowGraph()
        out = inner.get_output({"compliance_validated_report": "R", "status": AgentStatus.SUCCESS.value})
        assert out["compliance_validated_report"] == "R"
        assert out["status"] == AgentStatus.SUCCESS.value


class TestEndToEndInvoke:
    """Full agent run: outer backbone + inner domain workflow, no LLM."""

    def _run(self, user_input: str) -> dict:
        agent = Graph()  # back-compat alias for MfgC2058Agent
        # Secure-by-Default: the backbone S-1 trust gate denies ANONYMOUS callers
        # (PreProcessNode requires VERIFIED_EXTERNAL, the domain nodes INTERNAL).
        # Supply a fully-trusted internal context, exactly as AgentGateway would
        # for an authenticated internal caller.
        ctx = InvocationContext.for_internal(caller_id="test-suite")
        return agent.invoke(user_input, ctx=ctx)

    def test_invoke_returns_success(self):
        result = self._run(_PAYLOAD)
        assert (
            result.get("status") == AgentStatus.SUCCESS.value
        ), f"Expected success, got {result.get('status')}. result={result!r}"

    def test_invoke_output_is_populated_report(self):
        result = self._run(_PAYLOAD)
        # Outer get_output() surfaces formatted_output (mapped from the inner
        # compliance_validated_report) under "output".
        output = result.get("output")
        assert isinstance(output, str) and output.strip(), f"Expected a non-empty report in output, got {output!r}"

    def test_report_contains_robot_and_sections(self):
        output = self._run(_PAYLOAD).get("output", "")
        assert "R-LINE3-07" in output
        assert "Robotics Incident Report" in output
        assert "Corrective Actions" in output

    def test_report_reflects_mechanical_classification(self):
        output = self._run(_PAYLOAD).get("output", "")
        assert "mechanical_failure" in output

    def test_e2e_traverses_post_process_gate(self):
        """ROUTING: a compliant run routes main -> post_process -> finalize.

        BaseNode.__call__ appends each node's CLASS name to node_history. The
        presence of PostProcessNode proves the outer route() sent the run
        through the S-3 gate (status=SUCCESS path), not main -> finalize.
        """
        history = self._run(_PAYLOAD).get("node_history", [])
        assert isinstance(history, list)
        for cls_name in ("PreProcessNode", "RoboticsIncidentGraphNode", "PostProcessNode"):
            assert cls_name in history, f"node_history missing {cls_name}: {history}"

    def test_free_text_input_still_produces_report(self):
        """Non-JSON free text with a clear mechanical signal still completes."""
        result = self._run("Servo motor overheating with abnormal torque and vibration on axis 1.")
        assert result.get("status") == AgentStatus.SUCCESS.value
        assert (result.get("output") or "").strip()


class TestStateRoundTrip:
    """State.to_json / from_json msgpack-safe serialization round-trip.

    ADR-005: structured State fields (parsed_telemetry, incident_classification,
    severity_level, report_draft) are stored as JSON STRINGS, not bare dicts.
    A producer writes with to_json(); a consumer reads with from_json(). The
    round-trip must be lossless for the dict/list shapes these fields hold.
    """

    def test_dict_round_trip_is_lossless(self):
        from src.schemas.state import from_json, to_json

        record = {
            "robot_id": "R-1",
            "error_codes": ["MEC-001", "MOT-014"],
            "joint_states": [{"j1": 1.0}, {"j2": -2.5}],
            "sensor_readings": {"torque": 88.0, "temp_c": 71.2},
            "nested": {"a": [1, 2, {"b": True}]},
        }
        assert from_json(to_json(record)) == record

    def test_list_round_trip_is_lossless(self):
        from src.schemas.state import from_json, to_json

        rationale = ["Base severity HIGH.", "Escalated to CRITICAL.", "rationale 3"]
        assert from_json(to_json(rationale)) == rationale

    def test_none_passes_through_unset(self):
        from src.schemas.state import to_json

        # None stays None so an 'unset' field is distinguishable from "{}".
        assert to_json(None) is None

    def test_from_json_default_on_missing_or_malformed(self):
        from src.schemas.state import from_json

        # Missing / empty / corrupt -> the supplied default (non-fatal read).
        assert from_json(None, {}) == {}
        assert from_json("", []) == []
        assert from_json("{not valid json", {"fallback": True}) == {"fallback": True}
