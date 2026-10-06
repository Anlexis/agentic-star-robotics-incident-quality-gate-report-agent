# MFG-C2-058 — Unit Tests: main slot (RoboticsIncidentGraphNode)
#
# The `main` backbone slot of MfgC2058Agent is a GraphNode subclass
# (RoboticsIncidentGraphNode) that delegates to the inner DomainWorkflowGraph.
# These tests exercise its three real contracts in isolation, without driving
# the whole agent (the full end-to-end run lives in test_graph_composition.py):
#
#   - get_subgraph()  -> returns a DomainWorkflowGraph instance (no ctor args)
#   - extract_input() -> reads validated_input (falls back to user_input)
#   - merge_output()  -> maps inner sub_result["compliance_validated_report"]
#                        onto the outer delta as compliance_validated_report +
#                        result + status
#
# NOTE: this file supersedes the generated scaffold stub (src/nodes/main_node.py
# MainNode), which is removed in this MR — graph.py wires RoboticsIncidentGraphNode
# into the main slot, not the scaffold MainNode.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.


from framework.schemas.agent_status import AgentStatus

from src.graph.graph import RoboticsIncidentGraphNode, MfgC2058Agent, Graph
from src.graph.domain_workflow_graph import DomainWorkflowGraph


class TestGetSubgraph:
    def test_get_subgraph_returns_domain_workflow_graph(self):
        sub = RoboticsIncidentGraphNode().get_subgraph()
        assert isinstance(
            sub, DomainWorkflowGraph
        ), f"get_subgraph() must return DomainWorkflowGraph, got {type(sub).__name__}"

    def test_get_subgraph_returns_fresh_instances(self):
        node = RoboticsIncidentGraphNode()
        assert node.get_subgraph() is not node.get_subgraph()

    def test_error_strategy_is_propagate(self):
        assert RoboticsIncidentGraphNode.error_strategy == "propagate"


class TestExtractInput:
    def test_prefers_validated_input(self):
        node = RoboticsIncidentGraphNode()
        state = {"validated_input": "PII-stripped payload", "user_input": "raw"}
        assert node.extract_input(state) == "PII-stripped payload"

    def test_falls_back_to_user_input(self):
        node = RoboticsIncidentGraphNode()
        assert node.extract_input({"user_input": "raw robotics request"}) == "raw robotics request"

    def test_empty_when_neither_present(self):
        assert RoboticsIncidentGraphNode().extract_input({}) == ""


class TestMergeOutput:
    def test_maps_report_to_outer_keys(self):
        node = RoboticsIncidentGraphNode()
        sub_result = {
            "compliance_validated_report": "# Robotics Incident Report\n\nbody...",
            "status": AgentStatus.SUCCESS.value,
        }
        delta = node.merge_output({}, sub_result)
        # The inner report must surface under BOTH the schema field
        # (compliance_validated_report) and result (what PostProcessNode reads).
        assert delta["compliance_validated_report"] == sub_result["compliance_validated_report"]
        assert delta["result"] == sub_result["compliance_validated_report"]
        assert delta["status"] == AgentStatus.SUCCESS.value

    def test_returns_only_changed_keys(self):
        node = RoboticsIncidentGraphNode()
        delta = node.merge_output(
            {"unrelated": "keep me out"},
            {"compliance_validated_report": "r", "status": AgentStatus.SUCCESS.value},
        )
        assert set(delta.keys()) == {
            "compliance_validated_report",
            "compliance_status",
            "result",
            "status",
        }

    def test_missing_report_yields_none(self):
        node = RoboticsIncidentGraphNode()
        delta = node.merge_output({}, {})
        assert delta["compliance_validated_report"] is None
        assert delta["result"] is None
        assert delta["status"] is None


class TestOuterAgentIdentity:
    def test_name_property(self):
        assert MfgC2058Agent().name == ("ManufacturingRoboticsIncidentClassificationQualityGateReportAgent")

    def test_graph_alias_is_outer_class(self):
        assert Graph is MfgC2058Agent

    def test_main_slot_is_robotics_incident_graph_node(self):
        agent = MfgC2058Agent()
        agent.register_nodes()
        assert isinstance(agent._nodes["main"], RoboticsIncidentGraphNode)
