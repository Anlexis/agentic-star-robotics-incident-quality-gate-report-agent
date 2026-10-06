# MFG-C2-058 — Integration: a declared runtime value must reach behaviour.
#
# Before the migration this could not have been true. The domain nodes declared
# execute(state, config=None) and read a `config` argument the framework never
# supplies; the graph was constructed with no config at all; and the inner graph
# was constructed bare, so anything the outer graph did hold stopped there.
# Every value in config/config.yaml was decorative.
#
# The path now is: config.yaml -> server -> MfgC2058Agent(config=...) ->
# RoboticsIncidentGraphNode.subgraph_config -> DomainWorkflowGraph(config=...)
# -> _extra_initial_state() -> state["runtime_limits"] -> SeverityRouteNode.
#
# These tests drive the whole path and assert the ANSWER changes — a config that
# arrives but changes nothing is the same defect wearing a better disguise.
#
# Deterministic — no LLM, no network.

import json

import pytest

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from src.api.server import load_runtime_config
from src.graph import context_bridge
from src.graph.graph import MfgC2058Agent

# calibration_error with one matched signal scores 0.65: above the shipped
# threshold of 0.5, below a declared 0.9. The one incident that straddles both.
_WEAKLY_CLASSIFIED = json.dumps({"robot_id": "RBT-1", "error_codes": ["CAL-0001"]})


def _run(payload: str, config: dict) -> dict:
    context_bridge.clear()
    agent = MfgC2058Agent(config=config)
    agent.compile()
    ctx = InvocationContext(
        session_id="cfg-test",
        caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
        caller_id="test-suite",
    )
    return agent.invoke(payload, ctx=ctx)


class TestShippedConfigFileIsReadable:
    def test_config_yaml_declares_the_documented_keys(self):
        config = load_runtime_config()
        assert config["max_retry"] == 3
        assert config["timeout_s"] == 30
        assert config["low_confidence_threshold"] == 0.5

    def test_the_shipped_file_drives_the_shipped_behaviour(self):
        output = _run(_WEAKLY_CLASSIFIED, load_runtime_config())["output"]
        assert "Severity MEDIUM" in output


class TestDeclaredValueChangesTheAnswer:
    def test_raising_the_threshold_escalates_the_same_incident(self):
        low = _run(_WEAKLY_CLASSIFIED, {"low_confidence_threshold": 0.5})["output"]
        high = _run(_WEAKLY_CLASSIFIED, {"low_confidence_threshold": 0.9})["output"]
        assert "Severity MEDIUM" in low
        assert "Severity HIGH" in high
        assert "flag_for_scheduled_maintenance" in low
        assert "hold_unit_and_engineering_review" in high

    def test_the_report_states_which_threshold_was_applied(self):
        output = _run(_WEAKLY_CLASSIFIED, {"low_confidence_threshold": 0.9})["output"]
        assert "0.90" in output

    def test_absent_config_falls_back_to_the_documented_default(self):
        assert "Severity MEDIUM" in _run(_WEAKLY_CLASSIFIED, {})["output"]

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), 5.0, -1.0, "abc", None])
    def test_an_unusable_declared_value_falls_back_rather_than_disabling_the_rule(self, bad):
        # NaN compares False against every bound, so an unguarded read would
        # silently switch the escalation off altogether.
        assert "Severity MEDIUM" in _run(_WEAKLY_CLASSIFIED, {"low_confidence_threshold": bad})["output"]


class TestConfigShape:
    def test_a_non_mapping_config_is_refused_at_compile(self):
        # Silently discarding everything an operator declared is the failure
        # mode this replaces.
        with pytest.raises(TypeError):
            MfgC2058Agent(config="max_retry: 3").compile()


class TestInputContextReachesTheInnerGraph:
    """GraphNode.execute() does not forward input_context to its subgraph.

    Verified against the installed SDK: it calls
    subgraph.invoke(user_input, session_id=..., ctx=...) and passes no
    input_context, so without the bridge the inner graph always sees {}.
    """

    def test_bridge_carries_the_context_across_the_boundary(self):
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        context_bridge.clear()
        context_bridge.stash({"channel": "mes", "site_id": "PLANT-7"})
        seeded = DomainWorkflowGraph(config={})._extra_initial_state()
        assert seeded["input_context"] == {"channel": "mes", "site_id": "PLANT-7"}

    def test_the_stash_is_cleared_on_read_so_it_cannot_leak_between_requests(self):
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        context_bridge.clear()
        context_bridge.stash({"channel": "mes"})
        DomainWorkflowGraph(config={})._extra_initial_state()
        assert DomainWorkflowGraph(config={})._extra_initial_state()["input_context"] == {}

    def test_a_request_carrying_context_still_produces_its_report(self):
        context_bridge.clear()
        agent = MfgC2058Agent(config=load_runtime_config())
        agent.compile()
        ctx = InvocationContext(
            session_id="ctx-test",
            caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
            caller_id="test-suite",
        )
        result = agent.invoke(
            json.dumps({"robot_id": "RBT-1", "error_codes": ["MOT-1"]}),
            ctx=ctx,
            input_context={"channel": "mes"},
        )
        assert result["status"] == "success"
