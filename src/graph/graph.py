"""AgentCore Platform v1.0"""

# MFG-C2-058 — Outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Manufacturing Robotics Incident Classification & Quality Gate Report Agent.
#
# Architecture (Cat 2):
#
#   Outer backbone (fixed — do NOT override add_edges()):
#     START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
#                                             |  (RETRY, max_retry)
#                                             v
#                                          pre_process
#
#   The `main` slot is a GraphNode subclass (RoboticsIncidentGraphNode) that
#   delegates the domain workflow to DomainWorkflowGraph (inner BaseGraph).
#
# Directory layout:
#   src/graph/graph.py                 ← outer graph (this file)
#   src/graph/domain_workflow_graph.py ← inner graph (multi-step topology)
#   src/graph/context_bridge.py        ← outer→inner request-context carrier
#
# Rules enforced:
#   - MfgC2058Agent inherits AgentBaseGraph (L1 Base — direct inheritance)
#   - super().register_nodes() called first (fills initialize + finalize)
#   - RoboticsIncidentGraphNode assigned to self._nodes["main"]
#   - merge_output() returns only changed keys
#   - add_edges() NOT overridden on the outer graph

from typing import Any, ClassVar, Dict

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.graph.base_graph import BaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from src.graph import context_bridge
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State


class RoboticsIncidentGraphNode(GraphNode):
    """GraphNode subclass assigned to the `main` slot of MfgC2058Agent.

    Wraps DomainWorkflowGraph (inner Cat 2 BaseGraph).
    Called by the AgentBaseGraph backbone after pre_process and before
    post_process.

    Contracts:
      get_subgraph()    — instantiate and return DomainWorkflowGraph
      extract_input()   — pull validated_input (screened) from outer state
      merge_output()    — map sub_result fields into the outer state delta
      error_strategy    — "propagate": re-raise inner errors as SubgraphError
    """

    # "propagate": re-raise inner graph exceptions as SubgraphError (fail fast).
    error_strategy: ClassVar[str] = "propagate"

    # False: HITL interrupts are handled inside the inner graph only.
    propagate_hitl: ClassVar[bool] = False

    #: Runtime configuration handed down by the outer graph in register_nodes().
    #: Set as an attribute rather than a constructor argument: BaseNode takes no
    #: __init__ arguments and the framework instantiates nothing here for us.
    subgraph_config: Dict[str, Any] = {}

    def get_subgraph(self) -> BaseGraph:
        """Instantiate and return the inner domain workflow graph.

        Imported lazily to avoid circular-import risk at module load time.

        The inner graph receives the SAME runtime configuration the outer graph
        was built with. Without that hand-off the inner graph is constructed
        bare, its config is {}, and every value declared in config/config.yaml
        stops at the outer graph.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=dict(self.subgraph_config))

    def extract_input(self, state: AgentState) -> str:
        """Return the string input passed into inner_graph.invoke().

        Also stashes the caller's context for the inner graph. GraphNode.execute()
        calls get_subgraph(), then this method, then subgraph.invoke() — and it
        passes no input_context to that invoke(), so the stash below is the only
        route by which caller context reaches the inner graph. The ordering is
        what makes it correct: the stash is written here, and read inside
        invoke() by DomainWorkflowGraph._extra_initial_state().
        """
        input_context = state.get("input_context") or {}
        context_bridge.stash(input_context if isinstance(input_context, dict) else {})
        return str(state.get("validated_input") or state.get("user_input") or "")

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map inner graph sub_result back into the outer state delta.

        Returns ONLY changed keys — never the full state.

        Key coupling (designed together with DomainWorkflowGraph.get_output()):
          Inner get_output() emits  -> "compliance_validated_report", "status", ...
          This merge_output() reads -> sub_result.get("compliance_validated_report")

        `result` is written from the same value because the outer post_process
        slot reads state["result"] — and because that is the field
        AgentBaseGraph.get_output() falls back to when formatted_output is
        absent. PostProcessNode owns clearing both on a gate violation.
        """
        return {
            "compliance_validated_report": sub_result.get("compliance_validated_report"),
            "compliance_status": sub_result.get("compliance_status"),
            "result": sub_result.get("compliance_validated_report"),
            "status": sub_result.get("status"),
        }


class MfgC2058Agent(AgentBaseGraph):
    """Outer graph for MFG-C2-058 (Cat 2).

    Inherits AgentBaseGraph directly (L1 Base). Domain logic is fully
    encapsulated in RoboticsIncidentGraphNode (main slot), which delegates to
    DomainWorkflowGraph (inner BaseGraph).

    Backbone (fixed):
        START -> initialize -> pre_process -> main -> post_process -> finalize -> END

    Trust: PreProcessNode carries the manifest's declared entry contract
    (VERIFIED_EXTERNAL) and is the S-1 boundary for the whole pipeline. Every
    node behind it sits at ANONYMOUS — they are not independently addressable,
    and requiring more of them than the entry point requires refuses callers the
    manifest admits. That is not hypothetical: with the domain nodes at INTERNAL
    this agent returned status=error and no output for every VERIFIED_EXTERNAL
    caller, which is every caller the declared contract allows.

    register_nodes() is the ONLY override.
    add_edges() is NOT overridden — backbone wiring belongs to the framework.
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with AgentRegistry."""
        return "ManufacturingRoboticsIncidentClassificationQualityGateReportAgent"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        """Reject a config shape that would silently discard every declared value.

        Then delegate: AgentBaseGraph's own implementation validates max_retry,
        memory_enabled and the hitl block, and dropping it would trade a real
        check for a shape check.
        """
        if self.config is not None and not isinstance(self.config, dict):
            raise TypeError(f"{type(self).__name__}: config must be a mapping, got " f"{type(self.config).__name__}")
        super()._validate_config()

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the
        framework's default InitializeNode (schema_version, session_id,
        trust_level) and FinalizeNode (response_metadata, total_time_ms).
        """
        super().register_nodes()  # fills: initialize, finalize

        main_node = RoboticsIncidentGraphNode()
        # Hand the declared runtime configuration down to the inner graph.
        main_node.subgraph_config = dict(self.config or {})

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = main_node
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


# Back-compat alias — config/agent.yaml declares class: "src.graph.graph.Graph".
Graph = MfgC2058Agent
