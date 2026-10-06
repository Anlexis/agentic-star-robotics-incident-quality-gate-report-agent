"""AgentCore Platform v1.0"""

# MFG-C2-058 — DomainWorkflowGraph (inner BaseGraph)
#
# This is the INNER graph for the Cat 2 two-layer nested architecture.
# It encapsulates the full robotics incident-classification and quality-gate
# report workflow:
#
#   START -> telemetry_parse -> incident_classify -> severity_route
#         -> report_draft -> compliance_validate -> END
#
# Called by RoboticsIncidentGraphNode.get_subgraph() (graph.py).
# get_output() shapes the sub_result dict consumed by merge_output() there.
#
# ── How declared runtime parameters reach the domain nodes ────────────────
# Domain nodes are FunctionNodes and the framework calls execute(state) with no
# config argument, so a node cannot read graph config directly. The path is:
#
#   config/config.yaml -> server.py -> MfgC2058Agent(config=...)
#     -> RoboticsIncidentGraphNode.subgraph_config
#     -> DomainWorkflowGraph(config=...)
#     -> _extra_initial_state() seeds state["runtime_limits"]
#     -> SeverityRouteNode reads it
#
# Before the migration the nodes declared `execute(self, state, config=None)`
# and read a `config` argument the framework never supplies, so every declared
# value was silently the built-in default. The nodes are now on the framework's
# actual signature and the seed above is what carries configuration.
#
# Rules enforced:
#   - Inherits BaseGraph (fully custom topology — no forced backbone)
#   - Implements all 7 BaseGraph ABC methods
#   - register_nodes() does NOT call super() (abstract in BaseGraph)
#   - register_nodes() instantiates every domain node with NO ctor args
#   - Does NOT register initialize / finalize (outer backbone concerns)
#   - get_output() designed together with RoboticsIncidentGraphNode.merge_output()

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph import context_bridge
from src.nodes.compliance_validate_node import ComplianceValidateNode
from src.nodes.incident_classify_node import IncidentClassifyNode
from src.nodes.report_draft_node import ReportDraftNode
from src.nodes.severity_route_node import SeverityRouteNode
from src.nodes.telemetry_parse_node import TelemetryParseNode
from src.schemas.state import State, to_json
from src.services.service import finite_in_range

#: Runtime parameters this graph forwards to its nodes, with the bound each is
#: held to. A declared value outside its bound falls back to the default rather
#: than travelling on — see service.finite_in_range for why the bound has to be
#: a finite check and not a comparison.
_RUNTIME_PARAMS: Dict[str, Dict[str, float]] = {
    "low_confidence_threshold": {"low": 0.0, "high": 1.0, "default": 0.5},
}


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for MFG-C2-058.

    Inherits BaseGraph directly for a fully custom node topology.
    Called by RoboticsIncidentGraphNode.get_subgraph() in graph.py.

    Pipeline (linear):
        START
          -> telemetry_parse     (TelemetryParseNode)     — bound + normalise telemetry
          -> incident_classify   (IncidentClassifyNode)   — classify incident type
          -> severity_route      (SeverityRouteNode)      — severity + quality-gate routing
          -> report_draft        (ReportDraftNode)        — draft structured incident report
          -> compliance_validate (ComplianceValidateNode) — checklist + render
          -> END

    All nodes are FunctionNode subclasses returning partial-dict state updates.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # -- Identity --------------------------------------------------------------

    @property
    def name(self) -> str:
        """Unique identifier for this inner graph."""
        return "mfg_c2_058_robotics_incident_workflow"

    @property
    def state_schema(self) -> type:
        """TypedDict subclass shared across inner and outer graph."""
        return State

    # -- Config validation -----------------------------------------------------

    def _validate_config(self) -> None:
        """Validate inner graph config before compilation.

        Config is optional: absent parameters take the defaults in
        _RUNTIME_PARAMS. What is NOT tolerated is a config that is not a
        mapping, because that silently discards everything an operator
        declared. Individual values are bounded in _extra_initial_state()
        rather than rejected here, so one bad value cannot stop the agent
        starting.
        """
        if self.config is not None and not isinstance(self.config, dict):
            raise TypeError(f"{type(self).__name__}: config must be a mapping, got " f"{type(self.config).__name__}")

    # -- Initial state ---------------------------------------------------------

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the declared runtime parameters and the caller's context.

        Two things the framework does not do for a nested graph:

        1. Nodes cannot read graph config, so the bounded parameters are placed
           in state where the nodes that need them can read them.
        2. GraphNode.execute() does not forward input_context to the subgraph —
           verified against the installed SDK — so the outer node stashes it and
           it is picked up here. Without this the inner graph always sees {}.
        """
        config: Dict[str, Any] = self.config if isinstance(self.config, dict) else {}
        limits: Dict[str, float] = {}
        for key, bound in _RUNTIME_PARAMS.items():
            limits[key] = finite_in_range(
                config.get(key, bound["default"]),
                bound["low"],
                bound["high"],
                bound["default"],
            )
        return {
            "runtime_limits": to_json(limits),
            "input_context": context_bridge.take(),
        }

    # -- Node registration -----------------------------------------------------

    def register_nodes(self) -> None:
        """Register all 5 domain nodes.

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize; those are outer backbone
        concerns handled by AgentBaseGraph in graph.py.

        Every node is instantiated with NO constructor arguments: FunctionNode
        subclasses take no __init__, and configuration flows in through state
        (see _extra_initial_state above). Every key registered here is
        referenced in add_edges().
        """
        self._nodes["telemetry_parse"] = TelemetryParseNode()
        self._nodes["incident_classify"] = IncidentClassifyNode()
        self._nodes["severity_route"] = SeverityRouteNode()
        self._nodes["report_draft"] = ReportDraftNode()
        self._nodes["compliance_validate"] = ComplianceValidateNode()

    # -- Edge wiring -----------------------------------------------------------

    def add_edges(self) -> None:
        """Wire the linear robotics incident-report domain topology.

        Each step passes its partial-dict output into the shared State.
        For this template the topology is intentionally linear — no conditional
        branching between domain nodes. route() is implemented as required by
        the ABC but add_conditional_edges() is not used.
        """
        self._sg.add_edge(START, "telemetry_parse")
        self._sg.add_edge("telemetry_parse", "incident_classify")
        self._sg.add_edge("incident_classify", "severity_route")
        self._sg.add_edge("severity_route", "report_draft")
        self._sg.add_edge("report_draft", "compliance_validate")
        self._sg.add_edge("compliance_validate", END)

    # -- Routing ---------------------------------------------------------------

    def route(self, state: AgentState) -> str:
        """Conditional routing — required by BaseGraph ABC.

        For this linear topology add_conditional_edges() is not used, so this
        method is never called at runtime. It is implemented to satisfy the ABC
        contract. Returns END on error so an unexpected call does not re-enter a
        processing node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "compliance_validate"

    # -- Output shape ----------------------------------------------------------

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the output dict returned to the outer graph as sub_result.

        This dict is received by RoboticsIncidentGraphNode.merge_output() in
        graph.py as the `sub_result` argument. Both methods are designed
        together to guarantee field-name consistency:

            Inner get_output()   emits: "compliance_validated_report", "status", ...
            Outer merge_output() reads: sub_result.get("compliance_validated_report"),
                                        sub_result.get("status")
        """
        return {
            "compliance_validated_report": state.get("compliance_validated_report"),
            "compliance_status": state.get("compliance_status"),
            "status": state.get("status"),
            "incident_classification": state.get("incident_classification"),
            "severity_level": state.get("severity_level"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
