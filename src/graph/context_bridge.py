"""AgentCore Platform v1.0"""

# MFG-C2-058 — Outer-to-inner context bridge (Cat 2 nested architecture).
#
# GraphNode.execute() calls
#
#     subgraph.invoke(user_input, session_id=ctx.session_id, ctx=ctx)
#
# and passes NO input_context. Verified against the installed SDK: the parameter
# exists on BaseGraph.invoke() but GraphNode does not forward it, so anything a
# caller sends alongside the request reaches the outer graph and stops there.
# The inner graph sees `input_context: {}`.
#
# The bridge closes that without touching the framework:
#
#   outer RoboticsIncidentGraphNode.extract_input(state)  -> stash(...)
#   inner DomainWorkflowGraph._extra_initial_state()      -> take()
#
# The ordering is what makes it safe. GraphNode.execute() calls get_subgraph()
# first, extract_input() second, and only then invoke() — and _extra_initial_state()
# runs inside invoke(). So the stash is always written before it is read.
#
# A ContextVar rather than a module global: ContextVars are per-context, so two
# requests handled on different threads or tasks cannot see each other's stash.
# take() clears as it reads, so a stale value from an earlier request can never
# be picked up by a later one that did not write.

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Dict, Optional

_BRIDGE: ContextVar[Optional[Dict[str, Any]]] = ContextVar("mfg_c2_058_subgraph_context", default=None)


def stash(payload: Dict[str, Any]) -> None:
    """Record the context the inner graph should start with."""
    _BRIDGE.set(dict(payload))


def take() -> Dict[str, Any]:
    """Read and clear the stashed context. Absent stash -> empty mapping."""
    payload = _BRIDGE.get()
    _BRIDGE.set(None)
    return dict(payload) if payload else {}


def clear() -> None:
    """Drop any stashed context. Used by tests to guarantee isolation."""
    _BRIDGE.set(None)
