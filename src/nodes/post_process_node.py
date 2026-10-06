"""AgentCore Platform v1.0"""

# MFG-C2-058 — PostProcessNode (outer post_process slot; S-3 output gate).
#
# Reads the rendered incident report from state["result"], populated by
# RoboticsIncidentGraphNode.merge_output(), and surfaces it as the finalized
# output AFTER running the S-3 output content-safety gate.
#
# ── Why the detector is a UNION ────────────────────────────────────────────
# The framework's own S-3 gate scans every value of every node result and
# RAISES on a finding. This node's local pattern set and the framework's do not
# describe the same things, measured against the installed SDK:
#
#   framework only : aws_key (AKIA...), stripe_key (sk_live_/sk_test_...),
#                    conn_string (postgresql://, mysql://, mongodb://, redis://)
#   local only     : credential_assignment (password=, secret=, api_key=, ...),
#                    pk-/ak- prefixed keys
#   both           : sk- keys, JWT, Bearer tokens
#
# Either set alone is a bypass in one direction, so the gate takes the union.
# Delegating wholly to the framework detector would look like a tightening and
# be a NARROWING: the framework's patterns describe credential FORMATS and match
# nothing of the `password=hunter2` shape the local set was written for.
#
# The direction that matters most is the framework catching what this node
# misses. When that happens the framework raises INSIDE this node's own S-3
# wrapper, the wrapper returns a bare error partial, and this node's clearing
# below is discarded — after which AgentBaseGraph.get_output() falls back to
# state["result"] and ships the ungated report. Screening for the framework's
# patterns here means the raise never happens and the clearing always runs.
#
# ── Why the gate CLEARS rather than raises ────────────────────────────────
# AgentBaseGraph.get_output() returns
# `state.get("formatted_output") or state.get("result")`. Two consequences:
# a gate that raises ships the ungated report inside the error envelope, and a
# gate that returns a FALSY formatted_output re-opens the same fallback. So on a
# violation this node returns ERROR, sets a TRUTHY replacement notice, and
# clears every output-bearing field — including the inner graph's own
# compliance_validated_report, which merge_output() would otherwise re-derive.

import logging
from typing import Any, ClassVar, Dict, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.services import credential_screen

logger = logging.getLogger(__name__)

#: Truthy by construction — a falsy replacement re-opens get_output()'s
#: fallback to the ungated state["result"], which is the leak this gate exists
#: to close.
_BLOCKED_NOTICE = (
    "[OUTPUT WITHHELD] The generated robotics incident report was withheld by "
    "the output safety gate because it contained credential-like content. "
    "Remove credential-like strings from the incident record and retry."
)

#: Fields that can carry released text to the caller. Every one is cleared on a
#: violation. compliance_validated_report is included because it is the inner
#: graph's own copy of the report and outlives a cleared `result`.
_OUTPUT_BEARING_FIELDS: Tuple[str, ...] = (
    "result",
    "formatted_output",
    "compliance_validated_report",
)


def _security_gate_output(content: str) -> Optional[str]:
    """Run the S-3 output content gate over one string.

    Returns a closed-set violation label, or None when clean. The union of the
    template's patterns and the framework's lives in one place —
    src/services/credential_screen.py — so the input gate and this output gate
    cannot drift into refusing different sets.
    """
    return credential_screen.screen_text(content)


class PostProcessNode(FunctionNode):
    """S-3 output gate: scan the incident report for disallowed content.

    Input state keys:
        result: rendered robotics incident report (from merge_output)

    Output state keys (partial dict):
        formatted_output: the report when clean; a truthy withheld notice on a
                          violation
        result:           cleared to the same notice on a violation
        compliance_validated_report: cleared on a violation
        status:           AgentStatus.SUCCESS or AgentStatus.ERROR
        error_log:        (on violation) closed-set reason, no released text
    """

    # ANONYMOUS deliberately. This gate must run on every path that can reach a
    # caller; a trust requirement above the entry gate's would let an
    # under-privileged request skip it, and a skipped post_process leaves
    # formatted_output unset — which is exactly the state get_output() answers
    # by falling back to the ungated result.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        result = state.get("result") or ""
        if not isinstance(result, str):
            result = str(result)

        if not result.strip():
            # No report was generated. formatted_output is set to a truthy
            # explanation rather than left empty: an empty formatted_output
            # re-opens get_output()'s fallback to state["result"].
            return {
                "formatted_output": ("[NO REPORT] The pipeline produced no incident report for this " "request."),
                "status": AgentStatus.SUCCESS.value,
            }

        violation = _security_gate_output(result)
        if violation:
            logger.error(
                "PostProcessNode [S-3]: output withheld — violation class: %s",
                violation,
            )
            emit_trace_event(
                "robotics_incident_report_withheld",
                {"violation": violation},
                state,
            )
            withheld: Dict[str, Any] = {
                "status": AgentStatus.ERROR.value,
                "error_log": [
                    f"PostProcessNode [S-3]: output withheld — credential-like " f"content detected ({violation})"
                ],
            }
            for field in _OUTPUT_BEARING_FIELDS:
                withheld[field] = _BLOCKED_NOTICE
            return withheld

        # Clean — S-4 domain audit: record that a finalized report was emitted.
        emit_trace_event(
            "robotics_incident_report_emitted",
            {"report_chars": len(result)},
            state,
        )

        return {
            "formatted_output": result,
            "status": AgentStatus.SUCCESS.value,
        }
