# PB (S-3) — CONTAINMENT: what the caller can see when the output gate fires.
#
# AgentBaseGraph.get_output() returns
#     {"output": state.get("formatted_output") or state.get("result"), ...}
#
# Two consequences drive every assertion here:
#
#   * A gate that RAISES ships the ungated report inside the error envelope,
#     because the framework's wrapper returns a bare error partial and the
#     fallback then answers with state["result"].
#   * A gate that returns a FALSY formatted_output re-opens the same fallback.
#
# So the gate must return ERROR, set a TRUTHY replacement, and clear every
# output-bearing field — including compliance_validated_report, the inner
# graph's own copy of the report, which outlives a cleared `result`.
#
# The detector must also be the UNION of this template's patterns and the
# framework's. A class the framework catches and this gate misses makes the
# framework raise INSIDE this node, which discards the clearing below — a
# detector gap is a containment bypass.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.schemas.agent_status import AgentStatus
from src.nodes.post_process_node import _BLOCKED_NOTICE, _OUTPUT_BEARING_FIELDS, PostProcessNode

# Simulated credentials — NOT real. One per class the union must cover.
_SECRETS = {
    "aws_key": "AKIA3FQ7XZ9LMPWV2KDR",
    "stripe_key": "sk_live_9fQ2wZ7xR4tY6uI8",
    # No user:secret@ form: the framework's conn_string pattern needs only 8+
    # characters after the scheme, and a literal URL credential would itself
    # trip the repository's credential gate.
    "conn_string": "postgresql://db-host-01:5432/plant_telemetry",
    "openai_key": "sk-9fQ2wZ7xR4tY6uI8pL3nK5vB7cX1zA4s",
    "credential_assignment": "password=Zq7X2mR9wT4y",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
    "bearer_token": "Bearer 9fQ2wZ7xR4tY6uI8pL3nK5vB",
}


def _report_carrying(secret: str) -> str:
    return f"# Robotics Incident Report\n\n## Root Cause\n\nController log: {secret}\n"


class TestUnionDetector:
    """Both halves of the union are load-bearing, in opposite directions."""

    @pytest.mark.parametrize("label,secret", sorted(_SECRETS.items()))
    def test_every_class_is_withheld(self, label, secret):
        result = PostProcessNode().execute({"result": _report_carrying(secret)})
        assert result["status"] == AgentStatus.ERROR.value, f"{label} was not withheld"

    @pytest.mark.parametrize("label", ["aws_key", "stripe_key", "conn_string"])
    def test_framework_only_classes_are_caught_here_first(self, label):
        # If these were left to the framework, its gate would raise inside this
        # node, the wrapper would return a bare error partial, this node's
        # clearing would be discarded, and get_output() would fall back to the
        # ungated report.
        result = PostProcessNode().execute({"result": _report_carrying(_SECRETS[label])})
        assert result["status"] == AgentStatus.ERROR.value
        assert result["formatted_output"] == _BLOCKED_NOTICE

    def test_local_only_class_is_still_caught(self):
        # The framework's patterns describe credential FORMATS and match none of
        # this shape. Delegating to it wholesale would NARROW the gate.
        result = PostProcessNode().execute({"result": _report_carrying(_SECRETS["credential_assignment"])})
        assert result["status"] == AgentStatus.ERROR.value


class TestContainment:
    @pytest.mark.parametrize("label,secret", sorted(_SECRETS.items()))
    def test_no_output_bearing_field_survives(self, label, secret):
        state = {
            "result": _report_carrying(secret),
            "compliance_validated_report": _report_carrying(secret),
            "formatted_output": _report_carrying(secret),
        }
        result = PostProcessNode().execute(state)
        for field in _OUTPUT_BEARING_FIELDS:
            assert result[field] == _BLOCKED_NOTICE, f"{field} not cleared for {label}"

    @pytest.mark.parametrize("label,secret", sorted(_SECRETS.items()))
    def test_the_secret_appears_nowhere_in_the_returned_delta(self, label, secret):
        result = PostProcessNode().execute({"result": _report_carrying(secret)})
        assert secret not in repr(result)

    def test_released_report_text_does_not_survive(self):
        body = "Robot RBT-4471 must be returned to service without review"
        report = f"# Robotics Incident Report\n\n{body}\n{_SECRETS['aws_key']}\n"
        result = PostProcessNode().execute({"result": report})
        assert body not in repr(result)

    def test_error_log_carries_a_closed_set_reason_only(self):
        result = PostProcessNode().execute({"result": _report_carrying(_SECRETS["aws_key"])})
        joined = " ".join(result["error_log"])
        assert "aws_key" in joined
        assert _SECRETS["aws_key"] not in joined
        assert "Traceback" not in joined
        assert "/src/" not in joined

    def test_replacement_is_truthy_so_the_fallback_stays_closed(self):
        # get_output() answers a falsy formatted_output with state["result"].
        result = PostProcessNode().execute({"result": _report_carrying(_SECRETS["aws_key"])})
        assert result["formatted_output"]
        envelope = AgentBaseGraph.get_output(None, {**result})
        assert envelope["output"] == _BLOCKED_NOTICE
        assert _SECRETS["aws_key"] not in str(envelope)


class TestCleanPathUnaffected:
    def test_a_clean_report_is_surfaced_unchanged(self):
        report = "# Robotics Incident Report\n\nRobot RBT-4471; torque 88.2 Nm; code SAF-0012.\n"
        result = PostProcessNode().execute({"result": report})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"] == report
        # The clean path must not clear anything.
        assert "compliance_validated_report" not in result
