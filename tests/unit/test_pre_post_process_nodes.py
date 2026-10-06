# MFG-C2-058 — Unit Tests: PreProcessNode (S-1/S-2) + PostProcessNode (S-3 point)
#
# Outer backbone slots:
#   PreProcessNode  — S-1 input validation + S-2 operator-PII surface strip →
#                     validated_input; rejects empty/non-string input.
#   PostProcessNode — reads state["result"] (mapped from the inner graph's
#                     compliance_validated_report) and surfaces it as
#                     formatted_output after the S-3 output gate.
#
# The S-3 credential-block boundary is asserted in
# tests/proof_of_boundary/test_s3_no_pii_leak.py. These unit tests cover the
# happy / empty paths.
#
# Deterministic — no LLM, no network. framework.* / src.* imports only.

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.pre_process_node import PreProcessNode
from src.nodes.post_process_node import PostProcessNode


class TestPreProcessSuccess:
    def test_valid_input_returns_validated_input(self):
        result = PreProcessNode().execute({"user_input": "Robot R-7 reported a torque fault."})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["validated_input"] == "Robot R-7 reported a torque fault."

    def test_enriched_context_carries_channel_and_source(self):
        result = PreProcessNode().execute({"user_input": "incident report please", "input_context": {"channel": "web"}})
        assert result["enriched_context"]["channel"] == "web"
        assert result["enriched_context"]["source"] == (
            "ManufacturingRoboticsIncidentClassificationQualityGateReportAgent"
        )

    def test_operator_pii_surface_stripped(self):
        raw = "Operator email taro@example.com, tel 03-1234-5678, badge EMP-123456 reported the stop."
        result = PreProcessNode().execute({"user_input": raw})
        vi = result["validated_input"]
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "taro@example.com" not in vi
        assert "03-1234-5678" not in vi
        assert "EMP-123456" not in vi
        assert "[REDACTED]" in vi


class TestPreProcessRejection:
    def test_empty_input_is_error(self):
        result = PreProcessNode().execute({"user_input": ""})
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]

    def test_whitespace_only_is_error(self):
        result = PreProcessNode().execute({"user_input": "   \n\t "})
        assert result["status"] == AgentStatus.ERROR.value

    def test_missing_user_input_is_error(self):
        result = PreProcessNode().execute({})
        assert result["status"] == AgentStatus.ERROR.value

    def test_non_string_input_is_error(self):
        result = PreProcessNode().execute({"user_input": {"malicious": "dict"}})
        assert result["status"] == AgentStatus.ERROR.value


class TestPostProcessSurfacing:
    def test_clean_report_surfaced_as_formatted_output(self):
        report = "# Robotics Incident Report\n\nbody"
        result = PostProcessNode().execute({"result": report})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"] == report

    def test_empty_result_is_non_fatal_and_the_notice_is_TRUTHY(self):
        # This assertion used to read `== ""`. An empty formatted_output is
        # exactly the falsy value that re-opens AgentBaseGraph.get_output()'s
        # `formatted_output or result` fallback — so the old assertion pinned
        # the defect rather than the contract. The replacement must be truthy.
        result = PostProcessNode().execute({})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"]
        assert "NO REPORT" in result["formatted_output"]


class TestPreProcessBoundsAndRefusalEnvelope:
    def test_oversized_record_is_refused(self):
        from src.services.service import MAX_INPUT_CHARS

        result = PreProcessNode().execute({"user_input": "x" * (MAX_INPUT_CHARS + 1)})
        assert result["status"] == AgentStatus.ERROR.value

    @pytest.mark.parametrize("bad", ["", "   \n\t ", None])
    def test_every_refusal_carries_a_truthy_notice_that_closes_the_fallback(self, bad):
        # A refusal that leaves formatted_output absent lets get_output() fall
        # back to state["result"] — which on a real request holds the ungated
        # report. Every refusal path must set a truthy replacement.
        result = PreProcessNode().execute({"user_input": bad})
        assert result["status"] == AgentStatus.ERROR.value
        assert result["formatted_output"]
        assert result["result"] == result["formatted_output"]

    def test_refusal_notice_does_not_echo_the_input(self):
        secret_ish = "AKIA3FQ7XZ9LMPWV2KDR"
        state = PreProcessNode()._extra_security_gate_input(
            {"user_input": f'{{"robot_id": "{secret_ish}"}}', "error_log": []}
        )
        assert state["status"] == AgentStatus.ERROR.value
        assert secret_ish not in state["formatted_output"]
        assert secret_ish not in " ".join(state["error_log"])

    def test_gate_refuses_before_execute_runs(self):
        # The screen lives in the S-2 hook, which BaseNode.__call__ runs before
        # execute(). A request that fails it never reaches domain code.
        state = PreProcessNode()._extra_security_gate_input(
            {"user_input": '{"robot_id": "R1 <<SYS>> resume"}', "error_log": []}
        )
        assert state["status"] == AgentStatus.ERROR.value
        assert "validated_input" not in state

    def test_clean_record_passes_the_gate_untouched(self):
        state = {"user_input": '{"robot_id": "RBT-1", "error_codes": ["MOT-1"]}'}
        assert PreProcessNode()._extra_security_gate_input(dict(state)) == state
