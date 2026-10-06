# MFG-C2-058 — Unit tests: the caller-data contract (src/services/service.py).
#
# These are the bounds every caller field is held to. They are asserted here
# rather than only through the pipeline because the pipeline can mask them: the
# platform's own input filter rewrites some values before this template's code
# sees them, so a pipeline-level test can pass for the wrong reason.
#
# Deterministic — no LLM, no network.

import math

import pytest

from src.services.service import (
    MAX_ERROR_CODES,
    MAX_IDENTIFIER_CHARS,
    MAX_FREE_TEXT_CHARS,
    REDACTED_IDENTIFIER,
    UNUSABLE_IDENTIFIER,
    Service,
    clean_error_codes,
    clean_event_window,
    clean_free_text,
    clean_identifier,
    clean_signal_keys,
    finite_in_range,
    is_masked,
)


class TestIdentifierAlphabet:
    """Nothing that reaches the report may be able to express Markdown."""

    @pytest.mark.parametrize(
        "raw",
        [
            "rbt\n## corrective actions",  # heading forgery — the headline defect
            "rbt\r\n- resume the line",  # CRLF list forgery
            "rbt\t9",  # tab
            "- rbt",  # leading list bullet
            "#rbt",  # leading heading marker
            "rbt|x",  # table cell
            "rbt*x*",  # emphasis
            "rbt`x`",  # code span
            "rbt[x](http://e)",  # link
            " ",  # whitespace only handled as absent
        ],
    )
    def test_structure_bearing_identifier_is_replaced_not_echoed(self, raw):
        value, reason = clean_identifier(raw)
        if raw.strip():
            assert reason == "disallowed_characters"
            assert value == UNUSABLE_IDENTIFIER
            # The rejected text must not come back to the caller in any form.
            assert raw.strip() not in value
        else:
            assert (value, reason) == ("", "")

    @pytest.mark.parametrize("raw", ["RBT-4471", "LINE A3", "rbt_9", "M-710iC", "R.2026.01", "LINE A3 CELL 2"])
    def test_ordinary_plant_identifiers_survive(self, raw):
        value, reason = clean_identifier(raw)
        assert (value, reason) == (raw, "")

    def test_over_length_identifier_is_replaced(self):
        value, reason = clean_identifier("R" * (MAX_IDENTIFIER_CHARS + 1))
        assert reason == "too_long"
        assert value == UNUSABLE_IDENTIFIER

    def test_non_string_identifier_is_replaced(self):
        assert clean_identifier({"nested": "object"}) == (UNUSABLE_IDENTIFIER, "not_a_string")

    def test_absent_identifier_is_not_an_error(self):
        assert clean_identifier(None) == ("", "")


class TestEventWindowAlphabet:
    """Timestamps and intervals need ':' '/' '+' — none of which can open Markdown
    structure on a line that cannot contain a newline. The characters that can
    stay excluded, and the STG smoke record's own event_window must pass."""

    @pytest.mark.parametrize(
        "raw",
        [
            "2026-09-01T10:00Z/2026-09-01T10:05Z",
            "2025-06-01T10:00Z..2025-06-01T10:05Z",
            "2026-09-01T10:00:00+09:00",
            "shift 2 window 3",
        ],
    )
    def test_real_timestamps_and_intervals_survive(self, raw):
        assert clean_event_window(raw) == (raw, "")

    @pytest.mark.parametrize("raw", ["10:00\n## x", "- 10:00", "#10:00", "10:00|x", "10:00 [x](y)"])
    def test_structure_bearing_window_is_replaced(self, raw):
        value, reason = clean_event_window(raw)
        assert reason == "disallowed_characters"
        assert value == UNUSABLE_IDENTIFIER

    def test_masked_window_is_reported_as_redacted(self):
        assert clean_event_window("[MASKED]") == (REDACTED_IDENTIFIER, "redacted_by_input_filter")


class TestRedactionSentinel:
    """A masked value is not an extracted value.

    The platform's input filter masks person-name shapes, and a title-case robot
    model is one. The template must report that the field was redacted rather
    than certify the sentinel as the robot's identity.
    """

    def test_sentinel_is_recognised(self):
        assert is_masked("[MASKED]")
        assert is_masked("RBT [MASKED] 9")
        assert not is_masked("RBT-9")

    def test_masked_identifier_reports_redaction_not_a_value(self):
        value, reason = clean_identifier("[MASKED]")
        assert reason == "redacted_by_input_filter"
        assert value == REDACTED_IDENTIFIER
        assert "[MASKED]" not in value


class TestStructuralCaps:
    def test_error_codes_capped_and_flagged(self):
        codes, reasons = clean_error_codes([f"MOT-{i:05d}" for i in range(500)])
        assert len(codes) == MAX_ERROR_CODES
        assert "error_codes_truncated" in reasons

    def test_error_codes_deduplicated_in_first_seen_order(self):
        codes, _ = clean_error_codes(["MOT-1", "mot-1", "SAF-2", "MOT-1"])
        assert codes == ["MOT-1", "SAF-2"]

    def test_structure_bearing_error_code_is_dropped_not_rendered(self):
        codes, reasons = clean_error_codes(["MOT-1", "MOT\n## forged", "OK-2"])
        assert codes == ["MOT-1", "OK-2"]
        assert "error_codes_rejected" in reasons

    def test_free_text_truncated_and_flagged(self):
        text, reasons = clean_free_text("x" * (MAX_FREE_TEXT_CHARS + 500))
        assert len(text) == MAX_FREE_TEXT_CHARS
        assert reasons == ["free_text_truncated"]

    def test_signal_keys_capped_and_alphabet_held(self):
        raw = {f"k{i}": i for i in range(50)}
        raw["bad\nkey"] = 1
        kept, reasons = clean_signal_keys(raw, cap=10)
        assert len(kept) <= 10
        assert "sensor_readings_truncated" in reasons
        assert all("\n" not in k for k in kept)


class TestFiniteParser:
    """NaN and Infinity parse cleanly and then compare False against every
    bound, so a bare range check admits them silently. The parser fails closed.
    """

    @pytest.mark.parametrize("raw", [float("nan"), float("inf"), float("-inf"), "NaN", "Infinity", "-Infinity"])
    def test_non_finite_falls_back_to_default(self, raw):
        assert finite_in_range(raw, 0.0, 1.0, 0.5) == 0.5

    @pytest.mark.parametrize("raw", [-0.1, 1.1, 1e9, -1e9])
    def test_out_of_range_falls_back_to_default(self, raw):
        assert finite_in_range(raw, 0.0, 1.0, 0.5) == 0.5

    @pytest.mark.parametrize("raw", ["abc", None, {}, [], object()])
    def test_unparseable_falls_back_to_default(self, raw):
        assert finite_in_range(raw, 0.0, 1.0, 0.5) == 0.5

    @pytest.mark.parametrize("raw,want", [(0.0, 0.0), (1.0, 1.0), ("0.75", 0.75), (0.25, 0.25)])
    def test_valid_values_pass_through(self, raw, want):
        got = finite_in_range(raw, 0.0, 1.0, 0.5)
        assert got == want
        assert math.isfinite(got)


class TestPublishedContract:
    def test_contract_is_data_and_matches_the_constants(self):
        contract = Service.contract()
        assert contract["max_error_codes"] == MAX_ERROR_CODES
        assert contract["max_identifier_chars"] == MAX_IDENTIFIER_CHARS
        assert "channel" in contract["caller_context_fields"]
