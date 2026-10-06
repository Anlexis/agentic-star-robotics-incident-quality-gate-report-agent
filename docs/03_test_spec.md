# MFG-C2-058 — Test Specification

Manufacturing Robotics Incident Classification & Quality Gate Report Agent.

Test layers: per-node unit tests, integration through the real ASGI entry point,
and Proof-of-Boundary (PoB) security tests.

**Why the integration layer exists.** An earlier suite ran 116 tests in 0.19s
without ever invoking the agent, and the deployed agent could not serve a single
request. Nothing short of driving the real app would have caught it, so the
severity paths, the auth contract and the safety gates are all exercised through
`POST /invoke` rather than only at node level.

## 1. Unit Tests (`tests/unit/`)

### 1.1 Caller-data contract (`test_service_contract.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-CON-01 | identifier containing `\n`, `\r\n`, tab, leading `-`/`#`, `|`, `*`, backtick, link syntax | replaced with the placeholder, reason `disallowed_characters`, input never echoed |
| U-CON-02 | ordinary plant identifiers (`RBT-4471`, `LINE A3`, `M-710iC`) | pass through unchanged |
| U-CON-03 | identifier over its length bound | replaced, reason `too_long` |
| U-CON-04 | identifier containing the platform mask sentinel | replaced, reason `redacted_by_input_filter`; sentinel never reported as a value |
| U-CON-05 | 500 error codes / oversize free text / oversize sensor map | capped, truncation reason recorded |
| U-CON-06 | duplicate and lower-case error codes | upper-cased, deduplicated in first-seen order |
| U-CON-07 | `NaN`, `Infinity`, out-of-range and unparseable numbers through `finite_in_range` | fall back to the default (fail closed) |

### 1.2 Input screens (`test_input_screens.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-SCR-01 | `<<SYS>>`, `<|system|>`, `<|endoftext|>` | framework `detect_injection` returns `[]` (pinned) **and** the local screen flags `chat_control_token` |
| U-SCR-02 | `<|…|>`, `[INST]`, `[/INST]`, `<<SYS>>`, `<system>`, `## System` | flagged as one class |
| U-SCR-03 | instruction-override phrasings | flagged `instruction_override` |
| U-SCR-04 | ordinary engineering notes ("ignore the previous reading") | not flagged |
| U-SCR-05 | `ig<b>nore</b> all <i>previous</i> instructions` | flagged after the markup strip |
| U-SCR-06 | URL-encoded and zero-width-obfuscated directives | normalised then flagged |
| U-SCR-07 | `\u`-escaped control token in a JSON document | invisible raw and to the framework; flagged after parsing |
| U-SCR-08 | control token in a mapping KEY | flagged |
| U-SCR-09 | structure nested past the depth ceiling | refused, not recursed |
| U-SCR-10 | `AKIA…`, `sk_live_…`, `postgresql://…` | credential union flags the framework-only classes |
| U-SCR-11 | `password=…`, `api_key: …` | credential union flags the template-only class |
| U-SCR-12 | ordinary report text | clean |

### 1.3 PreProcessNode (S-1/S-2) (`test_pre_post_process_nodes.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-PRE-01 | empty / whitespace / missing / non-string `user_input` | `status=ERROR`, truthy refusal notice in `formatted_output` **and** `result` |
| U-PRE-02 | record over the size bound | `status=ERROR`, bound stated, offending length not reported |
| U-PRE-03 | input containing e-mail / badge / phone | each redacted to `[REDACTED]` in `validated_input` |
| U-PRE-04 | valid JSON telemetry | `status=SUCCESS`, `validated_input` present, `enriched_context.source` set |
| U-PRE-05 | credential-bearing record, driven at `_extra_security_gate_input` | refused before `execute()` runs; notice and `error_log` echo neither the value nor the field |
| U-PRE-06 | clean record | gate returns the state untouched |

### 1.4 TelemetryParseNode (`test_telemetry_parse_node.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-TEL-01 | JSON with identifiers and codes | codes upper-cased and deduplicated; `data_quality` empty |
| U-TEL-02 | nested `telemetry` block | unwrapped |
| U-TEL-03 | free text (non-JSON) | carried as a note; no crash |
| U-TEL-04 | scalar `error_codes` | coerced to a one-element list |
| U-TEL-05 | sensor readings | keys retained as signals, VALUES dropped from state |
| U-TEL-06 | `robot_id` = `rbt\n## x` (short) | replaced, flagged `disallowed_characters` — proves the alphabet guard, not the length cap |
| U-TEL-07 | full forged section in `robot_id` | no fragment of it survives into any field |
| U-TEL-08 | masked `robot_id` | flagged `redacted_by_input_filter` |
| U-TEL-09 | 400 codes / 400 joints / 400 sensor keys / long note | every cap applied, each truncation flagged |
| U-TEL-10 | `NaN` in a sensor reading | ingest survives; `to_json` refuses non-finite values outright |

### 1.5 IncidentClassifyNode (`test_incident_classify_node.py`)

| TC | Telemetry signals | Expected |
|----|-------------------|----------|
| U-CLS-01..04 | `SAF`/`ESTOP`, `CAL`/`TCP`, `SW`/`COMM`, `MEC`/`MOT` code prefixes | the matching incident type |
| U-CLS-05 | keyword in the free-text note | classified from the note |
| U-CLS-06 | sensor key as a signal | contributes a `kw:` signal |
| U-CLS-07 | no recognisable signals | `unknown`, `confidence=0.0` |
| U-CLS-08 | many matched signals | confidence rises with signal count, capped at 0.95 |
| U-CLS-09 | many codes | rendered signal list capped |
| U-CLS-10 | the same telemetry twice | identical result (determinism) |

### 1.6 SeverityRouteNode (`test_severity_route_node.py`)

| TC | Classification / codes / config | Expected |
|----|---------------------------------|----------|
| U-SEV-01..05 | each incident type | documented base severity + quality gate |
| U-SEV-06 | safety-critical code on a lower base | escalated to at least `HIGH`, rationale records it |
| U-SEV-07 | confidence below the threshold | escalated one step; `CRITICAL` never downgraded |
| U-SEV-08 | `low_confidence_threshold` 0.5 vs 0.9, same incident | `MEDIUM` vs `HIGH` — the declared value changes the answer |
| U-SEV-09 | `NaN` / `Infinity` confidence, injected as raw JSON tokens | falls back to 0.0 rather than skipping the escalation |
| U-SEV-10 | unusable declared threshold (non-finite, out of range, unparseable) | falls back to 0.5 rather than disabling the rule |

### 1.7 ReportDraftNode (`test_report_draft_node.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-DRF-01 | classification + severity + telemetry | every documented section drafted |
| U-DRF-02 | each incident type | corrective actions match that type's playbook |
| U-DRF-03 | rejected input fields | a data-quality section names each, by closed-set label |
| U-DRF-04 | severity rationale present | rendered so a reviewer can see why the severity was set |
| U-DRF-05 | maximal legal identifiers and code lists | no section body gains a line; only the deliberate bullet lists are multi-line |

### 1.8 ComplianceValidateNode (`test_compliance_validate_node.py`)

| TC | Input | Expected |
|----|-------|----------|
| U-CMP-01 | complete classified report | Markdown rendered, checklist all `[x]`, `compliance_status=complete` |
| U-CMP-02 | `incident_type=unknown` / no corrective actions / `CRITICAL` not routed to a safety review | `status=SUCCESS`, `compliance_status=incomplete`, report STILL returned with the unmet item unticked |
| U-CMP-03 | rendered report | says "Report completeness checklist", never claims regulatory conformance, and disclaims review and warranty |
| U-CMP-04 | oversize draft | report capped and the truncation stated |
| U-CMP-05 | missing upstream state | still renders a report, marked incomplete |

### 1.9 Main slot (`test_main_node.py`) and composition (`test_graph_composition.py`)

`get_subgraph()` returns a fresh inner graph; `extract_input()` prefers
`validated_input`; `merge_output()` returns only the four changed keys.

## 2. Integration Tests (`tests/integration/`)

### 2.1 The real ASGI entry point (`test_invoke_e2e.py`)

| TC | Scope | Expected |
|----|-------|----------|
| I-AUTH-01 | no / wrong / non-bearer credential | 401 |
| I-AUTH-02 | `INVOKE_AUTH_TOKEN` and `STG_INTERNAL_RUNNER_TOKEN` | both accepted |
| I-AUTH-03 | neither credential configured | 503, never an anonymous admission |
| I-RUN-01 | valid telemetry at the DECLARED trust level | `status=success`, non-empty report naming the robot |
| I-RUN-02 | free-text note / unrecognised code | still a report, marked incomplete |
| I-DEP-01 | `SAF` / `MOT` / `SW` / unmatched codes | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` each reachable, with its quality gate |
| I-DEP-02 | two different incidents | different reports (output depends on input) |
| I-VAL-01 | empty / oversize `input` | 422 at the request schema |
| I-CTX-01 | undeclared `input_context` key | dropped, request succeeds |
| I-CTX-02 | credential-shaped value in a declared field | 400 naming the field, never the value |
| I-CTX-03 | ordinary domain text on the same field | accepted |
| I-SEC-01 | control-token-bearing record | refused; no report published; the marker never echoed |
| I-SEC-02 | `<<SYS>>` / `<|system|>` — the classes the framework misses | refused with THIS template's readable notice |
| I-SEC-03 | `\u`-escaped marker | refused after parsing |
| I-SEC-04 | credential in the record | refused; the value appears nowhere in the response |
| I-SEC-05 | forged section in `robot_id` | report produced without it, data-quality flag raised |
| I-SEC-06 | title-case robot identity (masked by the platform filter) | reported as redacted, never certified |

### 2.2 Runtime configuration (`test_runtime_config_e2e.py`)

| TC | Scope | Expected |
|----|-------|----------|
| I-CFG-01 | the shipped `config/config.yaml` | declares the documented keys and drives the shipped behaviour |
| I-CFG-02 | `low_confidence_threshold` 0.5 vs 0.9 on the same incident | severity and quality gate both change |
| I-CFG-03 | absent config | documented default applies |
| I-CFG-04 | unusable declared value | falls back rather than disabling the rule |
| I-CFG-05 | non-mapping config | refused at compile rather than silently discarded |
| I-CFG-06 | `input_context` across the subgraph boundary | the bridge carries it; the stash clears on read so it cannot leak between requests |

## 3. Proof-of-Boundary (`tests/proof_of_boundary/`)

| TC | File | Asserts |
|----|------|---------|
| PoB-IMPORT-01 | `test_import_isolation.py` | no platform-SDK import anywhere in `src/`; outer class inherits `AgentBaseGraph` |
| PoB-STATE-01 | `test_state_safety.py` | every structured State field is a JSON string; no credential/PII field names in the schema |
| PoB-S1-01 | `test_s1_injection.py` | injection-bearing input is refused and nothing is published |
| PoB-S3-01 | `test_s3_no_pii_leak.py` | operator PII injected at the input never reaches the report; the S-3 gate withholds credential-bearing output with a TRUTHY notice |
| PoB-S3-02 | `test_s3_containment.py` | every credential class in the union is withheld; `result`, `formatted_output` and `compliance_validated_report` are all cleared; the secret appears nowhere in the returned delta; `error_log` carries a closed-set reason with no traceback or source path; the replacement is truthy so `get_output()`'s fallback stays closed |
| PoB-06 | `test_pb_invoke_order.py` | `S-1 → S-2 → execute() → S-3` order, and S-1 denial before `execute()` |
| PoB-07 | `test_pb7_hitl_interrupt_propagation.py` | HITL interrupt propagation contract |

## 4. Mutation evidence

Each fix was faulted on the DATA path and the suite re-run; every mutant is
caught. Three restore the ORIGINAL shipped code, because a single guard removed
from a layered fix often leaves a suite green when each layer alone contains the
fault.

| Mutant | Layer it falsifies | Failures |
|--------|--------------------|----------|
| drop the identifier alphabet check | inert rendering | 10 |
| drop the redaction-sentinel check | masked-value handling | 3 |
| drop the error-code cap | structural caps | 2 |
| narrow the S-3 gate to local patterns only | detector union (framework half) | 18 |
| narrow the S-3 gate to framework patterns only | detector union (local half) | 11 |
| stop clearing output-bearing fields | containment | 8 |
| make the withheld replacement falsy | `get_output()` fallback | 2 |
| drop the control-token class | injection screen | 18 |
| screen the raw text only | post-parse screen | 2 |
| drop the refusal envelope | refusal containment | 4 |
| **restore `INTERNAL` on a domain node** | trust wiring (original defect) | 23 |
| stop handing config to the inner graph | runtime-config path | 2 |
| drop the finite guard on the threshold | fail-closed numerics | 5 |
| **restore `ERROR` on an incomplete checklist** | report delivery (original defect) | 6 |
| **restore the anonymous-by-default adapter** | entry point (original defect) | 18 |

## 5. STG Quality Gate

- All unit + integration + PoB suites green in CI.
- S-3 gate proven to withhold a credential-bearing report and to clear every
  output-bearing field (PoB-S3-01, PoB-S3-02).
- The agent serves `POST /invoke` at its declared trust level (I-RUN-01).
- `gate-scaffold-integrity`, `gate-composition`, `gate-import-isolation`,
  `gate-invoke-chain`, `gate-credential-scan`, `gate-audit-trace-check`,
  `gate-trust-level`, `gate-manifest-schema` all PASS.
