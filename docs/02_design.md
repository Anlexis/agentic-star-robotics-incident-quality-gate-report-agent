# MFG-C2-058 — Design Specification

Manufacturing Robotics Incident Classification & Quality Gate Report Agent.

## 1. Position in AgentCore Architecture

- **Template ID**: MFG-C2-058
- **Agent Class (manifest `class:`)**: `Graph` (alias of `MfgC2058Agent`)
- **Category**: Cat 2 (domain-specific pipeline)
- **L1 Base**: `AgentBaseGraph` (direct L1 inheritance — no L2 class in the inheritance chain)
- **Pattern**: DocGeneration (a peer template conceptual reference), realized as a
  two-layer **nested** Cat 2 graph.
- **Three-layer separation**:
  - State: flat `TypedDict` composition (no Pydantic — msgpack incompatible)
  - Node: L1 inheritance (`FunctionNode`; `execute(self, state) -> Dict[str, Any]` override only.
    The framework calls `execute(state)` — a node cannot read graph config directly, so
    declared runtime parameters arrive in state; see §3.1)
  - Graph: composition (`register_nodes()` for slot substitution; inner workflow via `GraphNode`)

## 2. Nested Architecture Overview

The outer graph keeps the fixed 5-node backbone. The domain workflow lives
entirely inside an inner `BaseGraph`, wrapped by a `GraphNode` in the outer
`main` slot.

```
Outer backbone (AgentBaseGraph — fixed, add_edges() NOT overridden):
  START → initialize → pre_process → main → {route} → post_process → finalize → END
                                       │ (retry, max_retry from config.yaml)
                                       ▼
                                    pre_process

main slot = RoboticsIncidentGraphNode (GraphNode) → DomainWorkflowGraph (inner BaseGraph):
  START → telemetry_parse → incident_classify → severity_route
        → report_draft → compliance_validate → END
```

- `src/graph/graph.py` — outer graph (`MfgC2058Agent(AgentBaseGraph)` + `Graph` alias) and `RoboticsIncidentGraphNode`.
- `src/graph/domain_workflow_graph.py` — inner graph (`DomainWorkflowGraph(BaseGraph)`, 7 ABC methods, linear topology).

### 2.1 Outer node configuration

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|----------------|-------------|--------------|--------------------|
| initialize | schema_version, session_id, trust_level | user_input | (framework) | InitializeNode (default) |
| pre_process | S-1 input validation + S-2 operator-PII screen | user_input | validated_input | PreProcessNode (FunctionNode) |
| main | Delegate to inner DomainWorkflowGraph | validated_input | compliance_validated_report, result, status | RoboticsIncidentGraphNode (GraphNode) |
| post_process | S-3 output content gate + containment (§4.1) | result | formatted_output, result, compliance_validated_report, status | PostProcessNode (FunctionNode) |
| finalize | response_metadata, total_time_ms | — | (framework) | FinalizeNode (default) |

### 2.2 Inner domain node configuration

| Node | Responsibility | Input State | Output State |
|------|----------------|-------------|--------------|
| telemetry_parse | Parse, BOUND and normalise the caller's telemetry record (§3.2) | validated_input | parsed_telemetry |
| incident_classify | Classify incident type (deterministic rule table) | parsed_telemetry | incident_classification |
| severity_route | Severity (CRITICAL/HIGH/MEDIUM/LOW) + quality-gate routing; reads `low_confidence_threshold` | incident_classification, parsed_telemetry, runtime_limits | severity_level |
| report_draft | Draft summary / classification / severity / root cause / corrective actions | incident_classification, severity_level, parsed_telemetry | report_draft |
| compliance_validate | Completeness checklist + render final report | report_draft, incident_classification, severity_level, parsed_telemetry | compliance_validated_report, compliance_status, status |

## 3. State Definition

All structured fields are stored as **JSON strings** (ADR-005 msgpack safety):
producers call `to_json()` on write, consumers `from_json()` on read.

| Field | Type (stored) | Purpose | Required |
|-------|---------------|---------|----------|
| validated_input | str | Screened, surface-sanitized incident payload | yes |
| parsed_telemetry | str (JSON) | Bounded telemetry record: `{robot_id, robot_model, line_id, event_window, error_codes, joint_state_count, sensor_reading_keys, free_text, data_quality}` | yes |
| incident_classification | str (JSON) | `{incident_type, confidence, signals, candidate_types}` | yes |
| severity_level | str (JSON) | `{severity, quality_gate, escalate, confidence, low_confidence_threshold, rationale}` | yes |
| report_draft | str (JSON) | Section-keyed draft prose | yes |
| compliance_validated_report | str | Final rendered Markdown report | yes |
| compliance_status | str | `complete` / `incomplete` — whether every required checklist item was met | yes |
| runtime_limits | str (JSON) | Declared runtime parameters, bounded, seeded by the inner graph | yes |
| trace_id / correlation_id | str | Framework-managed audit ids (do not write from nodes) | framework |

**State constraints (mandatory):**
- Flat `TypedDict` only (primitives + JSON-serializable types).
- No JWT, API keys, credentials, or operator PII in State (checkpoint DB leakage).
- No raw telemetry stream persisted — only the derived, normalized record.
- `InvocationContext` via `config["configurable"]` only (not in State).
- No Pydantic models / dataclasses / arbitrary Python objects (msgpack incompatible).

### 3.1 How declared configuration reaches a node

`config/agent.yaml` is the registry manifest (identity, entry point, declared
trust level) and holds no tunables. `config/config.yaml` holds the runtime
parameters, and they travel this path:

```
config/config.yaml
  → src/api/server.py           load_runtime_config()
  → MfgC2058Agent(config=...)
  → RoboticsIncidentGraphNode.subgraph_config   (set in register_nodes())
  → DomainWorkflowGraph(config=...)             (get_subgraph())
  → _extra_initial_state()  → state["runtime_limits"]
  → SeverityRouteNode reads it
```

Two framework facts make each hop necessary:

- `BaseNode.__call__` invokes `execute(state)`. There is no config argument, so
  a node cannot read graph config directly — state is the only channel.
- `GraphNode.execute()` calls `subgraph.invoke(user_input, session_id=…, ctx=…)`
  and passes no `input_context`. `src/graph/context_bridge.py` carries it: the
  outer node stashes in `extract_input()`, the inner graph reads in
  `_extra_initial_state()`. The ordering is safe because `GraphNode.execute()`
  calls `extract_input()` before `invoke()`.

Every value is bounded on arrival through `finite_in_range`, so a declared value
that is out of range, unparseable or non-finite falls back to its default rather
than travelling on. `NaN` deserves the explicit mention: it parses cleanly and
then compares `False` against every bound, so an unguarded read switches the rule
it controls off silently rather than erroring.

| Key | Bound | Default | Effect |
|-----|-------|---------|--------|
| `max_retry` | validated by AgentBaseGraph | 3 | backbone retry ceiling |
| `timeout_s` | > 0 | 30 | request deadline enforced by the HTTP entry point |
| `low_confidence_threshold` | [0.0, 1.0] | 0.5 | classifications below it are escalated one severity step |

### 3.2 Caller-data contract

`src/services/service.py` is the single definition of what a caller may send and
what it is held to; `src/api/server.py` and `src/nodes/telemetry_parse_node.py`
both import it, so the bound at the edge and the bound inside the pipeline cannot
drift apart.

| Field | Bound | On violation |
|-------|-------|--------------|
| `input` (whole record) | 1 – 32,000 chars | request refused at the entry gate |
| `robot_id`, `line_id` | ≤ 32 chars, inert alphabet | replaced with a placeholder, flagged in `data_quality` |
| `robot_model` | ≤ 48 chars, inert alphabet | as above |
| `event_window` | ≤ 64 chars, inert alphabet | as above |
| `error_codes` | ≤ 32 entries, ≤ 24 chars each, upper-case inert alphabet | offending entries dropped, count flagged |
| `joint_states` | ≤ 64 entries, reduced to a count | truncation flagged |
| `sensor_readings` | ≤ 64 keys, inert alphabet, VALUES DROPPED | truncation flagged |
| `free_text` | ≤ 4,000 chars, never rendered | truncation flagged |
| `input_context` | only `channel`, `site_id`, `locale`, `requested_by_role` | undeclared keys dropped; credential-shaped values → HTTP 400 |

**Inert alphabet.** Any value that can reach the rendered report is restricted to
letters, digits, `.`, `_`, `-` and single interior spaces — a set that cannot
express Markdown structure. This is a safety property, not a formatting one: the
report is read as a safety document, and before the restriction a `robot_id`
carrying a newline could open a `## Corrective Actions` section of its own,
instructing an operator to resume a line, under a heading still marked as passing
its checklist.

**Rejected values are replaced, never echoed and never truncated-into-the-report.**
A refusal that quotes its input is a reflection channel. What the reader sees
instead is a closed-set label in the report's *Input Data Quality* section naming
which field was unusable and why.

**A redaction sentinel is not a value.** The platform's S-2 input filter masks
person-name shapes before template code runs, and a title-case robot model
("Yaskawa Motoman") is one — so `[MASKED]` arrives as an ordinary string. The
ingest node recognises it and reports the field as redacted rather than
certifying the sentinel as the robot's identity.

## 4. Security Gates (S-1 … S-5)

| Gate | Where | Implementation |
|------|-------|----------------|
| S-1 trust gate | `pre_process` (PreProcessNode) | declares the manifest's `required_trust_level` (VERIFIED_EXTERNAL); every node behind it is ANONYMOUS — see §4.2 |
| S-2 input screen | `pre_process` (PreProcessNode) | `_extra_security_gate_input()` refuses chat-template control tokens, instruction-override directives and credential shapes, screening the raw text AND the parsed document including KEYS (§4.3); `execute()` then bounds the size and redacts operator e-mail / phone / badge identifiers |
| S-3 output gate | `post_process` (PostProcessNode) | scans `result` with the UNION of the template's patterns and the framework detector; on a violation returns ERROR, sets a truthy withheld notice and CLEARS every output-bearing field (§4.1) |
| S-4 audit logging | every node `execute()` | one domain-specific `emit_trace_event()` per node (no node_start/complete/error duplicates) |
| S-5 secrets handling | server.py | `provision_secrets()` via secrets factory; no hardcoded credentials anywhere |

> **S-2/S-3 by node type (ADR-017):** the outer `FunctionNode` slots run the
> S-1/S-2/S-3 gates. `RoboticsIncidentGraphNode` (GraphNode) is a deliberate
> gate no-op — the upstream `pre_process` gate already applied, and the inner
> nodes operate on already-screened, PII-free data.

### 4.1 Output containment

`AgentBaseGraph.get_output()` returns
`{"output": state.get("formatted_output") or state.get("result"), …}`. Three
consequences shape the S-3 gate:

1. **A gate that raises does not contain.** The framework's wrapper catches the
   exception and returns a bare error partial, after which the fallback answers
   with `state["result"]` — the ungated report, inside the error envelope.
2. **A falsy replacement re-opens the same fallback.** The withheld notice is
   truthy by construction, and every refusal path in `pre_process` sets one too.
3. **Clearing `result` alone is not enough.** `compliance_validated_report` is
   the inner graph's own copy of the report and outlives a cleared `result`, so
   the gate clears `result`, `formatted_output` and
   `compliance_validated_report` together.

**The detector is the UNION of this template's patterns and the framework's**
(`src/services/credential_screen.py`), and both halves are load-bearing:

| Caught by | Classes |
|-----------|---------|
| framework only | `aws_key`, `stripe_key`, `conn_string` |
| this template only | `credential_assignment` (`password=…`), `pk-` / `ak-` keys |
| both | `sk-` keys, JWT, Bearer tokens |

Dropping the local patterns to "delegate" to the framework looks like a
tightening and is a narrowing — the framework's patterns describe credential
*formats* and match nothing of the `password=hunter2` shape. Dropping the
framework's is worse: a class it catches and we miss makes it raise *inside*
this node, which discards the clearing above. **A detector gap is a containment
bypass.**

### 4.2 Trust wiring

`PreProcessNode` carries the manifest's declared `required_trust_level`
(`VERIFIED_EXTERNAL`) and is the S-1 boundary for the whole pipeline. Every node
behind it declares `ANONYMOUS`.

That is deliberate rather than permissive. The inner nodes are not independently
addressable — the only route to them is through `pre_process`, which has already
run the S-1 gate for the request — and requiring *more* of them than the entry
point requires refuses callers the manifest admits. Before this change the domain
nodes declared `INTERNAL` while the manifest declared `VERIFIED_EXTERNAL`, and
the measured result was `status=error` with a null output for every caller the
declared contract allows.

`PostProcessNode` is `ANONYMOUS` for a second reason: a gate that can be
S-1-denied is a gate that can be skipped, and a skipped `post_process` leaves
`formatted_output` unset — exactly the state the fallback in §4.1 answers with
the ungated report.

The HTTP entry point resolves a bearer credential to a trust level and admits no
anonymous path. It accepts `INVOKE_AUTH_TOKEN` (external) and
`STG_INTERNAL_RUNNER_TOKEN` (an internal runner); with neither configured it
answers 503 rather than admitting callers the entry gate will reject.

### 4.3 Input screen

The framework's own injection policy runs first, on the raw request. This
template's screen (`src/services/injection_screen.py`) covers what it does not,
measured against the installed SDK rather than assumed:

- **`<<SYS>>`, `<|system|>` and `<|endoftext|>` score no findings at all.** The
  framework matches `<|im_start|>` / `<|im_end|>` by name and `[INST]` / `[SYS]`
  in square brackets, so the class is screened here as a class:
  any `<|…|>` marker, either bracket style, and turn-boundary tags.
- **The framework scans before parsing.** Caller data here is a JSON document, so
  `"<|im_start|>"` contains no literal marker until `json.loads` runs.
  Measured on this template before the change: such a payload passed the
  framework scan and the marker reached the rendered report.
- **The framework scans values, not keys.** Mapping keys steer this agent's
  classifier, so keys are screened too.
- **A sanitiser is not a refusal.** Every string is screened as received *and*
  after markup removal, so a control token is caught before a strip could remove
  it and a directive spliced with markup (`ig<b>nore all previous…`) is caught
  after the strip re-assembles it.

The screen fails closed, reports a closed-set label, and never reflects the
matched text. Credential shapes are refused here too: such a request cannot
succeed either way (the framework's output gate raises at the first node that
carries the value into a result), so refusing at the boundary turns an opaque
mid-pipeline error into a readable refusal.

### 4.4 Completeness verdict, not a conformance claim

The rendered report states **"Report completeness checklist: COMPLETE /
INCOMPLETE"**. The checklist establishes that the report contains what a safety
review needs — a classification, a severity, corrective actions, and a
safety-review routing for the most serious incidents. Whether the plant is
compliant is the reviewer's judgement. A template published without warranty
cannot also certify a regulator's standard.

An incomplete checklist is **not** a failed run. Returning `AgentStatus.ERROR`
made the inner graph raise `SubgraphError`, which discarded the rendered report —
so the engineer reporting an unfamiliar fault received nothing at all.
Completeness is carried in `compliance_status`; `ERROR` is reserved for a genuine
processing failure.

## 5. Composition Pattern

- **Pattern**: GraphNode subgraph (nested Cat 2).
- **Composition target**: `DomainWorkflowGraph` (inner `BaseGraph`), instantiated in `get_subgraph()` with the outer graph's runtime config (§3.1). Domain nodes still take no constructor arguments.
- **Input extraction**: `extract_input()` returns `validated_input` (fallback `user_input`), and stashes the caller's `input_context` for the inner graph — `GraphNode.execute()` does not forward it (§3.1).
- **Output merge**: `merge_output()` maps inner `compliance_validated_report` → outer `result` + `compliance_validated_report`, plus `compliance_status` and `status` (changed keys only).
- **Error propagation strategy**: `propagate` (inner errors re-raised as `SubgraphError`, fail-fast).

## 6. Import Isolation Confirmation

- Template does **not** import the agenticstar-platform SDK (Level 0).
- Import targets: `framework/`, `shared/`, `langgraph` only (no `agents/base/`).
- Every framework facility named in this template exists in the installed SDK; nothing is referenced by name alone.
- `emit_trace_event` is imported from `shared.utils.audit_logger` (free function, positional args).

## 7. Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | **AgentBaseGraph** | Deterministic DocGeneration pipeline, not an autonomous ReAct loop |
| Composition pattern | Flat Cat-1 slots | Nested inner BaseGraph | **Nested (GraphNode → BaseGraph)** | 5-step domain workflow exceeds the 3-slot Cat-1 backbone; encapsulate in an inner graph |
| Classification engine | External LLM call | Deterministic rules + LLM seam | **Deterministic rules + governed prompt seam** | SDK v1.0.0rc1 ships no LLM client; rules are testable now, production wires the LLM at the marked seam |
| Structured state storage | Bare dict/list fields | JSON-string fields | **JSON strings (to_json/from_json)** | ADR-005 msgpack safety for checkpointed State |
