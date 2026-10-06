# Robotics Incident & Quality Gate Report Agent

AI agent for classifying robotics incidents and producing quality-gate reports, built with Agentic Star.

> **Category**: Cat 2 (multi-step domain workflow — classification plus report generation)
> **Industry**: Manufacturing
> **Template ID**: MFG-C2-058

## Overview

Turns a raw robot incident telemetry record into a reviewable quality-gate report.

Given a telemetry export for a single incident — robot and line identifiers, controller error
codes, joint states and sensor readings — the agent normalises it, classifies the incident as a
mechanical failure, software fault, safety boundary breach or calibration error, assigns a
severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) with the quality-gate action that severity
implies, drafts the incident report, and checks that report against a robotics-safety
completeness checklist before rendering it as Markdown.

Typical users are quality engineers and factory safety managers who currently write these reports
by hand from controller logs after every stoppage, and who need the severity call and the routing
decision to be consistent between shifts rather than dependent on who was on duty.

The classification, severity and drafting steps are **deterministic**: they are rules over the
structured telemetry, not model output, so the same telemetry always yields the same severity and
the same routing decision. That is a deliberate property for a document that feeds a safety
review — see `docs/02_design.md` for the rule tables and how to replace them with your own.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >= 3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent fails at graph
compile / start-up preflight rather than starting in a partially working state. This is
intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Invoking

The entry point requires a bearer credential. Set `INVOKE_AUTH_TOKEN` (external callers) and,
optionally, `STG_INTERNAL_RUNNER_TOKEN` (an internal runner) before start-up; with neither set
the endpoint refuses every request rather than admitting callers the pipeline's entry gate will
reject.

`input` is one incident's telemetry as a JSON object. Every field is optional and every field is
bounds-checked; unknown fields are ignored.

```bash
curl -X POST http://localhost:8000/invoke \
  -H "Authorization: Bearer $INVOKE_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "input": "{\"robot_id\":\"RBT-4471\",\"line_id\":\"LINE-A3\",\"error_codes\":[\"SAF-0012\"],\"sensor_readings\":{\"torque_nm\":88.2}}",
        "session_id": "incident-4471"
      }'
```

Free text is accepted too: an incident note that is not JSON is classified from its wording, and
if nothing in it matches a known signal the agent still returns the report, marked as needing
review, rather than returning nothing.

Identifiers that reach the rendered report (`robot_id`, `line_id`, `robot_model`, error codes)
are constrained to a conservative character set and truncated to fixed lengths, so caller text
cannot introduce headings, list items or line breaks into the report body. A value that does not
fit the contract is replaced with a placeholder and recorded in the report's data-quality
section; it is never echoed back.

## Configuration

`config/agent.yaml` is the registry manifest (identity, entry point, declared trust level).
`config/config.yaml` holds the runtime parameters the agent actually reads:

| Key | Meaning |
|---|---|
| `max_retry` | Backbone retry ceiling. |
| `timeout_s` | Request deadline enforced by the HTTP entry point. |
| `low_confidence_threshold` | Classifications below this confidence are escalated one severity step for human review. |
| `max_error_codes` / `max_free_text_chars` / `max_sensor_readings` | Structural caps on one caller record. |

Those values are loaded at start-up and passed into the graph, which seeds them into the domain
workflow — changing `low_confidence_threshold` changes the severity a weakly-classified incident
receives. `tests/integration/test_runtime_config_e2e.py` pins that end to end.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/` for the design and the test specification.

## Customising

1. Adjust `config/config.yaml` for your own environment and policies.
2. Replace the classification rule table, severity baselines and corrective-action playbook in
   `src/nodes/` with the ones your plant actually uses — they are plain data structures.
3. Replace the completeness checklist in `src/nodes/compliance_validate_node.py` with the
   checklist your own safety standard requires.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
