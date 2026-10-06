"""AgentCore Platform v1.0"""

# MFG-C2-058 — Standalone HTTP entry point. Adapters only, no domain logic.
#
# Four things this adapter must do before the graph is invoked, each of which
# was missing and each of which produced a failure the caller could not read:
#
#   1. Establish the caller's trust level from a bearer credential. The
#      pipeline's entry gate requires VERIFIED_EXTERNAL. An adapter that never
#      sets request.state.trust_level leaves every caller at ANONYMOUS, so the
#      entry gate refuses the request at the first node and the response is
#      status=error with a null output and nothing explaining why. Measured on
#      this template before the change: every HTTP request failed that way.
#
#   2. Load config/config.yaml and hand it to the graph, so the declared
#      runtime parameters are the ones in force rather than framework defaults.
#      Constructing the graph bare is how a declared value becomes decorative.
#
#   3. Reduce the caller's context to the declared contract and screen it for
#      credential shapes. The framework's output check scans every value of
#      every node result and the FIRST node returns the invocation context
#      verbatim in its own result — so a credential-shaped string anywhere in
#      input_context fails the run before any template code executes. Declaring
#      a narrow contract is not immunity: validators IGNORE undeclared keys, and
#      an ignored key is still in the mapping handed to invoke(). Only dropping
#      them keeps them out.
#
#   4. Enforce the declared request deadline.

import asyncio
import hmac
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from framework.security.credential_detector import detect_credentials_in_value
from shared.secrets import factory as secrets_factory
from src.graph.graph import MfgC2058Agent
from src.services.service import (
    CALLER_CONTEXT_FIELDS,
    MAX_INPUT_CHARS,
    MIN_INPUT_CHARS,
)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
_SAFE_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_DEFAULT_TIMEOUT_S = 30.0

AGENT_NAME = "ManufacturingRoboticsIncidentClassificationQualityGateReportAgent"


def load_runtime_config(path: Path = _CONFIG_PATH) -> Dict[str, Any]:
    """Read the declared runtime parameters. Missing file -> framework defaults."""
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


RUNTIME_CONFIG: Dict[str, Any] = load_runtime_config()

app = FastAPI(title="MFG-C2-058 Robotics Incident Classification & Quality Gate Report")
agent = MfgC2058Agent(config=RUNTIME_CONFIG)
agent.compile()
agent.provision_secrets(secrets_factory(namespace="mfg", agent_name=AGENT_NAME))


class InvokeRequest(BaseModel):
    """One incident record.

    `input` is the telemetry export, normally a JSON object serialised as a
    string; free-text incident notes are accepted too. The bounds are the
    domain contract's, so the edge and the ingest node cannot disagree.
    """

    input: str = Field(min_length=MIN_INPUT_CHARS, max_length=MAX_INPUT_CHARS)
    session_id: str = Field(default="", max_length=128)
    input_context: Optional[Dict[str, Any]] = None


def _request_timeout_s() -> float:
    """The declared request deadline, falling back only when none is declared."""
    declared = RUNTIME_CONFIG.get("timeout_s", _DEFAULT_TIMEOUT_S)
    try:
        value = float(declared)
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT_S
    return value if value > 0 else _DEFAULT_TIMEOUT_S


def resolve_trust_level(request: Request) -> TrustLevel:
    """Map the presented bearer credential to a trust level, or refuse.

    There is no anonymous path: the entry gate requires VERIFIED_EXTERNAL, so
    admitting an unauthenticated caller at ANONYMOUS only defers the refusal to
    a place where the caller cannot see why it happened.

    Both credentials are accepted. The manifest declares VERIFIED_EXTERNAL, so
    the STG evidence harness presents INVOKE_AUTH_TOKEN — but a deployment that
    raises the declared entry contract to INTERNAL would then present
    STG_INTERNAL_RUNNER_TOKEN instead, and an adapter that reads only one of
    them turns that change into an unexplained deploy failure.
    """
    external = os.environ.get("INVOKE_AUTH_TOKEN", "")
    internal = os.environ.get("STG_INTERNAL_RUNNER_TOKEN", "")
    if not external and not internal:
        raise HTTPException(
            status_code=503,
            detail="Invocation auth is not configured; set INVOKE_AUTH_TOKEN.",
        )

    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(status_code=401, detail="Bearer credential required.")
    if internal and hmac.compare_digest(presented, internal):
        return TrustLevel.INTERNAL
    if external and hmac.compare_digest(presented, external):
        return TrustLevel.VERIFIED_EXTERNAL
    raise HTTPException(status_code=401, detail="Bearer credential rejected.")


def _field_label(name: Any, position: int) -> str:
    """Name a context field only when the name is itself safe to echo.

    Field names are caller data too. A name that is not a plain identifier, or
    that trips a credential pattern itself, is referred to by position instead.
    """
    if isinstance(name, str) and _SAFE_FIELD_NAME.match(name) and not detect_credentials_in_value(name):
        return f"input_context.{name}"
    return f"input_context field #{position}"


def prepare_input_context(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop undeclared keys, then refuse any declared value carrying a credential.

    Dropping rather than ignoring is the point: an ignored key is still in the
    mapping handed to invoke(), still reaches the first node's result, and still
    reaches the framework's output check, which raises on it — inside the first
    node, before any of this template's code runs.

    Fields are screened one at a time so a refusal can name the field. Scanning
    per field is exactly equivalent to scanning the whole mapping, because the
    framework's scan of a mapping is defined as the union over its values — so
    naming the field neither widens nor narrows what is refused. That identity
    is pinned as a property test in tests/unit/test_server_adapter.py.

    400, not 422: 422 belongs to request-schema validation and returns a
    different body shape, so reusing it makes client handling ambiguous.
    """
    if not raw:
        return {}
    prepared: Dict[str, Any] = {}
    for position, key in enumerate(sorted(raw, key=str), start=1):
        if key not in CALLER_CONTEXT_FIELDS:
            continue
        value = raw[key]
        if detect_credentials_in_value(value):
            raise HTTPException(
                status_code=400,
                detail=f"Credential-shaped value refused in {_field_label(key, position)}.",
            )
        prepared[key] = value
    return prepared


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Any:
    trust_level = resolve_trust_level(request)
    input_context = prepare_input_context(req.input_context)
    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust_level,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(agent.invoke, req.input, ctx=ctx, input_context=input_context),
                timeout=_request_timeout_s(),
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail="Report generation exceeded the configured deadline.",
            )


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "agent": "MFG-C2-058"}
