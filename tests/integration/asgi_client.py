# MFG-C2-058 — A minimal synchronous client over the real ASGI app.
#
# Deliberately not starlette.testclient: importing it emits a deprecation
# warning about its httpx usage, and the suite is required to run warning-free.
# httpx itself is a hard dependency of the framework wheel, so ASGITransport is
# available wherever the agent is, and it exercises the same ASGI interface a
# real server would call.

from __future__ import annotations

import asyncio
from typing import Any

import httpx

_BASE_URL = "http://testserver"


class AsgiClient:
    """Drive an ASGI app with ordinary blocking calls."""

    def __init__(self, app: Any) -> None:
        self._app = app

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self._request("POST", path, **kwargs)

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        async def _go() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._app)
            async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(_go())
