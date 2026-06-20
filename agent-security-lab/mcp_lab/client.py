"""Sync bridge from our hand-written (synchronous) agent loop to an async MCP session.

The agent connects to the MCP server as a real client over the SDK's in-memory transport
(real protocol, no OS pipes needed — ideal for reproducible tests). MCP tools are adapted
into our `Tool` objects and dispatched through the SAME `agent/dispatch.py` boundary, so
they are instrumented exactly like local tools.

Loading a tool fires `untrusted_ingress(source="tool_description")`: a description is
attacker-controllable text crossing into the model context — the Phase 4 thesis.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from mcp.server.lowlevel import Server
from mcp.shared.memory import create_connected_server_and_client_session

from agent.tools import Tool, ToolContext
from agent.trace import Tracer
from agent.types import ToolSchema


class McpClient:
    """Runs an asyncio loop in a background thread and keeps one MCP session alive."""

    def __init__(self, server: Server, call_timeout: float = 30.0) -> None:
        self._server = server
        self._timeout = call_timeout
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._session: Any = None
        self._ready = threading.Event()
        self._stop_async: asyncio.Event | None = None
        self._error: BaseException | None = None

    def __enter__(self) -> McpClient:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=15):
            raise RuntimeError(f"MCP client failed to start: {self._error}")
        if self._error is not None:
            raise RuntimeError(f"MCP client error: {self._error}")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._loop and self._stop_async:
            self._loop.call_soon_threadsafe(self._stop_async.set)
        if self._thread:
            self._thread.join(timeout=10)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except BaseException as exc:  # surface startup failures to __enter__
            self._error = exc
            self._ready.set()
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        self._stop_async = asyncio.Event()
        async with create_connected_server_and_client_session(self._server) as session:
            self._session = session
            self._ready.set()
            await self._stop_async.wait()

    def _submit(self, coro) -> Any:
        assert self._loop is not None
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=self._timeout)

    # ---- sync MCP operations -------------------------------------------------------
    def list_tools(self) -> list[ToolSchema]:
        result = self._submit(self._session.list_tools())
        return [
            ToolSchema(name=t.name, description=t.description or "", parameters=t.inputSchema or {})
            for t in result.tools
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        result = self._submit(self._session.call_tool(name, arguments))
        parts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
        return "\n".join(parts)


def load_mcp_tools(client: McpClient, tracer: Tracer, *, prefix: str = "mcp.") -> list[Tool]:
    """List MCP tools, emit untrusted_ingress per description, and adapt them to Tool."""
    tools: list[Tool] = []
    for schema in client.list_tools():
        # The description is attacker-controllable text entering the model context.
        tracer.untrusted_ingress(source="tool_description", origin=schema.name,
                                 content=schema.description, via_tool=schema.name)

        def _run(ctx: ToolContext, args: dict[str, Any], _name: str = schema.name) -> str:
            return client.call_tool(_name, args)

        adapted = ToolSchema(name=f"{prefix}{schema.name}", description=schema.description,
                             parameters=schema.parameters)
        tools.append(Tool(schema=adapted, run=_run))
    return tools
