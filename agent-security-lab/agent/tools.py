"""The three real tools the agent can call: read_file, run_shell, http_get.

Each tool does real I/O. Each carries a JSON schema (name, description, params); the
*descriptions* matter in Phase 4, where MCP poisons them. read_file and http_get emit
`untrusted_ingress` because the content they return is attacker-controllable and is
about to enter the model context.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from agent.sandbox_runner import SandboxRunner, default_sandbox
from agent.trace import Tracer
from agent.types import ToolSchema


class ToolError(Exception):
    """Raised by a tool on a real failure (missing file, bad path, network error)."""


@dataclass
class ToolContext:
    """Runtime wiring handed to every tool invocation."""

    workdir: Path
    tracer: Tracer
    sandbox: SandboxRunner = field(default_factory=default_sandbox)
    http_timeout: float = 15.0
    max_content_chars: int = 20_000


@dataclass
class Tool:
    schema: ToolSchema
    run: Callable[[ToolContext, dict[str, Any]], str]

    @property
    def name(self) -> str:
        return self.schema.name


# --------------------------------------------------------------------------------------
# read_file
# --------------------------------------------------------------------------------------

def _resolve_within(workdir: Path, path: str) -> Path:
    """Resolve `path` against the workdir and refuse to escape it. This is a safety
    boundary (don't read the host fs), NOT an attack defense: the prize .env.fake lives
    inside the workdir and is legitimately readable here until Phase 5 authz restricts it."""
    candidate = (workdir / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    workdir_resolved = workdir.resolve()
    if workdir_resolved not in candidate.parents and candidate != workdir_resolved:
        raise ToolError(f"path {path!r} escapes the workdir sandbox")
    return candidate


def _read_file(ctx: ToolContext, args: dict[str, Any]) -> str:
    path = args.get("path")
    if not isinstance(path, str):
        raise ToolError("read_file requires a string 'path' argument")
    target = _resolve_within(ctx.workdir, path)
    if not target.exists() or not target.is_file():
        raise ToolError(f"no such file: {path}")
    body = target.read_text(encoding="utf-8", errors="replace")[: ctx.max_content_chars]
    # A file body is attacker-controllable content crossing into the context.
    ctx.tracer.untrusted_ingress(source="file", origin=str(path), content=body, via_tool="read_file")
    return body


READ_FILE = Tool(
    schema=ToolSchema(
        name="read_file",
        description="Read a UTF-8 text file from the working directory and return its contents.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path relative to the workdir."}},
            "required": ["path"],
        },
    ),
    run=_read_file,
)


# --------------------------------------------------------------------------------------
# run_shell
# --------------------------------------------------------------------------------------

def _run_shell(ctx: ToolContext, args: dict[str, Any]) -> str:
    cmd = args.get("cmd")
    if not isinstance(cmd, str):
        raise ToolError("run_shell requires a string 'cmd' argument")
    result = ctx.sandbox.run(cmd, cwd=ctx.workdir)
    return result.render()


RUN_SHELL = Tool(
    schema=ToolSchema(
        name="run_shell",
        description="Execute a shell command inside the sandbox and return stdout/stderr.",
        parameters={
            "type": "object",
            "properties": {"cmd": {"type": "string", "description": "The shell command to run."}},
            "required": ["cmd"],
        },
    ),
    run=_run_shell,
)


# --------------------------------------------------------------------------------------
# http_get
# --------------------------------------------------------------------------------------

def _http_get(ctx: ToolContext, args: dict[str, Any]) -> str:
    url = args.get("url")
    if not isinstance(url, str):
        raise ToolError("http_get requires a string 'url' argument")
    try:
        resp = httpx.get(url, timeout=ctx.http_timeout, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise ToolError(f"http_get failed for {url}: {exc}") from exc
    body = resp.text[: ctx.max_content_chars]
    # An HTTP response body is attacker-controllable content crossing into the context.
    ctx.tracer.untrusted_ingress(source="http_response", origin=url, content=body, via_tool="http_get")
    return f"status={resp.status_code}\n{body}"


HTTP_GET = Tool(
    schema=ToolSchema(
        name="http_get",
        description="Perform an HTTP GET request to a URL and return the status and body.",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "The absolute URL to fetch."}},
            "required": ["url"],
        },
    ),
    run=_http_get,
)


# --------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------

def default_tools() -> list[Tool]:
    return [READ_FILE, RUN_SHELL, HTTP_GET]


def tool_map(tools: list[Tool]) -> dict[str, Tool]:
    return {t.name: t for t in tools}
