"""The tool-call boundary — the single place where untrusted model output becomes a
real-world action. This is "the ballgame."

It parses the model's requested tool call, validates arguments against the tool schema,
invokes the tool, and returns the result to the loop. It emits `tool_call_requested`
before execution and `tool_call_result` after, with full arguments and raw result.

In Phase 1 it enforces nothing beyond schema validity. The optional `enforcer` hook is
the *only* seam Phase 5 needs: every defense plugs in here, at the boundary, not in the
prompt. Keeping enforcement deterministic and centralized is the thesis of the lab.
"""

from __future__ import annotations

from typing import Any, Protocol

from agent.tools import Tool, ToolContext, ToolError, tool_map
from agent.trace import Tracer
from agent.types import ToolCall, ToolResult


class Enforcer(Protocol):
    """Phase 5 enforcement contract. Returns (allow, blocking_defense, reason).

    Implemented by defenses/enforcer.py. None in Phases 1-4 (no enforcement)."""

    def check(self, call: ToolCall, ctx: ToolContext) -> tuple[bool, str | None, str]: ...


def _validate_args(call: ToolCall, tool: Tool) -> str | None:
    """Minimal JSON-schema validation: required keys present and primitive types match.
    Returns an error string, or None if valid."""
    params = tool.schema.parameters
    props: dict[str, Any] = params.get("properties", {})
    required: list[str] = params.get("required", [])
    for key in required:
        if key not in call.arguments:
            return f"missing required argument {key!r}"
    type_map = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
                "object": dict, "array": list}
    for key, value in call.arguments.items():
        if key not in props:
            continue  # extra args are tolerated; the tool ignores them
        expected = props[key].get("type")
        py_type = type_map.get(expected)
        if py_type is not None and not isinstance(value, py_type):
            return f"argument {key!r} must be {expected}"
    return None


class Dispatcher:
    def __init__(self, tools: list[Tool], ctx: ToolContext, enforcer: Enforcer | None = None) -> None:
        self.tools = tool_map(tools)
        self.ctx = ctx
        self.enforcer = enforcer

    @property
    def tracer(self) -> Tracer:
        return self.ctx.tracer

    def dispatch(self, call: ToolCall) -> ToolResult:
        # 1. Trace the request BEFORE anything executes — this is the ingress of intent.
        self.tracer.tool_call_requested(tool=call.name, arguments=call.arguments, call_id=call.id)

        # 2. Resolve tool.
        tool = self.tools.get(call.name)
        if tool is None:
            return self._fail(call, f"unknown tool {call.name!r}")

        # 3. Schema validity (Phase 1's only gate).
        err = _validate_args(call, tool)
        if err is not None:
            return self._fail(call, f"schema validation failed: {err}")

        # 4. Phase 5 enforcement seam. Deterministic, at the boundary.
        if self.enforcer is not None:
            allow, defense, reason = self.enforcer.check(call, self.ctx)
            self.tracer.defense_decision(
                defense=defense or "enforcer", tool=call.name,
                decision="allow" if allow else "block", reason=reason, call_id=call.id,
            )
            if not allow:
                result = ToolResult(call.id, call.name, ok=False,
                                    content=f"blocked by defense: {reason}", blocked_by=defense)
                self.tracer.tool_call_result(tool=call.name, call_id=call.id, ok=False,
                                             result=result.content, blocked_by=defense)
                return result

        # 5. Execute the real tool.
        try:
            output = tool.run(self.ctx, call.arguments)
        except ToolError as exc:
            return self._fail(call, str(exc))
        except Exception as exc:  # unexpected — still record, never swallow silently
            return self._fail(call, f"unexpected tool error: {exc}")

        result = ToolResult(call.id, call.name, ok=True, content=output)
        self.tracer.tool_call_result(tool=call.name, call_id=call.id, ok=True, result=output)
        return result

    def _fail(self, call: ToolCall, message: str) -> ToolResult:
        self.tracer.tool_call_result(tool=call.name, call_id=call.id, ok=False, result=message,
                                     error=message)
        return ToolResult(call.id, call.name, ok=False, content=message, error=message)
