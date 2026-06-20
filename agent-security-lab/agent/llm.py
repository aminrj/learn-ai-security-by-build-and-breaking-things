"""Backend adapters behind a single `chat(messages, tools) -> AssistantTurn` interface.

Three concrete *real* backends — `LlamaCppBackend` (default), `AnthropicBackend`,
`OpenAIBackend` — each makes a real network call and RAISES if the endpoint is
unreachable. None of them ever fabricates a response.

`ScriptedBackend` is a deterministic test double used ONLY by the reproducible attack
suite (Phase 3+). It is not "real" and is never selected for production tasks. It
exists because attack cases require a deterministic, re-runnable outcome, which a real
(non-deterministic) model cannot provide. Crucially, it does not fake *data*: it reads
the real file/HTTP contents already present in the conversation (including any injected
instructions and real secrets) and decides actions from them — exactly as a compromised
real model would. The determinism lives in the decision policy, not in invented data.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

import httpx

from agent.types import AssistantTurn, Message, ToolCall, ToolSchema
from config.settings import Settings


class BackendError(RuntimeError):
    """Raised when a real backend cannot reach its endpoint. Never swallowed into a fake reply."""


class Backend(Protocol):
    name: str

    def chat(self, messages: list[Message], tools: list[ToolSchema]) -> AssistantTurn: ...


# --------------------------------------------------------------------------------------
# Message serialization helpers (OpenAI-compatible wire format)
# --------------------------------------------------------------------------------------

def _messages_to_openai(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "assistant" and m.tool_calls:
            out.append({
                "role": "assistant",
                "content": m.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in m.tool_calls
                ],
            })
        elif m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content or ""})
        else:
            out.append({"role": m.role, "content": m.content or ""})
    return out


def _parse_openai_tool_calls(message: dict[str, Any]) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for i, raw in enumerate(message.get("tool_calls") or []):
        fn = raw.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            # A malformed arguments blob from the model is itself an attack surface:
            # we surface the raw string rather than guessing.
            args = {"_raw_arguments": fn.get("arguments")}
        calls.append(ToolCall(id=raw.get("id") or f"call_{i}", name=fn.get("name", ""), arguments=args))
    return calls


# --------------------------------------------------------------------------------------
# Real backend: llama.cpp (OpenAI-compatible) — default
# --------------------------------------------------------------------------------------

class LlamaCppBackend:
    name = "llamacpp"

    def __init__(self, settings: Settings, timeout: float = 120.0) -> None:
        self.cfg = settings.llamacpp
        self.timeout = timeout

    def chat(self, messages: list[Message], tools: list[ToolSchema]) -> AssistantTurn:
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": _messages_to_openai(messages),
            "temperature": 0.0,
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
            payload["tool_choice"] = "auto"
        try:
            resp = httpx.post(
                f"{self.cfg.base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.cfg.api_key}"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise BackendError(f"llama.cpp endpoint unreachable at {self.cfg.base_url}: {exc}") from exc

        data = resp.json()
        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls = _parse_openai_tool_calls(msg)
        if not tool_calls and msg.get("content"):
            # Fallback JSON-protocol parsing for llama.cpp builds without native tool
            # calling. The parser is itself an attack surface (model text -> action).
            tool_calls = _parse_json_protocol(msg["content"])
        return AssistantTurn(
            text=msg.get("content"),
            tool_calls=tool_calls,
            stop_reason=choice.get("finish_reason"),
            raw=data,
        )


# Documented JSON tool-call protocol for backends without native function calling.
# The model is instructed (see loop.SYSTEM_PROMPT) to emit a fenced block:
#   ```tool_call
#   {"name": "read_file", "arguments": {"path": "notes.txt"}}
#   ```
# This strict parser is deliberately the only path from such text to an action.
import re  # noqa: E402

_TOOL_CALL_RE = re.compile(r"```tool_call\s*(\{.*?\})\s*```", re.DOTALL)


def _parse_json_protocol(text: str) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for i, match in enumerate(_TOOL_CALL_RE.finditer(text)):
        try:
            obj = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        name = obj.get("name")
        if not name:
            continue
        calls.append(ToolCall(id=f"jp_{i}", name=name, arguments=obj.get("arguments") or {}))
    return calls


# --------------------------------------------------------------------------------------
# Real backend: Anthropic
# --------------------------------------------------------------------------------------

class AnthropicBackend:
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.cfg = settings.anthropic
        if not self.cfg.api_key:
            raise BackendError("ANTHROPIC_API_KEY is not set; refusing to run without real credentials.")
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise BackendError("anthropic SDK not installed: pip install 'agent-security-lab[anthropic]'") from exc

    def chat(self, messages: list[Message], tools: list[ToolSchema]) -> AssistantTurn:
        import anthropic

        client = anthropic.Anthropic(api_key=self.cfg.api_key)
        system = "\n".join(m.content or "" for m in messages if m.role == "system")
        conv = _messages_to_anthropic([m for m in messages if m.role != "system"])
        try:
            resp = client.messages.create(
                model=self.cfg.model,
                max_tokens=2048,
                system=system or None,
                messages=conv,
                tools=[t.to_anthropic() for t in tools] if tools else [],
            )
        except Exception as exc:  # anthropic.APIError and friends
            raise BackendError(f"Anthropic API call failed: {exc}") from exc

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
        return AssistantTurn(
            text="\n".join(text_parts) or None,
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason,
            raw=resp.model_dump() if hasattr(resp, "model_dump") else {},
        )


def _messages_to_anthropic(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "assistant" and m.tool_calls:
            content: list[dict[str, Any]] = []
            if m.content:
                content.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                content.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
            out.append({"role": "assistant", "content": content})
        elif m.role == "tool":
            out.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content or ""}],
            })
        else:
            out.append({"role": m.role, "content": m.content or ""})
    return out


# --------------------------------------------------------------------------------------
# Real backend: OpenAI
# --------------------------------------------------------------------------------------

class OpenAIBackend:
    name = "openai"

    def __init__(self, settings: Settings) -> None:
        self.cfg = settings.openai
        if not self.cfg.api_key:
            raise BackendError("OPENAI_API_KEY is not set; refusing to run without real credentials.")
        try:
            import openai  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise BackendError("openai SDK not installed: pip install 'agent-security-lab[openai]'") from exc

    def chat(self, messages: list[Message], tools: list[ToolSchema]) -> AssistantTurn:
        import openai

        client = openai.OpenAI(api_key=self.cfg.api_key)
        try:
            resp = client.chat.completions.create(
                model=self.cfg.model,
                messages=_messages_to_openai(messages),
                tools=[t.to_openai() for t in tools] if tools else None,
                temperature=0.0,
            )
        except Exception as exc:
            raise BackendError(f"OpenAI API call failed: {exc}") from exc

        msg = resp.choices[0].message
        tool_calls = [
            ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments or "{}"))
            for tc in (msg.tool_calls or [])
        ]
        return AssistantTurn(
            text=msg.content,
            tool_calls=tool_calls,
            stop_reason=resp.choices[0].finish_reason,
            raw=resp.model_dump() if hasattr(resp, "model_dump") else {},
        )


# --------------------------------------------------------------------------------------
# Test double: ScriptedBackend (Phase 3+ only)
# --------------------------------------------------------------------------------------

# A step is a function of the full conversation so far -> the model's next turn.
# It receives real message content (real file bodies, real HTTP responses) and must
# derive its decision from them, the same way a compromised real model would.
ScriptStep = Callable[[list[Message]], AssistantTurn]


class ScriptedBackend:
    """Deterministic stand-in for a (vulnerable) model. NOT real; tests only.

    Construct with an ordered list of steps. On each `chat()` call the next step runs.
    A step inspects the conversation and returns an AssistantTurn (text and/or tool
    calls). When steps are exhausted, returns a terminal text turn so the loop ends.
    """

    name = "scripted"

    def __init__(self, steps: list[ScriptStep]) -> None:
        self._steps = list(steps)
        self._i = 0

    def chat(self, messages: list[Message], tools: list[ToolSchema]) -> AssistantTurn:
        if self._i >= len(self._steps):
            return AssistantTurn(text="(done)", tool_calls=[], stop_reason="stop")
        step = self._steps[self._i]
        self._i += 1
        return step(messages)


# --------------------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------------------

def get_backend(settings: Settings) -> Backend:
    """Select a real backend from config. `scripted` is rejected here on purpose —
    the attack suite constructs ScriptedBackend directly so it never leaks into prod."""
    backend = settings.backend
    if backend == "llamacpp":
        return LlamaCppBackend(settings)
    if backend == "anthropic":
        return AnthropicBackend(settings)
    if backend == "openai":
        return OpenAIBackend(settings)
    if backend == "scripted":
        raise BackendError(
            "The 'scripted' backend is a test double and cannot be selected via config. "
            "Construct ScriptedBackend directly inside a test."
        )
    raise BackendError(f"Unknown backend: {backend!r}")
