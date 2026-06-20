"""Shared data types for the agent loop, kept dependency-free to avoid import cycles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolCall:
    """A single tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolSchema:
    """The model-facing description of a tool. The `description` is attacker-controllable
    in Phase 4 (MCP tool poisoning) — that is why it is a first-class field here."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the arguments

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


@dataclass
class Message:
    """One conversation message. `tool_calls` is set on assistant turns that call tools;
    `tool_call_id`/`name` are set on tool-result messages."""

    role: Role
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [tc.__dict__ for tc in self.tool_calls],
            "tool_call_id": self.tool_call_id,
            "name": self.name,
        }


@dataclass
class AssistantTurn:
    """The model's reply for one turn: free text and/or zero+ tool calls."""

    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """The outcome of dispatching one tool call."""

    tool_call_id: str
    name: str
    ok: bool
    content: str
    # If a defense (Phase 5) blocked the call, this records which one and why.
    blocked_by: str | None = None
    error: str | None = None


@dataclass
class Transcript:
    """The full record of a run, sufficient to reconstruct it alongside the JSONL trace."""

    trace_id: str
    task: str
    messages: list[Message] = field(default_factory=list)
    turns_used: int = 0
    stop_reason: str = "unknown"
