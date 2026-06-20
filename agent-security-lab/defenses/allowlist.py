"""Tool allowlisting per task: only the tools a task legitimately needs may dispatch."""

from __future__ import annotations

from dataclasses import dataclass

from agent.tools import ToolContext
from agent.types import ToolCall
from defenses import Block


@dataclass
class AllowlistDefense:
    name: str = "allowlist"
    allowed: frozenset[str] = frozenset()

    def evaluate(self, call: ToolCall, ctx: ToolContext) -> Block | None:
        if self.allowed and call.name not in self.allowed:
            return Block(self.name,
                         f"tool '{call.name}' not in task allowlist {sorted(self.allowed)}")
        return None
