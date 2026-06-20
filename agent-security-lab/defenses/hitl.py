"""Human-in-the-loop confirmation for flagged tool calls. In test mode an auto-responder
simulates approve/deny so the suite stays reproducible; in production the responder would
prompt a human."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from agent.tools import ToolContext
from agent.types import ToolCall
from defenses import Block

Responder = Callable[[ToolCall], bool]  # returns True to approve


def auto_deny(_call: ToolCall) -> bool:
    return False


def auto_approve(_call: ToolCall) -> bool:
    return True


@dataclass
class HitlDefense:
    name: str = "hitl"
    flagged: frozenset[str] = frozenset({"http_get", "run_shell"})
    responder: Responder = field(default=auto_deny)

    def evaluate(self, call: ToolCall, ctx: ToolContext) -> Block | None:
        if call.name in self.flagged and not self.responder(call):
            return Block(self.name, f"human-in-the-loop denied '{call.name}'")
        return None
