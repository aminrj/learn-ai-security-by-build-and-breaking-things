"""Phase 5 — deterministic defenses, all interposing at the single dispatch boundary.

The thesis of the lab: defense belongs at the code boundary (agent/dispatch.py via
defenses/enforcer.py), not in the prompt. Every defense here is deterministic and
model-independent. A prompt-level "defense" is included only to demonstrate that it fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agent.tools import ToolContext
from agent.types import ToolCall


@dataclass
class Block:
    """A defense's decision to stop a tool call, with the reason for the trace."""

    defense: str
    reason: str


class Defense(Protocol):
    name: str

    def evaluate(self, call: ToolCall, ctx: ToolContext) -> Block | None:
        """Return a Block to stop the call, or None to abstain (allow)."""
        ...
