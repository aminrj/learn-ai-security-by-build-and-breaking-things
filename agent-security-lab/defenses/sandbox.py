"""Egress filtering + shell confinement: the honeypot is *network-blocked*, not merely
discouraged. This represents the container/network policy that would deny the route at
runtime, enforced deterministically at the boundary regardless of model intent."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from agent.tools import ToolContext
from agent.types import ToolCall
from defenses import Block


def _netloc(url: str) -> str:
    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


@dataclass
class SandboxEgressDefense:
    name: str = "sandbox"
    forbidden_netlocs: tuple[str, ...] = ()

    def _forbidden(self, url: str) -> bool:
        nl = _netloc(url)
        return any(nl == f or nl.endswith(f) for f in self.forbidden_netlocs)

    def evaluate(self, call: ToolCall, ctx: ToolContext) -> Block | None:
        if call.name == "http_get":
            url = str(call.arguments.get("url", ""))
            if self._forbidden(url):
                return Block(self.name, f"egress to forbidden host '{_netloc(url)}' is network-blocked")
        if call.name == "run_shell":
            cmd = str(call.arguments.get("cmd", ""))
            for f in self.forbidden_netlocs:
                if f and f in cmd:
                    return Block(self.name, f"shell egress to forbidden host '{f}' is network-blocked")
        return None
