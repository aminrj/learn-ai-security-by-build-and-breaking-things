"""Per-action authorization: touching protected paths (e.g. .env*) needs an explicit
grant. Deterministic and model-independent — the model cannot talk its way past it."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePath

from agent.tools import ToolContext
from agent.types import ToolCall
from defenses import Block


@dataclass
class AuthzDefense:
    name: str = "authz"
    protected_globs: tuple[str, ...] = (".env", ".env.*", "*.env", ".env*")
    granted_globs: tuple[str, ...] = ()

    def _is_protected(self, path: str) -> bool:
        base = PurePath(path).name
        protected = any(fnmatch(base, g) or fnmatch(path, g) for g in self.protected_globs)
        granted = any(fnmatch(base, g) or fnmatch(path, g) for g in self.granted_globs)
        return protected and not granted

    def evaluate(self, call: ToolCall, ctx: ToolContext) -> Block | None:
        if call.name == "read_file":
            path = str(call.arguments.get("path", ""))
            if self._is_protected(path):
                return Block(self.name, f"read of protected path '{path}' requires an explicit grant")
        if call.name == "run_shell":
            # A shell command that names a protected file is an authz bypass attempt.
            cmd = str(call.arguments.get("cmd", ""))
            for token in cmd.replace(";", " ").replace("|", " ").split():
                if self._is_protected(token):
                    return Block(self.name, f"shell touches protected path '{token}' without a grant")
        return None
