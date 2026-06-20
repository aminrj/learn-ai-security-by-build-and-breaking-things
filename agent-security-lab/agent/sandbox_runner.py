"""Execution backends for `run_shell`. The agent loop never calls these directly —
they go through `agent/tools.py` -> `agent/dispatch.py` so Phase 5 can interpose.

`DockerSandboxRunner` is the production path: commands run inside the sandbox container
defined in docker-compose, never on the host. `SubprocessSandboxRunner` is a weaker,
workdir-confined local runner used by the test suite when Docker is unavailable; it is
acceptable *only* because the whole lab is itself contained and the commands are the
object of study. Both are real command execution — nothing is faked.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class ShellResult:
    returncode: int
    stdout: str
    stderr: str

    def render(self) -> str:
        out = f"exit={self.returncode}\n"
        if self.stdout:
            out += f"stdout:\n{self.stdout}\n"
        if self.stderr:
            out += f"stderr:\n{self.stderr}\n"
        return out.strip()


class SandboxRunner(Protocol):
    location: str

    def run(self, cmd: str, *, cwd: Path, timeout: float = 30.0) -> ShellResult: ...


class SubprocessSandboxRunner:
    """Runs the command in a subprocess with cwd pinned to the workdir. Local-dev only."""

    location = "subprocess"

    def run(self, cmd: str, *, cwd: Path, timeout: float = 30.0) -> ShellResult:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return ShellResult(proc.returncode, proc.stdout, proc.stderr)


class DockerSandboxRunner:
    """Runs the command inside the sandbox container via `docker exec`. Production path."""

    location = "docker"

    def __init__(self, container: str = "asl-sandbox", workdir_in_container: str = "/work") -> None:
        self.container = container
        self.workdir_in_container = workdir_in_container

    def run(self, cmd: str, *, cwd: Path, timeout: float = 30.0) -> ShellResult:
        if shutil.which("docker") is None:
            raise RuntimeError("docker not available; cannot run sandboxed shell on host.")
        proc = subprocess.run(
            ["docker", "exec", "-w", self.workdir_in_container, self.container, "sh", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return ShellResult(proc.returncode, proc.stdout, proc.stderr)


def default_sandbox() -> SandboxRunner:
    """Local default. Compose-based runs override this with DockerSandboxRunner."""
    return SubprocessSandboxRunner()
