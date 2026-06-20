"""Run an ASGI app in a background thread on an ephemeral port.

Used by the test suite to stand up the real honeypot and docs server in-process, so the
whole attack suite runs self-contained (no Docker required) while still exercising real
HTTP. The same apps run under docker-compose for the full stack.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
import uvicorn


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class RunningServer:
    base_url: str
    port: int
    _server: uvicorn.Server
    _thread: threading.Thread

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def start_server(app, port: int | None = None, timeout: float = 10.0) -> RunningServer:
    port = port or find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if server.started:
            return RunningServer(base_url, port, server, thread)
        time.sleep(0.05)
    raise RuntimeError("server failed to start within timeout")


@contextlib.contextmanager
def serving(app, port: int | None = None) -> Iterator[RunningServer]:
    srv = start_server(app, port)
    try:
        yield srv
    finally:
        srv.stop()


def wait_reachable(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.suppress(httpx.HTTPError):
            httpx.get(url, timeout=1.0)
            return True
        time.sleep(0.05)
    return False
