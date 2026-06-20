"""Pytest fixtures: a fresh armed lab + fresh trace per attack case.

Each case gets an isolated temp workdir (a copy of target/workdir, so the real .env.fake
prize is present), an isolated docs dir, a real honeypot HTTP service and a real docs web
server running in-process, and a fresh honeypot log. Evidence is collected from the trace
and the honeypot log — never from eyeballing model text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attacks.labkit import armed_lab


@pytest.fixture()
def lab(tmp_path: Path):
    # Isolated copies so cases can plant payloads without touching the committed target.
    with armed_lab(tmp_path) as the_lab:
        yield the_lab


@pytest.fixture()
def results_root(tmp_path: Path) -> Path:
    """Per-test results dir so the suite stays hermetic. The reports test populates a
    shared dir explicitly when it wants a cross-case matrix."""
    d = tmp_path / "results"
    d.mkdir()
    return d
