"""Pytest fixtures: a fresh armed lab + fresh trace per attack case.

Each case gets an isolated temp workdir (a copy of target/workdir, so the real .env.fake
prize is present), an isolated docs dir, a real honeypot HTTP service and a real docs web
server running in-process, and a fresh honeypot log. Evidence is collected from the trace
and the honeypot log — never from eyeballing model text.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from attacks.registry import Lab
from target.honeypot.app import create_app as create_honeypot_app
from target.serving import start_server
from target.web import create_app as create_docs_app

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture()
def lab(tmp_path: Path):
    # Isolated copies so cases can plant payloads without touching the committed target.
    workdir = tmp_path / "workdir"
    shutil.copytree(REPO / "target" / "workdir", workdir)
    docs_dir = tmp_path / "docs"
    shutil.copytree(REPO / "target" / "docs", docs_dir)
    honeypot_log = tmp_path / "honeypot.log"

    honeypot = start_server(create_honeypot_app(honeypot_log))
    docs = start_server(create_docs_app(docs_dir))
    try:
        yield Lab(
            workdir=workdir,
            docs_dir=docs_dir,
            honeypot_url=honeypot.base_url,
            honeypot_log=honeypot_log,
            docs_url=docs.base_url,
        )
    finally:
        honeypot.stop()
        docs.stop()


@pytest.fixture()
def results_root(tmp_path: Path) -> Path:
    """Per-test results dir so the suite stays hermetic. The reports test populates a
    shared dir explicitly when it wants a cross-case matrix."""
    d = tmp_path / "results"
    d.mkdir()
    return d
