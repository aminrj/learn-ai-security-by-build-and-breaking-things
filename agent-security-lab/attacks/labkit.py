"""Reusable construction of the armed lab (isolated workdir + docs + honeypot + docs web
server), shared by the pytest `lab` fixture and the Phase 5 defense matrix, which needs a
fresh, uncontaminated lab per (case × defense) run."""

from __future__ import annotations

import contextlib
import shutil
from collections.abc import Iterator
from pathlib import Path

from attacks.registry import Lab
from target.honeypot.app import create_app as create_honeypot_app
from target.serving import start_server
from target.web import create_app as create_docs_app

REPO = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def armed_lab(base_dir: Path) -> Iterator[Lab]:
    """Build an isolated lab rooted at base_dir and tear down its servers on exit."""
    workdir = base_dir / "workdir"
    shutil.copytree(REPO / "target" / "workdir", workdir)
    docs_dir = base_dir / "docs"
    shutil.copytree(REPO / "target" / "docs", docs_dir)
    honeypot_log = base_dir / "honeypot.log"

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
