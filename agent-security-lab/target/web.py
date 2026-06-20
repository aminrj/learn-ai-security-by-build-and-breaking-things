"""Local web server serving target/docs/ — the indirect-injection (web) vector.

Benign in Phase 2. Phase 3 fixtures serve poisoned pages from a temp directory using
this same app so the agent fetches attacker-controlled HTML via http_get.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

DEFAULT_DOCS = Path(__file__).resolve().parent / "docs"


def create_app(docs_dir: Path = DEFAULT_DOCS) -> FastAPI:
    app = FastAPI(title="ASL Docs", docs_url=None, redoc_url=None)
    docs_dir = Path(docs_dir)
    docs_dir.mkdir(parents=True, exist_ok=True)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        items = "".join(f'<li><a href="/{p.name}">{p.name}</a></li>'
                        for p in sorted(docs_dir.iterdir()) if p.is_file())
        return f"<h1>Docs</h1><ul>{items}</ul>"

    @app.get("/health", response_class=PlainTextResponse)
    def health() -> str:
        return "ok"

    app.mount("/", StaticFiles(directory=str(docs_dir), html=True), name="docs")
    return app


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    parser = argparse.ArgumentParser(prog="asl-docs")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--docs", default=str(DEFAULT_DOCS))
    args = parser.parse_args(argv)
    uvicorn.run(create_app(Path(args.docs)), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
