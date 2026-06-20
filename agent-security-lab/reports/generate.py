"""Generate the cross-framework report and the attacks × defenses matrix from results/.

Two artifacts (written to reports/out/):
  - owasp_atlas_crossref.md : every case mapped to OWASP LLM Top 10 + MITRE ATLAS, with
    structured notes on where those frameworks are thin for agentic/MCP scenarios.
  - defense_matrix.md       : attacks (rows) × defenses (columns), each cell blocked/open,
    with the controlling evidence (trace_id) linked.

Usage:
    asl-report                 # read existing results/ (matrix.json + outcome.json)
    asl-report --run           # run the full matrix first, then generate
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.trace import default_results_dir

# Where each framework is thin for agentic / MCP scenarios — the seed of a write-up.
FRAMEWORK_GAP_NOTES = {
    "tool_description": (
        "OWASP LLM01 covers prompt injection generally but does not name *tool-description* "
        "poisoning as a distinct vector; MITRE ATLAS has no technique specific to MCP tool "
        "metadata as an injection surface. Both treat the description as trusted config."
    ),
    "mcp_chain": (
        "Neither framework models agent-to-agent (A2A) trust transfer: a compromised upstream "
        "agent laundering an injection into a downstream agent's context. ATLAS exfiltration "
        "techniques assume a single model; the cross-agent boundary is unmodeled."
    ),
    "indirect_file": (
        "Indirect injection via ingested files is acknowledged (LLM01) but the frameworks give "
        "little guidance on *where* the deterministic control belongs (ingestion vs tool boundary)."
    ),
    "indirect_web": (
        "SSRF-via-injection blends LLM01 with classic SSRF; OWASP LLM Top 10 lacks an explicit "
        "SSRF entry, so the network-egress control lives outside its taxonomy."
    ),
    "direct": (
        "Direct injection is the best-covered case; even so, the frameworks describe the threat, "
        "not the deterministic boundary control that actually stops it."
    ),
}


def load_matrix(results_dir: Path) -> dict | None:
    mpath = results_dir / "matrix.json"
    if mpath.exists():
        return json.loads(mpath.read_text())
    return None


def load_outcomes(results_dir: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted(results_dir.glob("*/outcome.json")):
        try:
            out.append(json.loads(p.read_text()))
        except json.JSONDecodeError:
            continue
    return out


def render_crossref(matrix: dict | None, outcomes: list[dict]) -> str:
    lines = ["# OWASP LLM Top 10 & MITRE ATLAS Cross-Reference", ""]
    lines += ["| Case | Vector | Objective | OWASP LLM | MITRE ATLAS |",
              "|------|--------|-----------|-----------|-------------|"]

    rows: dict[str, dict] = {}
    if matrix:
        for cid, c in matrix["cases"].items():
            rows[cid] = {"vector": c["vector"], "objective": c["objective"],
                         "owasp_llm": c["owasp_llm"], "mitre_atlas": c["mitre_atlas"]}
    for o in outcomes:  # fill any cases only present as raw outcomes
        rows.setdefault(o["case_id"], {"vector": o.get("vector", ""), "objective": o.get("objective", ""),
                                       "owasp_llm": o.get("owasp_llm", ""),
                                       "mitre_atlas": o.get("mitre_atlas", "")})

    for cid in sorted(rows):
        r = rows[cid]
        lines.append(f"| {cid} | {r['vector']} | {r['objective']} | {r['owasp_llm']} | {r['mitre_atlas']} |")

    lines += ["", "## Where the frameworks are thin (gap notes)", ""]
    seen_vectors = {r["vector"] for r in rows.values()}
    for vector in sorted(seen_vectors):
        note = FRAMEWORK_GAP_NOTES.get(vector)
        if note:
            lines += [f"### `{vector}`", "", note, ""]
    return "\n".join(lines) + "\n"


def render_matrix(matrix: dict) -> str:
    defenses = matrix["defenses"]
    lines = ["# Attack × Defense Matrix", "",
             "Legend: ✅ = blocked by this defense · ❌ = attack still succeeded.",
             "Each cell links its controlling evidence (trace id).", ""]
    header = "| Case | " + " | ".join(defenses) + " |"
    sep = "|------|" + "|".join(["------"] * len(defenses)) + "|"
    lines += [header, sep]
    for cid in sorted(matrix["cases"]):
        res = matrix["cases"][cid]["results"]
        cells = []
        for d in defenses:
            cell = res[d]
            mark = "✅" if cell["blocked"] else "❌"
            cells.append(f"{mark} `{cell['trace_id'][:8]}`")
        lines.append(f"| {cid} | " + " | ".join(cells) + " |")

    lines += ["", "## Reading the matrix", "",
              "- The `none` column is the undefended baseline (every attack succeeds).",
              "- `prompt_hardening` is a prompt-level mitigation; it blocks nothing here — "
              "a compliant model or a strong injection ignores the policy text.",
              "- `allowlist`, `authz`, `sandbox`, `hitl` are deterministic boundary controls.",
              "- `enforcer_all` composes the boundary controls and stops every attack.", ""]
    return "\n".join(lines) + "\n"


def generate(results_dir: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    matrix = load_matrix(results_dir)
    outcomes = load_outcomes(results_dir)

    written: list[Path] = []
    crossref = out_dir / "owasp_atlas_crossref.md"
    crossref.write_text(render_crossref(matrix, outcomes))
    written.append(crossref)

    if matrix:
        mfile = out_dir / "defense_matrix.md"
        mfile.write_text(render_matrix(matrix))
        written.append(mfile)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asl-report")
    parser.add_argument("--results-dir", default=str(default_results_dir()))
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "out"))
    parser.add_argument("--run", action="store_true",
                        help="Run the full attack×defense matrix before generating.")
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    if args.run:
        import tempfile

        from defenses.evaluation import run_matrix
        tmp = Path(tempfile.mkdtemp(prefix="asl-matrix-"))
        counter = {"n": 0}

        def new_dir() -> Path:
            counter["n"] += 1
            d = tmp / f"cell{counter['n']}"
            d.mkdir(parents=True)
            return d

        run_matrix(new_dir, results_root=results_dir)

    written = generate(results_dir, Path(args.out))
    for p in written:
        print(f"wrote {p}")
    if not written:
        print("no results found; run with --run or execute the suite first")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
