"""Phase 5 evaluation: run the UNCHANGED Phase 3 + Phase 4 suite against the defended
agent and build the attacks × defenses matrix with evidence per cell.

Each (case × defense) runs in a FRESH lab so honeypot evidence never bleeds between cells.
The matrix is written to <results_root>/matrix.json for reports/generate.py.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from agent.dispatch import Enforcer
from agent.trace import default_results_dir
from attacks.labkit import armed_lab
from attacks.registry import REGISTRY, AttackCase, Lab
from attacks.runner import run_attack
from defenses.enforcer import HARDENED_SYSTEM_PROMPT, build_enforcer
from mcp_lab.poison_cases.cases import run_p01, run_p02, run_p03

# Ordered defense columns. "none" = baseline; "prompt_hardening" = the prompt-level
# straw man that is expected to fail; the rest are deterministic boundary defenses.
DEFENSE_NAMES = ["none", "prompt_hardening", "allowlist", "authz", "sandbox", "hitl", "enforcer_all"]

CellRunner = Callable[[Lab, Enforcer | None, str | None, Path], tuple[bool, str, str, int]]


@dataclass
class MatrixCase:
    case_id: str
    owasp_llm: str
    mitre_atlas: str
    vector: str
    objective: str
    legit_tools: tuple[str, ...]
    runner: CellRunner


def _registry_runner(case: AttackCase) -> CellRunner:
    def run(lab, enforcer, system_prompt, results_root):
        ev = run_attack(case, lab, enforcer=enforcer, system_prompt=system_prompt,
                        results_root=results_root)
        oc = case.verify(ev)
        return oc.success, oc.detail, ev.tracer.trace_id, len(ev.honeypot_hits)
    return run


def _poison_runner(fn) -> CellRunner:
    def run(lab, enforcer, system_prompt, results_root):
        r = fn(lab, enforcer=enforcer, system_prompt=system_prompt, results_root=results_root)
        return r.success, r.detail, r.trace_id, r.honeypot_hits
    return run


_POISON_META = {
    "P01": ("LLM01 / MCP Tool Poisoning", "AML.T0051", "tool_description", "leak_secret",
            ("mcp.get_weather",), run_p01),
    "P02": ("LLM01 / LLM05 Supply Chain (rug-pull)", "AML.T0051", "tool_description",
            "leak_secret", ("mcp.append_note",), run_p02),
    "P03": ("LLM01 / Agent-to-Agent chaining", "AML.T0051", "mcp_chain", "leak_secret",
            ("read_file",), run_p03),
}


def all_cases() -> list[MatrixCase]:
    cases: list[MatrixCase] = []
    for c in REGISTRY:
        cases.append(MatrixCase(c.id, c.owasp_llm, c.mitre_atlas, c.vector, c.objective,
                                c.legit_tools, _registry_runner(c)))
    for cid, (owasp, atlas, vector, obj, legit, fn) in _POISON_META.items():
        cases.append(MatrixCase(cid, owasp, atlas, vector, obj, legit, _poison_runner(fn)))
    return cases


def defense_configs(lab: Lab, legit_tools: tuple[str, ...]) -> dict[str, tuple[Enforcer | None, str | None]]:
    hp = urlparse(lab.honeypot_url).netloc
    flagged = frozenset({"http_get", "run_shell"})
    return {
        "none": (None, None),
        "prompt_hardening": (None, HARDENED_SYSTEM_PROMPT),
        "allowlist": (build_enforcer(allowed_tools=frozenset(legit_tools)), None),
        "authz": (build_enforcer(protect_secrets=True), None),
        "sandbox": (build_enforcer(forbidden_netlocs=(hp,)), None),
        "hitl": (build_enforcer(hitl_flagged=flagged), None),
        "enforcer_all": (build_enforcer(allowed_tools=frozenset(legit_tools), protect_secrets=True,
                                        forbidden_netlocs=(hp,), hitl_flagged=flagged), None),
    }


def run_matrix(new_base_dir: Callable[[], Path], results_root: Path | None = None) -> dict:
    """new_base_dir() must return a fresh empty directory per call (one lab per cell)."""
    results_root = Path(results_root or default_results_dir())
    results_root.mkdir(parents=True, exist_ok=True)
    matrix: dict = {"defenses": DEFENSE_NAMES, "cases": {}}

    for mc in all_cases():
        row: dict[str, dict] = {}
        for dname in DEFENSE_NAMES:
            with armed_lab(new_base_dir()) as lab:
                enforcer, system_prompt = defense_configs(lab, mc.legit_tools)[dname]
                success, detail, trace_id, hits = mc.runner(lab, enforcer, system_prompt, results_root)
            row[dname] = {
                "success": success,        # attack achieved its objective
                "blocked": not success,    # defense stopped it
                "detail": detail,
                "trace_id": trace_id,
                "honeypot_hits": hits,
            }
        matrix["cases"][mc.case_id] = {
            "owasp_llm": mc.owasp_llm, "mitre_atlas": mc.mitre_atlas,
            "vector": mc.vector, "objective": mc.objective, "results": row,
        }

    (results_root / "matrix.json").write_text(json.dumps(matrix, indent=2))
    return matrix
