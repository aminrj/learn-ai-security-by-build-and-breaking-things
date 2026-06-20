"""Execute one attack case against the (optionally defended) agent and collect evidence.

A single function is reused by Phase 3 (enforcer=None → attacks succeed) and Phase 5
(enforcer set → measure blocked/not). It writes per-run artifacts to
attacks/results/<trace_id>/ so every outcome is reproducible from disk.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.dispatch import Dispatcher, Enforcer
from agent.loop import SYSTEM_PROMPT, AgentLoop
from agent.tools import ToolContext, default_tools
from agent.trace import Tracer, default_results_dir
from attacks.registry import AttackCase, Evidence, Lab, Outcome
from target.honeypot.app import HoneypotLog


def run_attack(
    case: AttackCase,
    lab: Lab,
    *,
    enforcer: Enforcer | None = None,
    system_prompt: str | None = None,
    results_root: Path | None = None,
    max_turns: int = 8,
) -> Evidence:
    case.setup(lab)

    results_root = results_root or default_results_dir()
    tracer = Tracer(sink_path=None)  # sink set after we know trace_id
    run_dir = Path(results_root) / tracer.trace_id
    run_dir.mkdir(parents=True, exist_ok=True)
    tracer.sink_path = run_dir / "trace.jsonl"
    tracer.__post_init__()
    tracer.emit("note", phase="attack", case_id=case.id, owasp_llm=case.owasp_llm,
                mitre_atlas=case.mitre_atlas, vector=case.vector, objective=case.objective,
                defended=enforcer is not None)

    tools = default_tools()
    ctx = ToolContext(workdir=lab.workdir, tracer=tracer)
    dispatcher = Dispatcher(tools, ctx, enforcer=enforcer)
    model = case.make_model(lab)
    loop = AgentLoop(model, dispatcher, tools, tracer, max_turns=max_turns,
                     system_prompt=system_prompt or SYSTEM_PROMPT)

    transcript = loop.run(case.make_task(lab))

    honeypot_hits = HoneypotLog.read(lab.honeypot_log)
    ev = Evidence(case=case, tracer=tracer, transcript=transcript, honeypot_hits=honeypot_hits)
    outcome = case.verify(ev)

    _persist(run_dir, case, ev, outcome, defended=enforcer is not None)
    return ev


def _persist(run_dir: Path, case: AttackCase, ev: Evidence, outcome: Outcome,
             *, defended: bool) -> None:
    (run_dir / "honeypot.json").write_text(json.dumps(ev.honeypot_hits, indent=2, default=str))
    (run_dir / "outcome.json").write_text(json.dumps({
        "case_id": case.id,
        "title": case.title,
        "vector": case.vector,
        "owasp_llm": case.owasp_llm,
        "mitre_atlas": case.mitre_atlas,
        "objective": case.objective,
        "defended": defended,
        "success": outcome.success,
        "detail": outcome.detail,
        "trace_id": ev.tracer.trace_id,
        "honeypot_hits": len(ev.honeypot_hits),
    }, indent=2, default=str))


def verify(case: AttackCase, ev: Evidence) -> Outcome:
    return case.verify(ev)
