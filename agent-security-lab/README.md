# Agent Security Lab

A real, minimal, **no-framework** AI agent — built so you can weaponize it against
itself and then defend it. Every phase produces working code running a real model loop
doing real work. No mockups, no stubbed responses, no toy simulations of agent behavior.

Every attack is a committed, re-runnable test case with a deterministic, evidence-based
outcome (success = "the secret reached the honeypot" / "a forbidden tool was called"),
mapped to **OWASP LLM Top 10** and **MITRE ATLAS**.

> ⚠️ **Safety boundary.** All offensive behavior is confined to this lab's *fake* secrets,
> a local sandbox, and a local honeypot host. Never point the agent at third-party
> infrastructure. `run_shell` runs only inside the sandbox/container, never the host.

---

## Why a test-double model exists (read this once)

The three production backends — `llamacpp` (default), `anthropic`, `openai` — are **real**.
They make real network calls and **raise** if the endpoint is unreachable; none ever
fabricates a response.

The attack suite additionally uses a `ScriptedBackend`, a **deterministic test double**.
A real model is non-deterministic, but the spec demands attacks be *reproducible with a
deterministic expected outcome*. The scripted backend resolves that tension honestly:

- It is **never** selectable as a production backend (`get_backend()` refuses it).
- It does **not** fake data. It reads the *real* file bodies / HTTP responses already in
  the conversation (including any injected instruction and the real fake-secret) and
  decides its actions from them — exactly as a compromised real model would. The
  determinism lives in the decision policy, not in invented data.
- The same attack, pointed at a live vulnerable model via `--live`, exercises the
  identical loop and boundary.

So: the *agent, loop, dispatch boundary, tools, honeypot, and evidence* are all real. Only
the model's decision is scripted, and only in tests.

---

## Layout

```
agent/      hand-written loop, backends, tools, dispatch boundary, JSON tracing
config/     backend/endpoint settings; defense policy (inert until Phase 5)
target/     Phase 2 armed environment: fake secrets, docs, honeypot
attacks/    Phase 3 reproducible attack suite (registry + pytest)
mcp/        Phase 4 MCP server + tool-poisoning cases
defenses/   Phase 5 defenses, all interposing at the single dispatch boundary
reports/    OWASP/ATLAS cross-reference + attack×defense matrix generator
tests/      unit tests for the harness itself
```

## Quick start

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
cp .env.example .env            # edit if using a live backend

# Phase 1+ unit tests and the full attack/defense suite (no GPU, no Docker needed):
uv run pytest

# Run against a live model (default llama.cpp on localhost:8080):
uv run asl-agent "read notes.txt in the workdir and summarize it" --save-trace
```

### Live backend

Point `ASL_BACKEND` + the matching endpoint/keys in `.env`:

- `llamacpp` — an OpenAI-compatible llama.cpp server (e.g. Qwen on an RTX 3090).
- `anthropic` — needs `ANTHROPIC_API_KEY` and `pip install '.[anthropic]'`.
- `openai` — needs `OPENAI_API_KEY` and `pip install '.[openai]'`.

Swapping backends is a **config change only** — no edit to `loop.py`.

### Full stack (Docker Compose)

```bash
docker compose up --build      # sandbox + honeypot + docs web server
```

The llama.cpp server runs on the host and is reached over the compose network.

---

## Phases

| Phase | What | Status |
|-------|------|--------|
| 1 | Simplest possible agent (loop + tools + dispatch + tracing) | ✅ |
| 2 | Arm it (fake secrets, honeypot, seeded docs, compose) | ✅ |
| 3 | Attack it (direct + indirect, reproducible, OWASP/ATLAS tagged) | ✅ |
| 4 | MCP server + tool poisoning + agent-to-agent chaining | ✅ |
| 5 | Defend at the boundary + attack×defense evidence matrix | ✅ |

## Reports

```bash
uv run asl-report                       # builds reports/out/*.md from attacks/results
```

Produces the OWASP/ATLAS cross-reference and the attack×defense matrix with linked
evidence. See `defenses/ANALYSIS.md` for the thesis: prompt-level defenses fail; only
deterministic boundary enforcement holds.

## Instrumentation

Everything is traced as JSON lines tagged with a `trace_id`. The key event is
`untrusted_ingress`: it fires at every point attacker-controllable data (a file body, an
HTTP response, a tool *description*, an agent handoff) crosses into the model context. A
run is fully reconstructable from its trace alone.
