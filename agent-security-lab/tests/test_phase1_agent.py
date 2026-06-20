"""Phase 1 acceptance: a real hand-written loop, real tools, full trace reconstruction."""

from __future__ import annotations

import pytest

from agent.dispatch import Dispatcher
from agent.llm import BackendError, LlamaCppBackend, ScriptedBackend, get_backend
from agent.loop import AgentLoop
from agent.tools import ToolContext, default_tools
from agent.trace import Tracer
from agent.types import AssistantTurn, ToolCall
from config.settings import Settings


def _wire(steps, workdir, max_turns=6):
    tracer = Tracer()
    tools = default_tools()
    ctx = ToolContext(workdir=workdir, tracer=tracer)
    dispatcher = Dispatcher(tools, ctx)
    backend = ScriptedBackend(steps)
    return AgentLoop(backend, dispatcher, tools, tracer, max_turns=max_turns), tracer


def test_benign_read_and_summarize(tmp_path):
    """Acceptance: agent calls read_file, gets REAL content, model produces a summary."""
    (tmp_path / "notes.txt").write_text("Project kickoff is Monday. Budget is 10k.")

    def step_read(messages):
        return AssistantTurn(text=None, tool_calls=[
            ToolCall(id="c1", name="read_file", arguments={"path": "notes.txt"})])

    def step_summarize(messages):
        # Derive the summary from the REAL tool result now in the conversation.
        last_tool = next(m for m in reversed(messages) if m.role == "tool")
        assert "Budget is 10k" in (last_tool.content or "")
        return AssistantTurn(text="Summary: kickoff Monday, 10k budget.", tool_calls=[])

    loop, tracer = _wire([step_read, step_summarize], tmp_path)
    transcript = loop.run("Read notes.txt and summarize it.")

    assert transcript.stop_reason == "completed"
    assert "kickoff Monday" in transcript.messages[-1].content
    # A real read_file tool call happened against the real filesystem.
    assert tracer.tool_calls_for("read_file")
    # The file body crossed into context as untrusted ingress.
    ingress = tracer.of_type("untrusted_ingress")
    assert any(e["source"] == "file" and e["via_tool"] == "read_file" for e in ingress)


def test_run_reconstructable_from_trace_alone(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    def step_read(_):
        return AssistantTurn(None, [ToolCall("c1", "read_file", {"path": "a.txt"})])

    def step_done(_):
        return AssistantTurn("done", [])

    loop, tracer = _wire([step_read, step_done], tmp_path)
    loop.run("read a.txt")

    kinds = [e["event"] for e in tracer.events]
    for required in ("run_start", "model_request", "model_response",
                     "tool_call_requested", "tool_call_result", "untrusted_ingress", "run_end"):
        assert required in kinds, f"missing trace event {required}"
    # seq numbers are monotonic — ordering is reconstructable.
    seqs = [e["seq"] for e in tracer.events]
    assert seqs == sorted(seqs)


def test_schema_validation_blocks_bad_args(tmp_path):
    def step_bad(_):
        return AssistantTurn(None, [ToolCall("c1", "read_file", {"wrong": "x"})])

    def step_done(_):
        return AssistantTurn("ok", [])

    loop, tracer = _wire([step_bad, step_done], tmp_path)
    loop.run("oops")
    results = tracer.of_type("tool_call_result")
    assert results and results[0]["ok"] is False
    assert "schema validation failed" in results[0]["result"]


def test_path_escape_is_refused(tmp_path):
    def step_escape(_):
        return AssistantTurn(None, [ToolCall("c1", "read_file", {"path": "../../etc/passwd"})])

    def step_done(_):
        return AssistantTurn("ok", [])

    loop, tracer = _wire([step_escape, step_done], tmp_path)
    loop.run("escape")
    results = tracer.of_type("tool_call_result")
    assert results[0]["ok"] is False
    assert "escapes the workdir" in results[0]["result"]


def test_turn_cap_is_enforced(tmp_path):
    def loop_forever(_):
        return AssistantTurn(None, [ToolCall("c1", "read_file", {"path": "missing.txt"})])

    loop, tracer = _wire([loop_forever] * 20, tmp_path, max_turns=3)
    transcript = loop.run("spin")
    assert transcript.turns_used == 3
    assert transcript.stop_reason == "max_turns"


def test_unreachable_real_backend_raises_not_fakes():
    """A real backend must raise on an unreachable endpoint, never fabricate a reply."""
    s = Settings()
    object.__setattr__(s.llamacpp, "base_url", "http://127.0.0.1:1/v1")  # nothing listening
    backend = LlamaCppBackend(s, timeout=1.0)
    with pytest.raises(BackendError):
        backend.chat([], [])


def test_scripted_backend_cannot_be_selected_in_prod():
    s = Settings()
    object.__setattr__(s, "backend", "scripted")
    with pytest.raises(BackendError):
        get_backend(s)


def test_backend_swap_is_config_only(monkeypatch):
    """Swapping llama.cpp -> openai is a config change; loop.py is untouched."""
    s_llama = Settings()
    object.__setattr__(s_llama, "backend", "llamacpp")
    assert get_backend(s_llama).name == "llamacpp"

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    s_openai = Settings()
    object.__setattr__(s_openai, "backend", "openai")
    # Will raise only if the openai SDK is absent; the selection logic itself is config-driven.
    try:
        assert get_backend(s_openai).name == "openai"
    except BackendError as exc:
        assert "openai" in str(exc).lower()
