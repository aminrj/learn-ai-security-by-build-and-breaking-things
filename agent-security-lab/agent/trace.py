"""Structured JSON-lines instrumentation. The conceptual heart of the lab.

Every model call, every tool call, and — most importantly — every point where
attacker-controllable data crosses into the model's context is emitted as one JSON
object per line, tagged with a `trace_id`. A run is fully reconstructable from its
trace alone (Phase 1 acceptance criterion).

`untrusted_ingress` is the key event: it fires whenever external content (a file
body, an HTTP response body, or a tool *description*) is placed into the context.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

EventType = Literal[
    "run_start",
    "run_end",
    "model_request",
    "model_response",
    "tool_call_requested",
    "tool_call_result",
    "untrusted_ingress",
    "defense_decision",  # Phase 5: emitted by the enforcer at the boundary
    "trust_transfer",    # Phase 4 P03: marks framing crossing an agent->agent boundary
    "note",
]

# Source kinds for untrusted_ingress, so reports can group by ingress vector.
IngressSource = Literal["file", "http_response", "tool_description", "agent_handoff", "user_task"]


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class Tracer:
    """Collects trace events in memory and optionally mirrors them to a JSONL file.

    The in-memory `events` list is what `verify()` functions inspect; the file is for
    persisted per-run artifacts under attacks/results/<trace_id>/.
    """

    trace_id: str = field(default_factory=new_trace_id)
    sink_path: Path | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _seq: int = 0

    def __post_init__(self) -> None:
        if self.sink_path is not None:
            self.sink_path = Path(self.sink_path)
            self.sink_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: EventType, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            event = {
                "trace_id": self.trace_id,
                "seq": self._seq,
                "ts": time.time(),
                "event": event_type,
                **fields,
            }
            self.events.append(event)
            if self.sink_path is not None:
                with self.sink_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, default=str) + "\n")
            return event

    # ---- typed convenience emitters -------------------------------------------------

    def model_request(self, *, messages: list[dict[str, Any]], tools: list[str], backend: str) -> None:
        self.emit("model_request", backend=backend, tools=tools, message_count=len(messages),
                  messages=messages)

    def model_response(self, *, text: str | None, tool_calls: list[dict[str, Any]],
                       stop_reason: str | None) -> None:
        self.emit("model_response", text=text, tool_calls=tool_calls, stop_reason=stop_reason)

    def tool_call_requested(self, *, tool: str, arguments: dict[str, Any], call_id: str) -> None:
        self.emit("tool_call_requested", tool=tool, call_id=call_id, arguments=arguments)

    def tool_call_result(self, *, tool: str, call_id: str, ok: bool, result: str,
                         blocked_by: str | None = None, error: str | None = None) -> None:
        self.emit("tool_call_result", tool=tool, call_id=call_id, ok=ok, result=result,
                  blocked_by=blocked_by, error=error)

    def untrusted_ingress(self, *, source: IngressSource, origin: str, content: str,
                          via_tool: str | None = None) -> None:
        """Attacker-controllable content entering the model context. `origin` is where it
        came from (a path, URL, tool name, or upstream agent id)."""
        self.emit("untrusted_ingress", source=source, origin=origin, via_tool=via_tool,
                  content=content, content_len=len(content))

    def defense_decision(self, *, defense: str, tool: str, decision: str, reason: str,
                         call_id: str | None = None) -> None:
        self.emit("defense_decision", defense=defense, tool=tool, decision=decision,
                  reason=reason, call_id=call_id)

    def trust_transfer(self, *, from_agent: str, to_agent: str, inherited: str) -> None:
        self.emit("trust_transfer", from_agent=from_agent, to_agent=to_agent, inherited=inherited)

    # ---- querying helpers (used by attack verify() functions) -----------------------

    def of_type(self, event_type: EventType) -> list[dict[str, Any]]:
        return [e for e in self.events if e["event"] == event_type]

    def tool_calls_for(self, tool: str) -> list[dict[str, Any]]:
        return [e for e in self.of_type("tool_call_requested") if e.get("tool") == tool]

    def dumps(self) -> str:
        return "\n".join(json.dumps(e, default=str) for e in self.events)


def default_results_dir() -> Path:
    return Path(os.environ.get("ASL_RESULTS_DIR", Path(__file__).resolve().parent.parent / "attacks" / "results"))
