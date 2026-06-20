"""Minimal CLI: run the agent on a task with the configured real backend.

    asl-agent "read notes.txt in the workdir and summarize it"

Prints the final answer and the trace location. Use this for Phase 1/2 manual runs
against a live llama.cpp/Anthropic/OpenAI backend.
"""

from __future__ import annotations

import argparse
import sys

from agent.loop import build_default_loop
from agent.trace import default_results_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asl-agent", description="Run the security-lab agent.")
    parser.add_argument("task", help="The task for the agent to perform.")
    parser.add_argument("--max-turns", type=int, default=None, help="Override the loop turn cap.")
    parser.add_argument("--save-trace", action="store_true", help="Persist the JSONL trace to disk.")
    args = parser.parse_args(argv)

    loop = build_default_loop(max_turns=args.max_turns)
    if args.save_trace:
        sink = default_results_dir() / loop.tracer.trace_id / "trace.jsonl"
        loop.tracer.sink_path = sink
        loop.tracer.__post_init__()

    try:
        transcript = loop.run(args.task)
    except Exception as exc:  # surface backend errors clearly; never fabricate
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    final = next((m.content for m in reversed(transcript.messages)
                  if m.role == "assistant" and m.content), "(no final text)")
    print(final)
    print(f"\n[trace_id={transcript.trace_id} turns={transcript.turns_used} "
          f"stop={transcript.stop_reason}]", file=sys.stderr)
    if args.save_trace:
        print(f"[trace saved to {loop.tracer.sink_path}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
