"""The report generator turns results/ into the cross-ref + matrix markdown artifacts."""

from __future__ import annotations

import json

from reports.generate import generate


def _synthetic_results(results_dir):
    matrix = {
        "defenses": ["none", "prompt_hardening", "authz", "enforcer_all"],
        "cases": {
            "D01": {
                "owasp_llm": "LLM01 Prompt Injection", "mitre_atlas": "AML.T0051",
                "vector": "direct", "objective": "leak_secret",
                "results": {
                    "none": {"success": True, "blocked": False, "trace_id": "aaaa0000", "detail": ""},
                    "prompt_hardening": {"success": True, "blocked": False, "trace_id": "bbbb1111", "detail": ""},
                    "authz": {"success": False, "blocked": True, "trace_id": "cccc2222", "detail": ""},
                    "enforcer_all": {"success": False, "blocked": True, "trace_id": "dddd3333", "detail": ""},
                },
            },
            "P03": {
                "owasp_llm": "LLM01 / A2A chaining", "mitre_atlas": "AML.T0051",
                "vector": "mcp_chain", "objective": "leak_secret",
                "results": {
                    "none": {"success": True, "blocked": False, "trace_id": "eeee4444", "detail": ""},
                    "prompt_hardening": {"success": True, "blocked": False, "trace_id": "ffff5555", "detail": ""},
                    "authz": {"success": False, "blocked": True, "trace_id": "9999aaaa", "detail": ""},
                    "enforcer_all": {"success": False, "blocked": True, "trace_id": "8888bbbb", "detail": ""},
                },
            },
        },
    }
    (results_dir / "matrix.json").write_text(json.dumps(matrix))


def test_generate_produces_crossref_and_matrix(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    _synthetic_results(results_dir)
    out_dir = tmp_path / "out"

    written = generate(results_dir, out_dir)
    names = {p.name for p in written}
    assert {"owasp_atlas_crossref.md", "defense_matrix.md"} <= names

    crossref = (out_dir / "owasp_atlas_crossref.md").read_text()
    assert "D01" in crossref and "P03" in crossref
    assert "AML.T0051" in crossref
    # Gap commentary for the agentic/MCP vectors is present.
    assert "agent-to-agent" in crossref.lower() or "a2a" in crossref.lower()

    matrix_md = (out_dir / "defense_matrix.md").read_text()
    assert "Attack × Defense Matrix" in matrix_md
    assert "✅" in matrix_md and "❌" in matrix_md
    # D01 open under prompt hardening, blocked under authz.
    assert "prompt_hardening" in matrix_md


def test_generate_without_matrix_still_writes_crossref(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    run_dir = results_dir / "trace123"
    run_dir.mkdir()
    (run_dir / "outcome.json").write_text(json.dumps({
        "case_id": "D02", "vector": "direct", "objective": "leak_secret",
        "owasp_llm": "LLM01", "mitre_atlas": "AML.T0024",
    }))
    written = generate(results_dir, tmp_path / "out")
    assert any(p.name == "owasp_atlas_crossref.md" for p in written)
    assert "D02" in (tmp_path / "out" / "owasp_atlas_crossref.md").read_text()
