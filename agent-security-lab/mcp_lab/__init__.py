"""Phase 4 — MCP server + tool poisoning.

NOTE ON THE NAME: the spec's layout calls this directory `mcp/`. It is named `mcp_lab`
here because a package literally named `mcp` would shadow the official `mcp` SDK on
import (you could no longer `import mcp.server`). Everything else matches the spec.

MCP is used here only as a *protocol target under test*, not as an agent framework: the
agent still drives the loop and dispatches MCP tools through the same hand-written
`agent/dispatch.py` boundary, so MCP tools are instrumented identically to local tools.
"""
