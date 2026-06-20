"""Defense policy (Phase 5). Inert until Phase 5 wires it into the enforcer.

This module is intentionally present from Phase 1 so the shape of the policy is
visible early, but every field defaults to a permissive/"no-op" stance. The agent
in Phases 1-4 behaves as if no policy exists. `defenses/enforcer.py` reads this in
Phase 5; nothing else should consume it before then.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    # ---- allowlist.py ----
    # If non-empty, only these tools may be dispatched for a task. Empty = allow all.
    allowed_tools: frozenset[str] = field(default_factory=frozenset)

    # ---- authz.py ----
    # Path glob patterns that require an explicit grant before read_file/run_shell
    # may touch them. Deterministic, not model-mediated.
    protected_path_globs: tuple[str, ...] = ()
    granted_path_globs: tuple[str, ...] = ()

    # ---- sandbox.py ----
    # Hosts run_shell / http_get may never reach (egress filter). Honeypot goes here
    # in Phase 5 to prove network-level blocking, not prompt-level discouragement.
    forbidden_hosts: tuple[str, ...] = ()
    # If True, run_shell must execute inside the sandbox container, never the host.
    require_sandboxed_shell: bool = False

    # ---- hitl.py ----
    # Tools whose calls require human-in-the-loop confirmation.
    hitl_required_tools: frozenset[str] = field(default_factory=frozenset)

    enabled: bool = False


# The permissive default used by Phases 1-4 (everything allowed, nothing enforced).
INERT_POLICY = Policy()
