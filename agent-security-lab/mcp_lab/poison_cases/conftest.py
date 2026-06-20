"""Re-export the armed-lab fixtures so the MCP poison tests share the exact same lab
(honeypot + docs server + isolated workdir) as the Phase 3 attack suite."""

from attacks.conftest import lab, results_root  # noqa: F401
