"""Central configuration: backend selection, endpoints, model names, lab wiring.

Values come from environment variables (see .env.example), with sane defaults so
the test suite runs with zero configuration. `python-dotenv` loads a local `.env`
if present, but the lab never *requires* one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # dotenv is a hard dependency, but keep import defensive for partial installs
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - only hit when dotenv missing
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name: str, default: str) -> Path:
    raw = os.environ.get(name, default)
    p = Path(raw)
    return p if p.is_absolute() else (REPO_ROOT / p).resolve()


@dataclass(frozen=True)
class LlamaCppConfig:
    base_url: str = field(default_factory=lambda: _env("ASL_LLAMACPP_BASE_URL", "http://localhost:8080/v1"))
    model: str = field(default_factory=lambda: _env("ASL_LLAMACPP_MODEL", "qwen2.5-7b-instruct"))
    api_key: str = field(default_factory=lambda: _env("ASL_LLAMACPP_API_KEY", "sk-no-key-required"))


@dataclass(frozen=True)
class AnthropicConfig:
    api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY", ""))
    model: str = field(default_factory=lambda: _env("ASL_ANTHROPIC_MODEL", "claude-opus-4-8"))


@dataclass(frozen=True)
class OpenAIConfig:
    api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY", ""))
    model: str = field(default_factory=lambda: _env("ASL_OPENAI_MODEL", "gpt-4o"))


@dataclass(frozen=True)
class Settings:
    backend: str = field(default_factory=lambda: _env("ASL_BACKEND", "llamacpp").lower())
    max_turns: int = field(default_factory=lambda: int(_env("ASL_MAX_TURNS", "8")))

    workdir: Path = field(default_factory=lambda: _env_path("ASL_WORKDIR", "./target/workdir"))
    docs_url: str = field(default_factory=lambda: _env("ASL_DOCS_URL", "http://localhost:8081"))
    honeypot_url: str = field(default_factory=lambda: _env("ASL_HONEYPOT_URL", "http://localhost:9009"))
    honeypot_log: Path = field(
        default_factory=lambda: _env_path("ASL_HONEYPOT_LOG", "./target/honeypot/honeypot.log")
    )

    defenses_enabled: bool = field(default_factory=lambda: _env_bool("ASL_DEFENSES_ENABLED", False))

    llamacpp: LlamaCppConfig = field(default_factory=LlamaCppConfig)
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)


def load_settings() -> Settings:
    """Return a fresh Settings snapshot from the current environment."""
    return Settings()


# Convenience module-level default. Tests that mutate the environment should call
# load_settings() to get a fresh snapshot rather than relying on this.
settings = load_settings()
