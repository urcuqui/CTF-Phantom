"""Experiment configuration (YAML) schema and loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ctf_phantom.agent.agent import AgentConfig
from ctf_phantom.challenges.flags import DEFAULT_SALT
from ctf_phantom.providers.base import ProviderConfig


class EnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: Literal["docker", "local"] = "docker"
    startup_timeout_s: float = 90.0


class ExecutionConfig(BaseModel):
    """Failure handling and experiment-level budgets."""

    model_config = ConfigDict(extra="forbid")

    # Attempts per (variant, repetition) when a run fails for a *recoverable* infrastructure
    # reason. Retries reuse the same seed; every attempt keeps its own trace.
    max_attempts_per_run: int = Field(2, ge=1)
    # Circuit breaker: abort after this many consecutive failed attempts of any kind.
    max_consecutive_failures: int = Field(3, ge=1)
    # Stop starting new runs once these are reached (runs in flight finish normally).
    max_experiment_tokens: int | None = Field(None, gt=0)
    max_experiment_wall_time_s: float | None = Field(None, gt=0)
    # Refuse to start unless the latest provider readiness check for this exact provider/prompt/
    # tool configuration passed and is recent (``ctf-phantom check-provider`` records checks).
    require_provider_check: bool = False
    provider_check_max_age_hours: float = Field(24.0, gt=0)


class PinsConfig(BaseModel):
    """Expected provenance hashes. Any mismatch aborts before the first run."""

    model_config = ConfigDict(extra="forbid")

    challenge_hash: str | None = None
    variant_hashes: dict[str, str] | None = None
    system_prompt_sha256: str | None = None
    tool_specs_sha256: str | None = None
    flag_secret_fingerprint: str | None = None


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    challenge: str
    variants: list[str] = Field(min_length=1)
    repetitions: int = Field(1, gt=0)
    seed: int = 1337
    # Public domain-separation label for flag derivation. NOT a secret: flags are keyed by the
    # private flag secret (see ctf_phantom.challenges.flags).
    flag_salt: str = DEFAULT_SALT
    # Randomise variant order within each repetition block (seeded) to spread temporal drift.
    shuffle_variants: bool = True
    environment: EnvironmentConfig = Field(default_factory=EnvironmentConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)  # type: ignore[arg-type]
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)  # type: ignore[arg-type]
    pins: PinsConfig = Field(default_factory=PinsConfig)
    output_dir: str | None = None


def experiment_dir(cfg: ExperimentConfig) -> Path:
    from ctf_phantom.paths import results_dir

    base = Path(cfg.output_dir) if cfg.output_dir else results_dir()
    return base / cfg.name


def load_experiment(path: Path) -> ExperimentConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping")
    return ExperimentConfig.model_validate(data)


def apply_overrides(cfg: ExperimentConfig, overrides: dict[str, Any]) -> ExperimentConfig:
    """Apply dotted-key overrides (e.g. {"provider.model": "x"}); None values are ignored."""
    data = cfg.model_dump()
    for dotted, value in overrides.items():
        if value is None:
            continue
        node = data
        *parents, leaf = dotted.split(".")
        for key in parents:
            node = node[key]
        node[leaf] = value
    return ExperimentConfig.model_validate(data)


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env loader (KEY=VALUE lines); never overrides variables already set."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)
