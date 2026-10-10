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


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    challenge: str
    variants: list[str] = Field(min_length=1)
    repetitions: int = Field(1, gt=0)
    seed: int = 1337
    flag_salt: str = DEFAULT_SALT
    # Randomise variant order within each repetition block (seeded) to spread temporal drift.
    shuffle_variants: bool = True
    environment: EnvironmentConfig = Field(default_factory=EnvironmentConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)  # type: ignore[arg-type]
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    output_dir: str | None = None


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
