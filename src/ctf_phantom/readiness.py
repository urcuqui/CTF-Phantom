"""Provider compatibility checks as first-class experiment readiness evidence.

``ctf-phantom check-provider`` sends ONE request with the experiment's real system prompt, tools
and objective (``runner.probe_provider``) and appends the outcome to

    <experiment_dir>/readiness/provider_checks.jsonl

before any run exists. Each record is keyed by a ``probe_key``: a hash of everything that can
change the provider's answer (provider settings, system prompt, tool specs, challenge objective).
A check is only evidence for configurations with the same key.

Outcomes: ``ready`` (well-formed tool call) | ``refusal`` (provider declined; category kept, e.g.
``cyber``) | ``no_tool_call`` | ``malformed_tool_call`` | ``provider_error``.

A refusal is recorded as-is. This module never retries, rephrases or otherwise tries to get
around a provider's safety policy; a refusing model/prompt combination is simply not ready.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ctf_phantom import __version__
from ctf_phantom.agent import get_profile
from ctf_phantom.challenges import load_challenge
from ctf_phantom.config import ExperimentConfig, experiment_dir
from ctf_phantom.hashing import sha256_json, sha256_text
from ctf_phantom.tools import TOOL_SPECS

SCHEMA_VERSION = "1.0"
READINESS_DIR = "readiness"
CHECKS_FILE = "provider_checks.jsonl"
OUTCOMES = ("ready", "refusal", "no_tool_call", "malformed_tool_call", "provider_error")
# Provider settings that cannot change the model's answer are excluded from the key.
_IRRELEVANT_PROVIDER_KEYS = {"timeout_s", "max_retries"}


def probe_key(cfg: ExperimentConfig) -> str:
    challenge = load_challenge(cfg.challenge)
    provider = {k: v for k, v in cfg.provider.model_dump(mode="json").items() if k not in _IRRELEVANT_PROVIDER_KEYS}
    return sha256_json({
        "provider": provider,
        "system_prompt_sha256": sha256_text(get_profile(cfg.agent.prompt_profile).system),
        "tool_specs_sha256": sha256_json([t.as_dict() for t in TOOL_SPECS]),
        "challenge": challenge.id,
        "objective_template_sha256": sha256_text(challenge.spec.objective),
    })[:16]


def checks_path(cfg: ExperimentConfig) -> Path:
    return experiment_dir(cfg) / READINESS_DIR / CHECKS_FILE


def record_check(cfg: ExperimentConfig, probe: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Append a probe outcome (append-only). Tool-call arguments and raw text are not stored."""
    outcome = probe.get("outcome") or ("ready" if probe.get("ok") else "provider_error")
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown probe outcome {outcome!r}")
    record = {
        "schema_version": SCHEMA_VERSION,
        "checked_at": (now or datetime.now(UTC)).isoformat(),
        "experiment": cfg.name,
        "probe_key": probe_key(cfg),
        "harness_version": __version__,
        "provider": cfg.provider.name,
        "requested_model": cfg.provider.model,
        "reported_model": probe.get("reported_model"),
        "effort": cfg.provider.effort,
        "ok": bool(probe.get("ok")) and outcome == "ready",
        "outcome": outcome,
        "stop_reason": probe.get("stop_reason"),
        "refusal_category": probe.get("refusal_category"),
        "refusal_explanation": probe.get("refusal_explanation"),
        "tool_calls": [{"name": c.get("name"), "well_formed": c.get("well_formed")}
                       for c in probe.get("tool_calls") or []],
        "usage": probe.get("usage"),
        "latency_s": probe.get("latency_s"),
        "error": probe.get("error"),
        "status_code": probe.get("status_code"),
    }
    path = checks_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return record


def load_checks(cfg: ExperimentConfig) -> list[dict[str, Any]]:
    path = checks_path(cfg)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def latest_check(cfg: ExperimentConfig) -> dict[str, Any] | None:
    """Most recent check (file order) whose probe_key matches the current configuration."""
    key = probe_key(cfg)
    matching = [c for c in load_checks(cfg) if c.get("probe_key") == key]
    return matching[-1] if matching else None


def readiness_problem(cfg: ExperimentConfig, *, now: datetime | None = None) -> str | None:
    """None if a recent passing check exists for this configuration, else why not."""
    check = latest_check(cfg)
    if check is None:
        return "no provider readiness check recorded for this provider/prompt/tool configuration " \
               "(run `ctf-phantom check-provider --config <file>`)"
    if not check["ok"]:
        category = f", category={check['refusal_category']}" if check.get("refusal_category") else ""
        return f"latest provider readiness check failed: outcome={check['outcome']}{category} ({check['checked_at']})"
    age = (now or datetime.now(UTC)) - datetime.fromisoformat(check["checked_at"])
    if age > timedelta(hours=cfg.execution.provider_check_max_age_hours):
        return f"latest passing provider check is older than {cfg.execution.provider_check_max_age_hours} h"
    return None
