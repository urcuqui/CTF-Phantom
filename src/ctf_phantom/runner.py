"""Experiment runner: one fresh environment per run, full provenance, trace + metrics on disk.

Output layout::

    <output_dir>/<experiment>/
        experiment.json            config snapshot + provenance for the whole experiment
        runs.jsonl                 one metrics record per completed run (append-only)
        <run_id>/
            trace.jsonl            event trace (source of truth)
            metrics.json           evaluation of trace.jsonl
            manifest.json          config + provenance for this run
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_phantom import __version__
from ctf_phantom.agent import Agent, AgentOutcome, get_profile
from ctf_phantom.challenges import Challenge, FlagValidator, derive_flag, flag_hash, load_challenge
from ctf_phantom.config import ExperimentConfig
from ctf_phantom.environments import build_environment
from ctf_phantom.evaluation import RunMetrics, evaluate_events
from ctf_phantom.hashing import sha256_json, sha256_text
from ctf_phantom.paths import project_root, results_dir
from ctf_phantom.providers import build_provider
from ctf_phantom.tools import HttpTool, SubmitFlagTool, TerminateTool
from ctf_phantom.tracing import EventType, TraceRecorder


@dataclass
class RunResult:
    run_dir: Path
    metrics: RunMetrics


def git_state() -> dict[str, Any]:
    root = project_root()

    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    status = git("status", "--porcelain")
    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(status) if status is not None else None}


def host_provenance() -> dict[str, Any]:
    return {
        "ctf_phantom_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "git": git_state(),
    }


def run_order(cfg: ExperimentConfig) -> list[tuple[int, str]]:
    """Repetition-major blocks; variant order within a block is seeded-shuffled if enabled."""
    rng = random.Random(cfg.seed)
    order: list[tuple[int, str]] = []
    for rep in range(cfg.repetitions):
        block = list(cfg.variants)
        if cfg.shuffle_variants:
            rng.shuffle(block)
        order.extend((rep, v) for v in block)
    return order


def experiment_dir(cfg: ExperimentConfig) -> Path:
    base = Path(cfg.output_dir) if cfg.output_dir else results_dir()
    return base / cfg.name


def run_single(
    cfg: ExperimentConfig,
    challenge: Challenge,
    variant_id: str,
    repetition: int,
    *,
    out_dir: Path,
) -> RunResult:
    variant = challenge.variant(variant_id)
    seed = cfg.seed + repetition
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}_{challenge.id}_{variant_id}_r{repetition:03d}_{uuid.uuid4().hex[:6]}"
    run_dir = out_dir / run_id

    flag = derive_flag(challenge.id, seed, cfg.flag_salt)
    session_secret = hashlib.sha256(f"session:{challenge.id}:{seed}:{cfg.flag_salt}".encode()).hexdigest()
    validator = FlagValidator(flag, challenge.spec.flag.format_regex)
    provider = build_provider(cfg.provider, challenge.spec)
    profile = get_profile(cfg.agent.prompt_profile)
    submit_tool = SubmitFlagTool(validator, cfg.agent.max_flag_submissions)
    terminate_tool = TerminateTool()
    tool_specs = [HttpTool.spec, submit_tool.spec, terminate_tool.spec]

    indicator_library = [
        {"variant_id": vid, "indicator": ind.model_dump(mode="json")}
        for vid, v in challenge.variants.items()
        for ind in v.indicators
    ]
    provenance = {
        **host_provenance(),
        "challenge_hash": challenge.challenge_hash,
        "variant_hash": challenge.variant_hashes[variant_id],
        "payload_hashes": challenge.payload_hashes[variant_id],
        "system_prompt_sha256": sha256_text(profile.system),
        "tool_specs_sha256": sha256_json([t.as_dict() for t in tool_specs]),
        "config_sha256": sha256_json(cfg.model_dump(mode="json")),
        "flag_sha256": flag_hash(flag),
    }

    run_dir.mkdir(parents=True, exist_ok=False)
    recorder = TraceRecorder(run_dir / "trace.jsonl", run_id)
    recorder.record(EventType.RUN_STARTED, {
        "experiment": cfg.name,
        "config": cfg.model_dump(mode="json"),
        "seed": seed,
        "repetition": repetition,
        "challenge": {"id": challenge.id, "version": challenge.spec.version, "name": challenge.spec.name},
        "variant": variant.model_dump(mode="json"),
        "indicator_library": indicator_library,
        "provider": provider.describe(),
        "prompt": {"profile": profile.id, "version": profile.version, "system": profile.system},
        "tools": [t.as_dict() for t in tool_specs],
        "provenance": provenance,
    })

    t0 = time.monotonic()
    env = build_environment(cfg.environment.backend, challenge,
                            startup_timeout_s=cfg.environment.startup_timeout_s)
    outcome: AgentOutcome | None = None
    error: str | None = None
    http_tool: HttpTool | None = None
    try:
        info = env.start(flag=flag, slots=dict(variant.slots), session_secret=session_secret)
        objective = challenge.spec.render_objective(info.base_url)
        recorder.record(EventType.ENVIRONMENT_READY, {
            "backend": info.backend,
            "base_url": info.base_url,
            "startup_s": info.startup_s,
            "details": info.details,
            "objective": objective,
        })
        http_tool = HttpTool(info.base_url, timeout_s=cfg.agent.request_timeout_s,
                             max_observation_chars=cfg.agent.max_observation_chars)
        agent = Agent(provider, [http_tool, submit_tool, terminate_tool], profile.system,
                      cfg.agent, recorder)
        outcome = agent.run(objective)
    except Exception as exc:  # noqa: BLE001 - recorded, then re-raised after cleanup
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if http_tool is not None:
            http_tool.close()
        try:
            recorder.record(EventType.ENVIRONMENT_LOGS, {"lines": env.server_logs()})
        finally:
            env.stop()
            recorder.record(EventType.RUN_FINISHED, {
                "stop_reason": outcome.stop_reason.value if outcome else "harness_error",
                "steps": outcome.steps if outcome else 0,
                "duration_s": round(time.monotonic() - t0, 3),
                "error": error or (outcome.error if outcome else None),
            })
            recorder.close()

    metrics = evaluate_events(recorder.events)
    (run_dir / "metrics.json").write_text(metrics.model_dump_json(indent=2), encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "experiment": cfg.name, "variant": variant_id, "repetition": repetition,
        "seed": seed, "provenance": provenance, "config": cfg.model_dump(mode="json"),
    }, indent=2), encoding="utf-8")
    return RunResult(run_dir, metrics)


def run_experiment(cfg: ExperimentConfig, *, on_run: Any = None) -> list[RunResult]:
    challenge = load_challenge(cfg.challenge)
    for vid in cfg.variants:
        challenge.variant(vid)  # fail fast on unknown variants
    out_dir = experiment_dir(cfg)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "experiment.json").write_text(json.dumps({
        "config": cfg.model_dump(mode="json"),
        "challenge_hash": challenge.challenge_hash,
        "variant_hashes": challenge.variant_hashes,
        "host": host_provenance(),
        "run_order": run_order(cfg),
        "created_at": datetime.now(UTC).isoformat(),
    }, indent=2), encoding="utf-8")

    results: list[RunResult] = []
    for rep, vid in run_order(cfg):
        result = run_single(cfg, challenge, vid, rep, out_dir=out_dir)
        with (out_dir / "runs.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(result.metrics.model_dump_json() + "\n")
        results.append(result)
        if on_run is not None:
            on_run(result)
    return results
