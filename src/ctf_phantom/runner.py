"""Experiment runner: one fresh environment per run, full provenance, trace + metrics on disk.

Output layout::

    <output_dir>/<experiment>/
        experiment.json            config, provenance, run order, final status (updated at end)
        runs.jsonl                 one metrics record per ATTEMPTED run, valid or not (append-only)
        <run_id>/
            trace.jsonl            event trace (source of truth; secrets redacted)
            metrics.json           evaluation of trace.jsonl
            manifest.json          config + provenance + final status for this run

Failure handling
----------------
Every attempted run produces a trace ending in ``run_finished`` with a ``status``
(see ``ctf_phantom.status``) and the environment is always torn down. Failures are classified:

* recoverable (transient provider/environment errors, harness exceptions): the same
  (variant, repetition) is retried with the same seed up to ``execution.max_attempts_per_run``;
  a circuit breaker aborts after ``execution.max_consecutive_failures`` consecutive failures;
* fatal (configuration errors, non-recoverable provider errors, isolation failures, failed
  teardown, operator interrupt): the experiment stops safely after recording the run.

Configuration problems detectable up front are raised by ``preflight`` before any run starts.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import random
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_phantom import __version__
from ctf_phantom.agent import Agent, AgentOutcome, StopReason, get_profile
from ctf_phantom.challenges import (
    Challenge,
    FlagSecret,
    FlagSecretError,
    FlagValidator,
    derive_flag,
    derive_session_secret,
    flag_hash,
    load_challenge,
    load_flag_secret,
)
from ctf_phantom.config import ExperimentConfig
from ctf_phantom.environments import (
    BackendUnavailableError,
    ChallengeEnvironment,
    CleanupError,
    EnvironmentError_,
    IsolationError,
    build_environment,
    docker_available,
)
from ctf_phantom.evaluation import RunMetrics, evaluate_events
from ctf_phantom.hashing import sha256_json, sha256_text
from ctf_phantom.paths import project_root, results_dir
from ctf_phantom.providers import LLMProvider, ProviderError, build_provider
from ctf_phantom.status import ConfigurationError, RunStatus
from ctf_phantom.tools import HttpTool, SubmitFlagTool, TerminateTool, ToolSpec
from ctf_phantom.tools.control import SUBMIT_FLAG_SPEC, TERMINATE_SPEC
from ctf_phantom.tools.http import HTTP_REQUEST_SPEC
from ctf_phantom.tracing import EventType, TraceRecorder

FLAG_DERIVATION = "hmac-sha256/v2"
FLAG_PLACEHOLDER = "[REDACTED:flag]"
SESSION_PLACEHOLDER = "[REDACTED:session_secret]"
# The victim's fixed tool surface. Its hash is recorded per run and can be pinned.
TOOL_SPECS: tuple[ToolSpec, ...] = (HTTP_REQUEST_SPEC, SUBMIT_FLAG_SPEC, TERMINATE_SPEC)
PAID_RUNS_ENV = "CTF_PHANTOM_ALLOW_PAID_RUNS"


@dataclass
class RunResult:
    run_dir: Path
    metrics: RunMetrics
    status: RunStatus = RunStatus.COMPLETED
    recoverable: bool = True      # for failures: retrying this (variant, repetition) makes sense
    fatal: bool = False           # the experiment must stop after this run


@dataclass
class ExperimentReport:
    out_dir: Path
    status: str                   # completed | aborted | budget_exhausted
    reason: str | None = None
    results: list[RunResult] = field(default_factory=list)


class _StopExperiment(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------------------------
# provenance
# --------------------------------------------------------------------------------------------
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


def tool_specs_sha256() -> str:
    return sha256_json([t.as_dict() for t in TOOL_SPECS])


def current_pins(cfg: ExperimentConfig, challenge: Challenge, secret: FlagSecret | None) -> dict[str, Any]:
    """Values that `pins:` in an experiment config is compared against."""
    return {
        "challenge_hash": challenge.challenge_hash,
        "variant_hashes": {v: challenge.variant_hashes[v] for v in cfg.variants},
        "system_prompt_sha256": sha256_text(get_profile(cfg.agent.prompt_profile).system),
        "tool_specs_sha256": tool_specs_sha256(),
        "flag_secret_fingerprint": secret.fingerprint if secret else None,
    }


# --------------------------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------------------------
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


def preflight(cfg: ExperimentConfig, *, flag_secret: FlagSecret | None = None,
              create_secret: bool = False) -> tuple[Challenge, FlagSecret]:
    """Validate everything that would make every run fail identically. Raises ConfigurationError."""
    try:
        challenge = load_challenge(cfg.challenge)
        for vid in cfg.variants:
            challenge.variant(vid)
        get_profile(cfg.agent.prompt_profile)
    except (FileNotFoundError, KeyError, ValueError) as exc:
        raise ConfigurationError(str(exc)) from exc

    if cfg.provider.name != "scripted" and os.environ.get("CI") and not os.environ.get(PAID_RUNS_ENV):
        raise ConfigurationError(
            f"refusing to call a real LLM provider ({cfg.provider.name}) in CI; set {PAID_RUNS_ENV}=1 to override"
        )
    try:
        secret = flag_secret or load_flag_secret(create=create_secret)
    except FlagSecretError as exc:
        raise ConfigurationError(str(exc)) from exc

    expected = cfg.pins.model_dump(exclude_none=True)
    if expected:
        actual = current_pins(cfg, challenge, secret)
        mismatches = []
        for key, want in expected.items():
            have = actual[key]
            if key == "variant_hashes":
                bad = {v: (h, have.get(v)) for v, h in want.items() if have.get(v) != h}
                if bad:
                    mismatches.append(f"variant_hashes {bad}")
            elif have != want:
                mismatches.append(f"{key}: pinned {want} != current {have}")
        if mismatches:
            raise ConfigurationError("provenance pins do not match: " + "; ".join(mismatches))

    try:
        build_provider(cfg.provider, challenge.spec)
    except ProviderError as exc:
        raise ConfigurationError(f"provider cannot be constructed: {exc}") from exc
    if cfg.environment.backend == "docker" and not docker_available():
        raise ConfigurationError("Docker daemon not reachable. Start Docker or use --backend local.")
    return challenge, secret


# --------------------------------------------------------------------------------------------
# single run
# --------------------------------------------------------------------------------------------
def classify_exception(exc: BaseException) -> tuple[RunStatus, bool]:
    """Map an exception to (status, recoverable)."""
    if isinstance(exc, ConfigurationError):
        return RunStatus.CONFIGURATION_ERROR, False
    if isinstance(exc, ProviderError):
        if exc.kind == "configuration":
            return RunStatus.CONFIGURATION_ERROR, False
        return RunStatus.PROVIDER_ERROR, exc.recoverable
    if isinstance(exc, IsolationError):
        return RunStatus.ISOLATION_FAILURE, False
    if isinstance(exc, (BackendUnavailableError, CleanupError)):
        return RunStatus.ENVIRONMENT_ERROR, False
    if isinstance(exc, EnvironmentError_):
        return RunStatus.ENVIRONMENT_ERROR, True
    return RunStatus.HARNESS_ERROR, True


def run_single(
    cfg: ExperimentConfig,
    challenge: Challenge,
    variant_id: str,
    repetition: int,
    *,
    out_dir: Path,
    flag_secret: FlagSecret,
    attempt: int = 1,
) -> RunResult:
    variant = challenge.variant(variant_id)
    seed = cfg.seed + repetition
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}_{challenge.id}_{variant_id}_r{repetition:03d}_a{attempt}_{uuid.uuid4().hex[:6]}"
    run_dir = out_dir / run_id

    flag = derive_flag(challenge.id, seed, flag_secret, cfg.flag_salt, reserved=challenge.decoy_flags)
    session_secret = derive_session_secret(challenge.id, seed, flag_secret, cfg.flag_salt)
    profile = get_profile(cfg.agent.prompt_profile)
    validator = FlagValidator(flag, challenge.spec.flag.format_regex, reserved=challenge.decoy_flags)
    submit_tool = SubmitFlagTool(validator, cfg.agent.max_flag_submissions)
    terminate_tool = TerminateTool()

    provenance = {
        **host_provenance(),
        "challenge_hash": challenge.challenge_hash,
        "variant_hash": challenge.variant_hashes[variant_id],
        "payload_hashes": challenge.payload_hashes[variant_id],
        "system_prompt_sha256": sha256_text(profile.system),
        "tool_specs_sha256": tool_specs_sha256(),
        "config_sha256": sha256_json(cfg.model_dump(mode="json")),
        "flag_sha256": flag_hash(flag),
        "flag_derivation": FLAG_DERIVATION,
        "flag_secret_fingerprint": flag_secret.fingerprint,
        "decoy_flags_reserved": sorted(challenge.decoy_flags),
    }

    run_dir.mkdir(parents=True, exist_ok=False)
    recorder = TraceRecorder(run_dir / "trace.jsonl", run_id,
                             redactions={flag: FLAG_PLACEHOLDER, session_secret: SESSION_PLACEHOLDER})

    provider: LLMProvider | None = None
    setup_error: ProviderError | None = None
    try:
        provider = build_provider(cfg.provider, challenge.spec)
        provider_desc = provider.describe()
    except ProviderError as exc:
        setup_error = exc
        provider_desc = {"provider": cfg.provider.name, "requested_model": cfg.provider.model,
                         "construction_error": str(exc)}

    recorder.record(EventType.RUN_STARTED, {
        "experiment": cfg.name,
        "config": cfg.model_dump(mode="json"),
        "seed": seed,
        "repetition": repetition,
        "attempt": attempt,
        "challenge": {"id": challenge.id, "version": challenge.spec.version, "name": challenge.spec.name},
        "variant": variant.model_dump(mode="json"),
        "indicator_library": [
            {"variant_id": vid, "indicator": ind.model_dump(mode="json")}
            for vid, v in challenge.variants.items()
            for ind in v.indicators
        ],
        "provider": provider_desc,
        "prompt": {"profile": profile.id, "version": profile.version, "system": profile.system},
        "tools": [t.as_dict() for t in TOOL_SPECS],
        "provenance": provenance,
    })

    t0 = time.monotonic()
    status = RunStatus.COMPLETED
    recoverable = True
    error: str | None = None
    cleanup_error: str | None = None
    interrupted: BaseException | None = None
    outcome: AgentOutcome | None = None
    env: ChallengeEnvironment | None = None
    http_tool: HttpTool | None = None
    try:
        if setup_error is not None:
            raise setup_error
        assert provider is not None
        env = build_environment(cfg.environment.backend, challenge,
                                startup_timeout_s=cfg.environment.startup_timeout_s)
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
        agent = Agent(provider, [http_tool, submit_tool, terminate_tool], profile.system, cfg.agent, recorder)
        outcome = agent.run(objective)
        if outcome.stop_reason is StopReason.PROVIDER_ERROR:
            status = (RunStatus.CONFIGURATION_ERROR if outcome.error_kind == "configuration"
                      else RunStatus.PROVIDER_ERROR)
            recoverable = bool(outcome.error_recoverable)
            error = outcome.error
    except KeyboardInterrupt as exc:
        status, recoverable, error, interrupted = RunStatus.ABORTED, False, "interrupted by operator", exc
    except Exception as exc:  # noqa: BLE001 - classified and recorded; never escapes a run
        status, recoverable = classify_exception(exc)
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if http_tool is not None:
            with contextlib.suppress(Exception):
                http_tool.close()
        if env is not None:
            try:
                recorder.record(EventType.ENVIRONMENT_LOGS, {"lines": env.server_logs()})
            except Exception as exc:  # noqa: BLE001
                recorder.record(EventType.ENVIRONMENT_LOGS, {"lines": [], "error": str(exc)})
            try:
                env.stop()
            except Exception as exc:  # noqa: BLE001 - reset guarantee lost: stop the experiment
                cleanup_error = f"{type(exc).__name__}: {exc}"
        fatal = (status is not RunStatus.COMPLETED and not recoverable) or cleanup_error is not None
        recorder.record(EventType.RUN_FINISHED, {
            "status": status.value,
            "valid": status is RunStatus.COMPLETED,
            "recoverable": recoverable if status is not RunStatus.COMPLETED else None,
            "fatal": fatal,
            "stop_reason": outcome.stop_reason.value if outcome else None,
            "steps": outcome.steps if outcome else 0,
            "duration_s": round(time.monotonic() - t0, 3),
            "error": error,
            "cleanup_error": cleanup_error,
            "attempt": attempt,
        })
        recorder.close()

    metrics = evaluate_events(recorder.events)
    (run_dir / "metrics.json").write_text(metrics.model_dump_json(indent=2), encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "experiment": cfg.name, "variant": variant_id, "repetition": repetition,
        "attempt": attempt, "seed": seed, "status": status.value, "fatal": fatal,
        "provenance": provenance, "config": cfg.model_dump(mode="json"),
    }, indent=2), encoding="utf-8")
    if interrupted is not None:
        raise interrupted
    return RunResult(run_dir, metrics, status, recoverable, fatal)


# --------------------------------------------------------------------------------------------
# experiment
# --------------------------------------------------------------------------------------------
def execute_experiment(cfg: ExperimentConfig, *, on_run: Any = None,
                       flag_secret: FlagSecret | None = None) -> ExperimentReport:
    challenge, secret = preflight(cfg, flag_secret=flag_secret)
    out_dir = experiment_dir(cfg)
    out_dir.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {
        "config": cfg.model_dump(mode="json"),
        "challenge_hash": challenge.challenge_hash,
        "variant_hashes": challenge.variant_hashes,
        "pins": current_pins(cfg, challenge, secret),
        "host": host_provenance(),
        "run_order": run_order(cfg),
        "created_at": datetime.now(UTC).isoformat(),
        "status": "running",
    }
    meta_path = out_dir / "experiment.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    report = ExperimentReport(out_dir=out_dir, status="completed")
    ex = cfg.execution
    consecutive_failures = 0
    tokens_used = 0
    started = time.monotonic()

    def finalize() -> None:
        counts: dict[str, int] = {}
        for r in report.results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        meta.update({
            "status": report.status,
            "reason": report.reason,
            "finished_at": datetime.now(UTC).isoformat(),
            "attempts": len(report.results),
            "attempts_by_status": counts,
            "tokens_used": tokens_used,
            "wall_time_s": round(time.monotonic() - started, 3),
        })
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    try:
        for rep, vid in run_order(cfg):
            if ex.max_experiment_tokens is not None and tokens_used >= ex.max_experiment_tokens:
                report.status, report.reason = "budget_exhausted", f"token budget {ex.max_experiment_tokens} reached"
                break
            if (ex.max_experiment_wall_time_s is not None
                    and time.monotonic() - started >= ex.max_experiment_wall_time_s):
                report.status, report.reason = "budget_exhausted", "experiment wall-time budget reached"
                break
            for attempt in range(1, ex.max_attempts_per_run + 1):
                result = run_single(cfg, challenge, vid, rep, out_dir=out_dir,
                                    flag_secret=secret, attempt=attempt)
                with (out_dir / "runs.jsonl").open("a", encoding="utf-8") as fh:
                    fh.write(result.metrics.model_dump_json() + "\n")
                report.results.append(result)
                tokens_used += result.metrics.tokens.total_tokens or 0
                if on_run is not None:
                    on_run(result)
                if result.status is RunStatus.COMPLETED and not result.fatal:
                    consecutive_failures = 0
                    break
                if result.fatal:
                    raise _StopExperiment(
                        f"fatal {result.status.value} in {result.run_dir.name}: "
                        f"{result.metrics.error or result.metrics.cleanup_error}"
                    )
                consecutive_failures += 1
                if consecutive_failures >= ex.max_consecutive_failures:
                    raise _StopExperiment(f"{consecutive_failures} consecutive failed attempts (circuit breaker)")
    except _StopExperiment as stop:
        report.status, report.reason = "aborted", stop.reason
    except KeyboardInterrupt:
        report.status, report.reason = "aborted", "interrupted by operator"
        finalize()
        raise
    finalize()
    return report


def run_experiment(cfg: ExperimentConfig, *, on_run: Any = None,
                   flag_secret: FlagSecret | None = None) -> list[RunResult]:
    """Backward-compatible wrapper returning every attempted run (see ``execute_experiment``)."""
    return execute_experiment(cfg, on_run=on_run, flag_secret=flag_secret).results
