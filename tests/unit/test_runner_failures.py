"""Failure handling: classification, retries, circuit breaker, safe stops, guaranteed cleanup."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from ctf_phantom import runner as runner_mod
from ctf_phantom.agent import Agent
from ctf_phantom.challenges.spec import ScriptStep
from ctf_phantom.config import ExperimentConfig
from ctf_phantom.environments import (
    BackendUnavailableError,
    CleanupError,
    EnvironmentError_,
    IsolationError,
    LocalEnvironment,
)
from ctf_phantom.evaluation import evaluate_trace, summarize
from ctf_phantom.providers import ProviderConfig, ProviderError, TokenUsage
from ctf_phantom.providers.scripted import ScriptedProvider
from ctf_phantom.runner import classify_exception, current_pins, execute_experiment, preflight
from ctf_phantom.status import ConfigurationError, RunStatus
from ctf_phantom.tracing import EventType, read_trace


def _cfg(results: Path, variants: list[str] | None = None, *, reps: int = 1, script: Any = "reference",
         execution: dict[str, Any] | None = None, agent: dict[str, Any] | None = None,
         provider: dict[str, Any] | None = None, environment: dict[str, Any] | None = None,
         **extra: Any) -> ExperimentConfig:
    return ExperimentConfig.model_validate({
        "name": "fail",
        "challenge": "phantom_001",
        "variants": variants or ["baseline"],
        "repetitions": reps,
        "seed": 7,
        "shuffle_variants": False,
        "environment": environment or {"backend": "local"},
        "agent": agent or {},
        "execution": execution or {},
        "provider": provider or {"name": "scripted", "model": "t", "script": script},
        "output_dir": str(results),
        **extra,
    })


def _statuses(results: list[runner_mod.RunResult]) -> list[str]:
    return [r.status.value for r in results]


def _experiment_meta(results: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((results / "fail" / "experiment.json").read_text())
    return data


def _assert_trace_complete(run_dir: Path, status: str) -> None:
    events = read_trace(run_dir / "trace.jsonl")
    assert events[0].type is EventType.RUN_STARTED
    assert events[-1].type is EventType.RUN_FINISHED
    assert events[-1].data["status"] == status
    assert (run_dir / "metrics.json").is_file() and (run_dir / "manifest.json").is_file()


class _FlakyFactory:
    """build_provider replacement: provider instances listed in ``fail_instances`` raise on first call.

    Instance 0 is created by preflight (never asked for a completion).
    """

    def __init__(self, fail_instances: set[int], *, recoverable: bool = True, status_code: int | None = 503,
                 kind: str = "api", usage: TokenUsage | None = None, sleep_s: float = 0.0) -> None:
        self.fail_instances = fail_instances
        self.recoverable = recoverable
        self.status_code = status_code
        self.kind = kind
        self.usage = usage
        self.sleep_s = sleep_s
        self.created = 0

    def __call__(self, config: ProviderConfig, challenge: Any) -> ScriptedProvider:
        index = self.created
        self.created += 1
        factory = self

        class _P(ScriptedProvider):
            def complete(self, system, messages, tools):  # type: ignore[no-untyped-def]
                if index in factory.fail_instances:
                    raise ProviderError("simulated", recoverable=factory.recoverable,
                                        status_code=factory.status_code, kind=factory.kind)
                time.sleep(factory.sleep_s)
                resp = super().complete(system, messages, tools)
                resp.usage = factory.usage
                return resp

        return _P(config, list(challenge.reference_solution))


class _FakeEnv(LocalEnvironment):
    start_error: BaseException | None = None
    stop_error: BaseException | None = None
    stops = 0

    def start(self, **kw: Any):  # type: ignore[no-untyped-def]
        if type(self).start_error is not None:
            raise type(self).start_error
        return super().start(**kw)

    def stop(self) -> None:
        type(self).stops += 1
        super().stop()
        if type(self).stop_error is not None:
            raise type(self).stop_error


@pytest.fixture
def fake_env(monkeypatch: pytest.MonkeyPatch) -> type[_FakeEnv]:
    _FakeEnv.start_error = None
    _FakeEnv.stop_error = None
    _FakeEnv.stops = 0
    monkeypatch.setattr(runner_mod, "build_environment",
                        lambda backend, challenge, *, startup_timeout_s, build=True:
                        _FakeEnv(challenge, startup_timeout_s=startup_timeout_s))
    return _FakeEnv


# ---------------------------------------------------------------------------- classification
@pytest.mark.parametrize(("exc", "status", "recoverable"), [
    (ConfigurationError("x"), RunStatus.CONFIGURATION_ERROR, False),
    (ProviderError("x", recoverable=True, status_code=529), RunStatus.PROVIDER_ERROR, True),
    (ProviderError("x", recoverable=False, status_code=401), RunStatus.PROVIDER_ERROR, False),
    (ProviderError("x", recoverable=False, kind="configuration"), RunStatus.CONFIGURATION_ERROR, False),
    (IsolationError("x"), RunStatus.ISOLATION_FAILURE, False),
    (BackendUnavailableError("x"), RunStatus.ENVIRONMENT_ERROR, False),
    (CleanupError("x"), RunStatus.ENVIRONMENT_ERROR, False),
    (EnvironmentError_("x"), RunStatus.ENVIRONMENT_ERROR, True),
    (RuntimeError("bug"), RunStatus.HARNESS_ERROR, True),
])
def test_classify_exception(exc: BaseException, status: RunStatus, recoverable: bool) -> None:
    assert classify_exception(exc) == (status, recoverable)


@pytest.mark.parametrize(("code", "recoverable"), [(400, False), (401, False), (403, False), (404, False),
                                                   (408, True), (429, True), (500, True), (529, True)])
def test_status_code_recoverability(code: int, recoverable: bool) -> None:
    from ctf_phantom.providers.base import is_recoverable_status

    assert is_recoverable_status(code) is recoverable


# ---------------------------------------------------------------------------- provider failures
def test_recoverable_provider_error_is_retried_and_excluded(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory({1}))
    report = execute_experiment(_cfg(results_tmp))
    assert report.status == "completed"
    assert _statuses(report.results) == ["provider_error", "completed"]
    failed, ok = report.results
    _assert_trace_complete(failed.run_dir, "provider_error")
    assert failed.recoverable and not failed.fatal
    # Infrastructure failure is NOT a failed CTF attempt.
    assert failed.metrics.valid is False
    assert failed.metrics.challenge_completed is None and failed.metrics.attack_outcome == "invalid"
    assert ok.metrics.valid and ok.metrics.challenge_completed and ok.metrics.attempt == 2
    assert failed.metrics.seed == ok.metrics.seed  # retries reuse the seed
    lines = (results_tmp / "fail" / "runs.jsonl").read_text().splitlines()
    assert len(lines) == 2  # every attempt is recorded
    (row,) = summarize([failed.metrics, ok.metrics])
    assert row["runs"] == 1 and row["attempted_runs"] == 2 and row["excluded"] == {"provider_error": 1}
    assert row["completion"]["k"] == 1 and row["completion"]["n"] == 1


def test_non_recoverable_provider_error_stops_experiment(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory({1, 2, 3}, recoverable=False, status_code=401))
    report = execute_experiment(_cfg(results_tmp, ["baseline", "deception"], reps=2))
    assert report.status == "aborted" and "provider_error" in (report.reason or "")
    assert _statuses(report.results) == ["provider_error"]
    assert report.results[0].fatal
    meta = _experiment_meta(results_tmp)
    assert meta["status"] == "aborted" and meta["attempts_by_status"] == {"provider_error": 1}


def test_recoverable_failures_continue_with_next_repetition(results_tmp: Path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory({1, 2}))
    report = execute_experiment(_cfg(results_tmp, reps=2, execution={"max_attempts_per_run": 2,
                                                                        "max_consecutive_failures": 5}))
    # Execution finished, but one planned run has no valid attempt: never reported as "completed".
    assert report.status == "incomplete"
    assert _statuses(report.results) == ["provider_error", "provider_error", "completed"]
    assert [r.metrics.repetition for r in report.results] == [0, 0, 1]
    assert (report.planned_runs, report.attempted_runs, report.attempts, report.valid_runs) == (2, 2, 3, 1)
    assert [(p.repetition, p.outcome) for p in report.exhausted_retries] == [(0, "retries_exhausted")]
    execution = _experiment_meta(results_tmp)["execution"]
    assert execution["complete"] is False and execution["invalid_attempts"] == 2
    assert len(execution["missing_valid_runs"]) == 1 and len(execution["attempt_log"]) == 3


def test_circuit_breaker(results_tmp: Path) -> None:
    script = [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": True}}]
    report = execute_experiment(_cfg(results_tmp, reps=5, script=script,
                                     execution={"max_attempts_per_run": 2, "max_consecutive_failures": 3}))
    assert report.status == "aborted" and "circuit breaker" in (report.reason or "")
    assert len(report.results) == 3
    for r in report.results:
        _assert_trace_complete(r.run_dir, "provider_error")


def test_provider_config_error_from_scripted_injection(results_tmp: Path) -> None:
    script = [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": False, "status_code": 404}}]
    report = execute_experiment(_cfg(results_tmp, reps=3, script=script))
    assert report.status == "aborted" and len(report.results) == 1
    events = read_trace(report.results[0].run_dir / "trace.jsonl")
    err = next(e for e in events if e.type is EventType.LLM_ERROR)
    assert err.data["recoverable"] is False and err.data["status_code"] == 404


# ---------------------------------------------------------------------------- environment failures
def test_environment_start_failure_is_recoverable_and_cleaned_up(results_tmp: Path, fake_env: type[_FakeEnv]) -> None:
    fake_env.start_error = EnvironmentError_("compose up timed out")
    report = execute_experiment(_cfg(results_tmp, execution={"max_attempts_per_run": 2,
                                                             "max_consecutive_failures": 5}))
    assert _statuses(report.results) == ["environment_error", "environment_error"]
    assert fake_env.stops == 2  # cleanup ran for every attempt
    assert report.status == "incomplete" and report.valid_runs == 0
    for r in report.results:
        _assert_trace_complete(r.run_dir, "environment_error")
        assert r.metrics.valid is False


def test_isolation_failure_stops_before_agent_runs(results_tmp: Path, fake_env: type[_FakeEnv]) -> None:
    fake_env.start_error = IsolationError("challenge container has egress")
    report = execute_experiment(_cfg(results_tmp, ["baseline", "deception"], reps=3))
    assert report.status == "aborted" and _statuses(report.results) == ["isolation_failure"]
    assert fake_env.stops == 1
    events = read_trace(report.results[0].run_dir / "trace.jsonl")
    assert not any(e.type in (EventType.LLM_REQUEST, EventType.TOOL_CALL) for e in events)


def _three_way(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    finished = read_trace(run_dir / "trace.jsonl")[-1].data
    metrics = json.loads((run_dir / "metrics.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    return finished, metrics, manifest


def test_cleanup_failure_after_successful_episode_is_invalid_and_fatal(results_tmp: Path,
                                                                       fake_env: type[_FakeEnv]) -> None:
    fake_env.stop_error = CleanupError("compose down failed")
    report = execute_experiment(_cfg(results_tmp, reps=3))
    assert report.status == "aborted" and len(report.results) == 1
    (r,) = report.results
    assert r.status is RunStatus.CLEANUP_FAILURE and r.fatal and not r.recoverable
    assert r.metrics.valid is False and r.metrics.challenge_completed is None
    assert r.metrics.stop_reason == "flag_correct"  # the episode itself finished; kept as evidence
    finished, metrics, manifest = _three_way(r.run_dir)
    for view in (finished, manifest):
        assert view["status"] == metrics["run_status"] == "cleanup_failure"
        assert view["valid"] is metrics["valid"] is False
        assert view["fatal"] is metrics["fatal"] is True
        assert view["cleanup_error"] == metrics["cleanup_error"] == "CleanupError: compose down failed"
    assert manifest["recoverable"] is metrics["recoverable_failure"] is False
    assert report.planned[0].outcome == "failed_fatal"
    assert [p.outcome for p in report.planned[1:]] == ["not_attempted", "not_attempted"]
    (row,) = summarize([r.metrics])
    assert row["runs"] == 0 and row["excluded"] == {"cleanup_failure": 1}


def test_cleanup_failure_after_failed_episode_keeps_primary_status(results_tmp: Path,
                                                                   fake_env: type[_FakeEnv]) -> None:
    fake_env.start_error = EnvironmentError_("compose up failed")
    fake_env.stop_error = RuntimeError("docker socket gone")  # any teardown exception counts
    report = execute_experiment(_cfg(results_tmp, reps=2))
    (r,) = report.results
    assert r.status is RunStatus.ENVIRONMENT_ERROR and r.fatal and report.status == "aborted"
    finished, metrics, manifest = _three_way(r.run_dir)
    assert finished["status"] == metrics["run_status"] == manifest["status"] == "environment_error"
    assert finished["cleanup_error"] == metrics["cleanup_error"] == manifest["cleanup_error"]
    assert finished["recoverable"] is False and finished["fatal"] is True


def test_status_validity_agree_for_every_run(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory({1}))
    report = execute_experiment(_cfg(results_tmp, ["baseline", "deception"]))
    for r in report.results:
        finished, metrics, manifest = _three_way(r.run_dir)
        assert finished["status"] == metrics["run_status"] == manifest["status"]
        assert finished["valid"] is metrics["valid"] is manifest["valid"]
        assert finished["fatal"] is metrics["fatal"] is manifest["fatal"]


# ---------------------------------------------------------------------------- harness failures
def test_harness_exception_recorded_and_env_stopped(results_tmp: Path, fake_env: type[_FakeEnv],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self: Agent, objective: str) -> Any:
        raise RuntimeError("bug in harness")

    monkeypatch.setattr(Agent, "run", boom)
    report = execute_experiment(_cfg(results_tmp, execution={"max_attempts_per_run": 1}))
    (r,) = report.results
    assert r.status is RunStatus.HARNESS_ERROR and "bug in harness" in (r.metrics.error or "")
    assert fake_env.stops == 1
    _assert_trace_complete(r.run_dir, "harness_error")


def test_keyboard_interrupt_records_aborted_and_reraises(results_tmp: Path, fake_env: type[_FakeEnv],
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(self: Agent, objective: str) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(Agent, "run", interrupt)
    with pytest.raises(KeyboardInterrupt):
        execute_experiment(_cfg(results_tmp, reps=2))
    assert fake_env.stops == 1
    (run_dir,) = [p for p in (results_tmp / "fail").iterdir() if p.is_dir()]
    _assert_trace_complete(run_dir, "aborted")
    meta = _experiment_meta(results_tmp)
    assert meta["status"] == "aborted"
    # The interrupted attempt is still recorded as diagnostic evidence.
    assert len((results_tmp / "fail" / "runs.jsonl").read_text().splitlines()) == 1
    assert [a["status"] for a in meta["execution"]["attempt_log"]] == ["aborted"]
    assert len(meta["execution"]["not_attempted"]) == 1


# ---------------------------------------------------------------------------- preflight
@pytest.mark.parametrize("bad", [
    {"variants": ["nope"]},
    {"agent": {"prompt_profile": "nope"}},
    {"script": "/nonexistent/policy.yaml"},
    {"pins": {"challenge_hash": "0" * 64}},
    {"pins": {"variant_hashes": {"baseline": "0" * 64}}},
    {"pins": {"flag_secret_fingerprint": "deadbeefdeadbeef"}},
])
def test_preflight_rejects_bad_config_before_any_run(results_tmp: Path, bad: dict[str, Any]) -> None:
    kw: dict[str, Any] = dict(bad)
    variants = kw.pop("variants", None)
    cfg = _cfg(results_tmp, variants, **kw)
    with pytest.raises(ConfigurationError):
        execute_experiment(cfg)
    assert not (results_tmp / "fail").exists()


def test_preflight_refuses_paid_provider_in_ci(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    monkeypatch.delenv("CTF_PHANTOM_ALLOW_PAID_RUNS", raising=False)
    cfg = _cfg(results_tmp, provider={"name": "anthropic", "model": "claude-opus-5-5"})
    with pytest.raises(ConfigurationError, match="CI"):
        preflight(cfg)


def test_matching_pins_pass(results_tmp: Path, secret: Any) -> None:
    cfg = _cfg(results_tmp, ["baseline", "deception"])
    challenge, _ = preflight(cfg)
    pinned = cfg.model_copy(update={"pins": cfg.pins.model_validate(current_pins(cfg, challenge, secret))})
    preflight(pinned)


# ---------------------------------------------------------------------------- budgets
# Reference solution = 5 model calls; with usage (100 in, 10 out) a full run bills 550 tokens.
@pytest.mark.parametrize(("cap", "runs"), [(1150, 2), (1149, 1), (600, 1), (1700, 3)])
def test_experiment_token_budget_boundary(results_tmp: Path, monkeypatch: pytest.MonkeyPatch,
                                          cap: int, runs: int) -> None:
    """A run starts only if remaining >= per-run cap (600): 1150-550 = 600 starts, 1149-550 does not."""
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory(set(), usage=TokenUsage(100, 10)))
    report = execute_experiment(_cfg(results_tmp, reps=3, agent={"max_total_tokens": 600},
                                     execution={"max_experiment_tokens": cap}))
    assert len(report.results) == runs
    assert all(r.billable_tokens == 550 for r in report.results)
    total = sum(r.billable_tokens for r in report.results)
    assert total <= cap  # never crossed by a whole run
    expected = "completed" if runs == 3 else "budget_exhausted"
    assert report.status == expected
    meta = _experiment_meta(results_tmp)
    assert meta["status"] == expected and meta["tokens_used"] == total
    if runs < 3:
        assert len(meta["execution"]["not_attempted"]) == 3 - runs


def test_retries_respect_experiment_budget(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    factory = _FlakyFactory(set(), usage=TokenUsage(100, 10))
    script = [{"tool": "http_request", "args": {"method": "GET", "url": "/"}},
              {"tool": "$PROVIDER_ERROR", "args": {"recoverable": True}}]

    def build(config: ProviderConfig, challenge: Any) -> ScriptedProvider:
        p = factory(config, challenge)
        p.steps = [ScriptStep.model_validate(x) for x in script]  # type: ignore[attr-defined]
        return p

    monkeypatch.setattr(runner_mod, "build_provider", build)
    report = execute_experiment(_cfg(results_tmp, reps=2, agent={"max_total_tokens": 600},
                                     execution={"max_experiment_tokens": 700, "max_attempts_per_run": 3,
                                                "max_consecutive_failures": 9}))
    # attempt 1 bills 110 -> remaining 590 < 600: no retry is started.
    assert len(report.results) == 1 and report.status == "budget_exhausted"
    assert report.planned[0].outcome == "attempted_invalid"


def test_cache_tokens_count_toward_budgets(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=10, cache_read_input_tokens=80, cache_creation_input_tokens=0)
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory(set(), usage=usage))
    report = execute_experiment(_cfg(results_tmp, agent={"max_total_tokens": 200}))
    (r,) = report.results
    # 100 billable per call: stops before the 3rd request although input+output is only 40.
    assert r.metrics.stop_reason == "token_budget" and r.billable_tokens == 200
    assert r.metrics.tokens.total_tokens == 40  # evaluation schema unchanged (input + output)


@pytest.mark.parametrize(("cap", "requests", "stop"), [(220, 2, "token_budget"), (221, 3, "token_budget"),
                                                         (10_000, 5, "flag_correct")])
def test_agent_token_budget_is_checked_before_each_request(results_tmp: Path, monkeypatch: pytest.MonkeyPatch,
                                                           cap: int, requests: int, stop: str) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory(set(), usage=TokenUsage(100, 10)))
    report = execute_experiment(_cfg(results_tmp, agent={"max_total_tokens": cap}))
    (r,) = report.results
    events = read_trace(r.run_dir / "trace.jsonl")
    assert sum(e.type is EventType.LLM_REQUEST for e in events) == requests
    assert r.metrics.stop_reason == stop and r.metrics.valid
    if stop == "token_budget":
        note = [e for e in events if e.type is EventType.AGENT_NOTE and e.data.get("budget") == "tokens"]
        assert note and note[0].data["limit"] == cap and r.metrics.steps == requests


def test_token_budget_applies_to_turns_without_tool_calls(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    factory = _FlakyFactory(set(), usage=TokenUsage(100, 10))

    def build(config: ProviderConfig, challenge: Any) -> ScriptedProvider:
        p = factory(config, challenge)
        p.steps = []  # type: ignore[attr-defined]  # every turn: no tool call
        return p

    monkeypatch.setattr(runner_mod, "build_provider", build)
    report = execute_experiment(_cfg(results_tmp, agent={"max_total_tokens": 220, "max_consecutive_no_tool": 10}))
    (r,) = report.results
    assert r.metrics.stop_reason == "token_budget"
    assert sum(e.type is EventType.LLM_REQUEST for e in read_trace(r.run_dir / "trace.jsonl")) == 2


def test_max_steps_is_hard(results_tmp: Path) -> None:
    report = execute_experiment(_cfg(results_tmp, agent={"max_steps": 2}))
    (r,) = report.results
    assert r.metrics.stop_reason == "max_steps"
    assert sum(e.type is EventType.LLM_REQUEST for e in read_trace(r.run_dir / "trace.jsonl")) == 2


@pytest.mark.parametrize(("elapsed", "blocked"), [(0.0, False), (100.0, False), (100.001, True), (500.0, True)])
def test_experiment_wall_budget_boundary(results_tmp: Path, elapsed: float, blocked: bool) -> None:
    # need = agent wall (300) + startup timeout (100) = 400; cap 500 -> starts while elapsed <= 100.
    cfg = _cfg(results_tmp, agent={"max_wall_time_s": 300}, environment={"backend": "local", "startup_timeout_s": 100},
               execution={"max_experiment_wall_time_s": 500})
    assert (runner_mod._budget_block(cfg, 0, elapsed) is not None) is blocked


@pytest.mark.parametrize(("agent", "execution", "match"), [
    ({}, {"max_experiment_tokens": 1000}, "requires agent.max_total_tokens"),
    ({"max_total_tokens": 2000}, {"max_experiment_tokens": 1000}, "exceeds"),
    ({}, {"max_experiment_wall_time_s": 1000}, "requires agent.max_wall_time_s"),
    ({"max_wall_time_s": 990}, {"max_experiment_wall_time_s": 1000}, "worst case"),
])
def test_unenforceable_budgets_rejected(results_tmp: Path, agent: dict[str, Any], execution: dict[str, Any],
                                        match: str) -> None:
    with pytest.raises(ConfigurationError, match=match):
        preflight(_cfg(results_tmp, agent=agent, execution=execution))


def test_existing_experiment_directory_is_never_reused(results_tmp: Path) -> None:
    execute_experiment(_cfg(results_tmp))
    with pytest.raises(ConfigurationError, match="already contains runs"):
        execute_experiment(_cfg(results_tmp))


def test_completed_experiment_reports_full_execution(results_tmp: Path) -> None:
    report = execute_experiment(_cfg(results_tmp, ["baseline", "deception"], reps=2))
    assert report.status == "completed" and report.complete
    ex = _experiment_meta(results_tmp)["execution"]
    assert (ex["planned_runs"], ex["attempted_runs"], ex["attempts"], ex["valid_runs"]) == (4, 4, 4, 4)
    assert ex["missing_valid_runs"] == [] and ex["invalid_attempts"] == 0
    assert "not evaluated" in _experiment_meta(results_tmp)["acceptance"]


def test_agent_wall_time_budget_is_a_valid_stop(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "build_provider", _FlakyFactory(set(), sleep_s=0.05))
    report = execute_experiment(_cfg(results_tmp, agent={"max_wall_time_s": 0.08}))
    (r,) = report.results
    assert r.metrics.valid and r.metrics.stop_reason == "time_budget"
    assert r.metrics.challenge_completed is False  # a budget stop IS a failed attempt (agent-side)


def test_reevaluation_matches_recorded_metrics_for_failed_runs(results_tmp: Path) -> None:
    script = [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": True}}]
    report = execute_experiment(_cfg(results_tmp, script=script, execution={"max_attempts_per_run": 1}))
    (r,) = report.results
    assert evaluate_trace(r.run_dir / "trace.jsonl") == r.metrics
