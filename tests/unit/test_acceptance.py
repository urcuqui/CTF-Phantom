"""Pilot acceptance (A1-A10) is separate from execution status and evaluated from artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ctf_phantom import runner as runner_mod
from ctf_phantom.config import ExperimentConfig, PinsConfig
from ctf_phantom.environments import EnvironmentInfo, LocalEnvironment
from ctf_phantom.evaluation import check_acceptance
from ctf_phantom.runner import current_pins, execute_experiment, preflight
from tests.conftest import ROOT

IMAGES = {"challenge": "sha256:" + "a" * 64, "gateway": "sha256:" + "b" * 64}
VARIANTS = ["baseline", "benign_control", "deception", "prompt_injection"]


class _DockerLikeEnv(LocalEnvironment):
    """Local server that reports itself the way the verified docker backend does."""

    images = dict(IMAGES)

    def start(self, **kw: Any) -> EnvironmentInfo:
        info = super().start(**kw)
        return EnvironmentInfo("docker", info.base_url, info.startup_s,
                               {"egress_blocked": True, "images": dict(type(self).images)})


@pytest.fixture
def docker_like(monkeypatch: pytest.MonkeyPatch) -> None:
    _DockerLikeEnv.images = dict(IMAGES)
    monkeypatch.setattr(runner_mod, "build_environment", lambda b, c, *, startup_timeout_s, build=True:
                        _DockerLikeEnv(c, startup_timeout_s=startup_timeout_s))
    monkeypatch.setattr(runner_mod, "prepare_backend", lambda b, c: (dict(IMAGES), {}))  # legacy: engine IDs only
    monkeypatch.setattr(runner_mod, "git_state", lambda: {"commit": "abc", "dirty": False})


def _cfg(results: Path, *, script: Any = "reference", pinned: bool = True, reps: int = 2,
         execution: dict[str, Any] | None = None) -> ExperimentConfig:
    cfg = ExperimentConfig.model_validate({
        "name": "acc", "challenge": "phantom_001", "variants": VARIANTS, "repetitions": reps, "seed": 11,
        "environment": {"backend": "local"}, "execution": execution or {},
        "provider": {"name": "scripted", "model": "t", "script": script}, "output_dir": str(results),
    })
    if pinned:
        challenge, secret = preflight(cfg)
        cfg = cfg.model_copy(update={"pins": PinsConfig.model_validate(current_pins(cfg, challenge, secret))})
    return cfg


def _status(result: dict[str, Any]) -> dict[str, str]:
    return {c["id"]: c["status"] for c in result["criteria"]}


def test_clean_reference_experiment_is_accepted(results_tmp: Path, docker_like: None) -> None:
    report = execute_experiment(_cfg(results_tmp))
    assert report.status == "completed"
    result = check_acceptance(report.out_dir)
    assert result["verdict"] == "accepted", result["criteria"]
    assert set(_status(result).values()) == {"pass"}


def test_execution_complete_but_not_accepted(results_tmp: Path, docker_like: None) -> None:
    """Every planned run valid (execution completed) yet rejected: controls show false positives."""
    report = execute_experiment(_cfg(results_tmp, script=str(ROOT / "experiments/scripts/injection_follower.yaml")))
    assert report.status == "completed" and report.complete
    result = check_acceptance(report.out_dir)
    s = _status(result)
    assert result["verdict"] == "rejected"
    assert s["A1"] == s["A2"] == "pass"
    assert s["A5"] == "fail" and s["A6"] == "fail"  # control FP; baseline never completes
    assert s["A10"] == "manual" and result["criteria"][9]["detail"]["runs_to_audit"]


def test_local_backend_runs_fail_isolation_criterion(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "git_state", lambda: {"commit": "abc", "dirty": False})
    report = execute_experiment(_cfg(results_tmp, reps=1))
    result = check_acceptance(report.out_dir)
    a4 = next(c for c in result["criteria"] if c["id"] == "A4")
    assert a4["status"] == "fail" and "backend_not_docker" in a4["detail"]


@pytest.mark.parametrize("problem", ["dirty", "unpinned", "images"])
def test_provenance_violations_fail_a4(results_tmp: Path, docker_like: None, monkeypatch: pytest.MonkeyPatch,
                                       problem: str) -> None:
    if problem == "dirty":
        monkeypatch.setattr(runner_mod, "git_state", lambda: {"commit": "abc", "dirty": True})
    if problem == "images":
        _DockerLikeEnv.images = {"challenge": "sha256:" + "c" * 64, "gateway": "sha256:" + "b" * 64}
    report = execute_experiment(_cfg(results_tmp, reps=1, pinned=problem != "unpinned"))
    a4 = next(c for c in check_acceptance(report.out_dir)["criteria"] if c["id"] == "A4")
    expected = {"dirty": "git_dirty_or_unknown", "unpinned": "pins_not_set", "images": "images_differ_from_experiment"}
    assert a4["status"] == "fail" and expected[problem] in a4["detail"]


def test_incomplete_execution_fails_a2_not_a1(results_tmp: Path, docker_like: None) -> None:
    script = [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": True}}]
    report = execute_experiment(_cfg(results_tmp, reps=1, script=script,
                                     execution={"max_attempts_per_run": 1, "max_consecutive_failures": 10}))
    assert report.status == "incomplete"
    s = _status(check_acceptance(report.out_dir))
    assert s["A1"] == "pass" and s["A2"] == "fail"


def test_aborted_execution_fails_a1(results_tmp: Path, docker_like: None) -> None:
    script = [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": False}}]
    report = execute_experiment(_cfg(results_tmp, reps=1, script=script))
    assert report.status == "aborted"
    assert _status(check_acceptance(report.out_dir))["A1"] == "fail"


def test_tampered_metrics_and_flag_leak_detected(results_tmp: Path, docker_like: None) -> None:
    report = execute_experiment(_cfg(results_tmp, reps=1))
    run_dir = report.results[0].run_dir
    metrics = json.loads((run_dir / "metrics.json").read_text())
    metrics["challenge_completed"] = not metrics["challenge_completed"]
    (run_dir / "metrics.json").write_text(json.dumps(metrics))
    (report.out_dir / "notes.txt").write_text("PHANTOM{0123456789abcdef01234567}")
    s = _status(check_acceptance(report.out_dir))
    assert s["A8"] == "fail" and s["A9"] == "fail"


def test_reserved_decoy_is_not_a_leak(results_tmp: Path, docker_like: None) -> None:
    report = execute_experiment(_cfg(results_tmp, reps=1,
                                     script=str(ROOT / "experiments/scripts/decoy_follower.yaml")))
    assert _status(check_acceptance(report.out_dir))["A9"] == "pass"
