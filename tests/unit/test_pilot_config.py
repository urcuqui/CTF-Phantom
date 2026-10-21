"""The committed pilot configuration must stay valid, fully pinned, budgeted and paired."""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_phantom.config import apply_overrides, load_experiment
from ctf_phantom.runner import current_pins, preflight, run_order
from ctf_phantom.status import ConfigurationError
from tests.conftest import ROOT

PILOT = ROOT / "experiments/pilot/phantom_001_pilot.yaml"


@pytest.fixture
def pilot():  # type: ignore[no-untyped-def]
    return load_experiment(PILOT)


def test_pilot_design(pilot) -> None:  # type: ignore[no-untyped-def]
    assert pilot.variants == ["baseline", "benign_control", "deception", "prompt_injection"]
    assert pilot.repetitions == 10
    assert pilot.provider.name == "anthropic" and pilot.provider.model
    assert pilot.provider.effort  # pinned, not left to the model default
    assert pilot.agent.prompt_profile == "standard"
    assert pilot.environment.backend == "docker"


def test_pilot_has_explicit_budgets(pilot) -> None:  # type: ignore[no-untyped-def]
    assert pilot.agent.max_steps and pilot.agent.max_flag_submissions
    assert pilot.agent.max_total_tokens and pilot.agent.max_wall_time_s
    assert pilot.execution.max_experiment_tokens and pilot.execution.max_experiment_wall_time_s
    assert pilot.execution.max_attempts_per_run >= 1 and pilot.execution.max_consecutive_failures >= 1


def test_pilot_is_paired_and_blocked(pilot) -> None:  # type: ignore[no-untyped-def]
    order = run_order(pilot)
    assert len(order) == 40
    for rep in range(10):
        assert sorted(v for r, v in order if r == rep) == sorted(pilot.variants)
    assert order == run_order(pilot)  # deterministic


def test_pilot_pins_match_repository(pilot) -> None:  # type: ignore[no-untyped-def]
    """Fails if the challenge, payloads, prompt or tools changed without re-pinning."""
    pins = pilot.pins.model_dump(exclude_none=True)
    assert set(pins) >= {"challenge_hash", "variant_hashes", "system_prompt_sha256", "tool_specs_sha256"}
    offline = apply_overrides(pilot, {"provider.name": "scripted", "provider.model": "reference",
                                      "environment.backend": "local"})
    challenge, secret = preflight(offline)  # raises ConfigurationError on any mismatch
    current = current_pins(offline, challenge, secret)
    for key in ("challenge_hash", "variant_hashes", "system_prompt_sha256", "tool_specs_sha256"):
        assert pins[key] == current[key]


def test_pilot_refused_in_ci(pilot, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("CTF_PHANTOM_ALLOW_PAID_RUNS", raising=False)
    with pytest.raises(ConfigurationError, match="CI"):
        preflight(pilot)


def test_pilot_path() -> None:
    assert isinstance(PILOT, Path) and PILOT.is_file()
