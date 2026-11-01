"""The Sonnet 4.5 qualification config must stay valid, fully pinned, budgeted and pilot-consistent."""

from __future__ import annotations

import pytest

from ctf_phantom.config import apply_overrides, load_experiment
from ctf_phantom.providers import Message
from ctf_phantom.providers.anthropic_provider import AnthropicProvider
from ctf_phantom.runner import current_pins, preflight, run_order
from ctf_phantom.status import ConfigurationError
from ctf_phantom.tools import TOOL_SPECS
from tests.conftest import ROOT

QUALIFICATION = ROOT / "experiments/pilot/phantom_001_sonnet45_qualification.yaml"
PILOT = ROOT / "experiments/pilot/phantom_001_pilot.yaml"


@pytest.fixture
def qual():  # type: ignore[no-untyped-def]
    return load_experiment(QUALIFICATION)


def test_qualification_design(qual) -> None:  # type: ignore[no-untyped-def]
    assert qual.name == "phantom_001_sonnet45_qualification_v1"
    assert qual.challenge == "phantom_001" and qual.variants == ["baseline"]
    assert qual.repetitions == 5 and qual.seed == 20261010
    assert (qual.provider.name, qual.provider.model) == ("anthropic", "claude-sonnet-4-5-20250929")
    assert qual.provider.max_tokens == 4096
    assert qual.environment.backend == "docker"
    assert qual.execution.require_provider_check


def test_qualification_keeps_pilot_methodology(qual) -> None:  # type: ignore[no-untyped-def]
    pilot = load_experiment(PILOT)
    assert qual.agent == pilot.agent
    assert qual.seed == pilot.seed and qual.flag_salt == pilot.flag_salt
    assert qual.environment == pilot.environment


def test_request_carries_no_unsupported_parameters(qual) -> None:  # type: ignore[no-untyped-def]
    provider = AnthropicProvider(qual.provider)
    assert provider.config_problems() == []
    request = provider.build_request("system", [Message(role="user", content="objective")], list(TOOL_SPECS))
    assert "output_config" not in request  # Sonnet 4.5 rejects effort
    assert not {"temperature", "top_p", "top_k", "seed"} & request.keys()
    assert request["model"] == "claude-sonnet-4-5-20250929" and request["max_tokens"] == 4096


def test_qualification_budgets_cover_every_attempt(qual) -> None:  # type: ignore[no-untyped-def]
    a, ex = qual.agent, qual.execution
    attempts = len(run_order(qual)) * ex.max_attempts_per_run
    assert a.max_total_tokens and a.max_wall_time_s
    assert ex.max_experiment_tokens is not None and ex.max_experiment_wall_time_s is not None
    assert attempts * a.max_total_tokens <= ex.max_experiment_tokens
    assert attempts * (a.max_wall_time_s + qual.environment.startup_timeout_s) <= ex.max_experiment_wall_time_s


def test_qualification_pins_match_repository(qual) -> None:  # type: ignore[no-untyped-def]
    """Fails if the challenge, baseline variant, prompt or tools changed without re-pinning."""
    pins = qual.pins.model_dump(exclude_none=True)
    assert set(pins) >= {"challenge_hash", "variant_hashes", "system_prompt_sha256", "tool_specs_sha256"}
    assert set(pins["variant_hashes"]) == set(qual.variants)
    # The fingerprint is per operator; tests run with their own secret, so compare the rest.
    offline = apply_overrides(qual, {"provider.name": "scripted", "provider.model": "reference",
                                     "environment.backend": "local"})
    offline = offline.model_copy(update={"pins": offline.pins.model_copy(update={"flag_secret_fingerprint": None})})
    challenge, secret = preflight(offline)  # raises ConfigurationError on any mismatch
    current = current_pins(offline, challenge, secret)
    for key in ("challenge_hash", "variant_hashes", "system_prompt_sha256", "tool_specs_sha256"):
        assert pins[key] == current[key]


def test_qualification_refused_in_ci(qual, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("CTF_PHANTOM_ALLOW_PAID_RUNS", raising=False)
    with pytest.raises(ConfigurationError, match="CI"):
        preflight(qual)
