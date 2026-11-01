"""The Sonnet 5.5 qualification config must stay valid, fully pinned, budgeted and pilot-consistent,
and its requests must match Sonnet 5.5's API surface."""

from __future__ import annotations

import pytest

from ctf_phantom.config import apply_overrides, load_experiment
from ctf_phantom.providers import Message, ProviderConfig, ToolCall
from ctf_phantom.providers.anthropic_provider import (
    MAX_NON_STREAMING_TOKENS,
    AnthropicProvider,
    to_anthropic_messages,
)
from ctf_phantom.runner import current_pins, preflight, run_order
from ctf_phantom.status import ConfigurationError
from ctf_phantom.tools import TOOL_SPECS
from tests.conftest import ROOT

QUALIFICATION = ROOT / "experiments/pilot/phantom_001_sonnet55_qualification.yaml"
PILOT = ROOT / "experiments/pilot/phantom_001_pilot.yaml"


@pytest.fixture
def qual():  # type: ignore[no-untyped-def]
    return load_experiment(QUALIFICATION)


def test_qualification_design(qual) -> None:  # type: ignore[no-untyped-def]
    assert qual.name == "phantom_001_sonnet55_qualification_v1"
    assert qual.challenge == "phantom_001" and qual.variants == ["baseline"]
    assert qual.repetitions == 5 and qual.seed == 20261010
    assert (qual.provider.name, qual.provider.model) == ("anthropic", "claude-sonnet-5-5")
    assert qual.environment.backend == "docker"
    assert qual.execution.require_provider_check


def test_qualification_keeps_pilot_methodology(qual) -> None:  # type: ignore[no-untyped-def]
    pilot = load_experiment(PILOT)
    assert qual.agent == pilot.agent
    assert qual.seed == pilot.seed and qual.flag_salt == pilot.flag_salt
    assert qual.environment == pilot.environment


def test_request_matches_sonnet55_api_surface(qual) -> None:  # type: ignore[no-untyped-def]
    provider = AnthropicProvider(qual.provider)
    assert provider.config_problems() == []
    request = provider.build_request("system", [Message(role="user", content="objective")], list(TOOL_SPECS))
    assert request["model"] == "claude-sonnet-5-5"
    assert request["output_config"] == {"effort": "medium"}  # pinned; the API default is `high`
    assert "thinking" not in request  # omitted = adaptive; `disabled` is a 400 on this model
    assert not {"temperature", "top_p", "top_k", "seed", "tool_choice", "fallbacks", "betas"} & request.keys()
    # Thinking counts against max_tokens; the adapter is non-streaming.
    assert 8000 <= request["max_tokens"] <= MAX_NON_STREAMING_TOKENS


@pytest.mark.parametrize("override", [{"temperature": 0.0}, {"seed": 1}, {"effort": "extreme"}])
def test_sonnet55_rejects_unsupported_parameters_offline(override: dict[str, object]) -> None:
    cfg = ProviderConfig(name="anthropic", model="claude-sonnet-5-5", effort="medium").model_copy(update=override)
    assert AnthropicProvider(cfg).config_problems()


def test_replayed_history_is_append_only() -> None:
    """Preserved thinking: earlier API messages must be byte-identical when the transcript grows."""
    payload = [{"type": "thinking", "thinking": "", "signature": "sig"},
               {"type": "tool_use", "id": "t1", "name": "http_request", "input": {"path": "/"}}]
    turn1 = [Message(role="user", content="objective"),
             Message(role="assistant", tool_calls=[ToolCall("t1", "http_request", {"path": "/"})],
                     provider_payload=payload),
             Message(role="tool", content="200 OK", tool_call_id="t1")]
    turn2 = [*turn1, Message(role="assistant", content="done", provider_payload=[{"type": "text", "text": "done"}]),
             Message(role="user", content="nudge")]
    first, second = to_anthropic_messages(turn1), to_anthropic_messages(turn2)
    assert second[:len(first)] == first
    assert second[1]["content"] is payload  # native blocks (incl. thinking) replayed unchanged


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
