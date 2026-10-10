"""Offline provider validation and the single-request readiness probe."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ctf_phantom import runner as runner_mod
from ctf_phantom.config import apply_overrides, load_experiment
from ctf_phantom.providers import LLMResponse, ProviderConfig, ProviderError, ToolCall
from ctf_phantom.providers.anthropic_provider import AnthropicProvider
from ctf_phantom.providers.scripted import ScriptedProvider
from ctf_phantom.runner import preflight, probe_provider
from ctf_phantom.status import ConfigurationError
from tests.conftest import ROOT

PILOT = ROOT / "experiments/pilot/phantom_001_pilot.yaml"


def test_pilot_provider_parameters_valid_offline() -> None:
    cfg = load_experiment(PILOT)
    assert AnthropicProvider(cfg.provider).config_problems() == []


@pytest.mark.parametrize(("override", "match"), [
    ({"temperature": 0.0}, "rejects sampling"),
    ({"effort": "extreme"}, "effort"),
    ({"max_tokens": 64000}, "streaming"),
    ({"seed": 1}, "no seed"),
])
def test_invalid_anthropic_parameters_rejected(override: dict[str, Any], match: str) -> None:
    cfg = ProviderConfig(name="anthropic", model="claude-opus-5-5", effort="medium").model_copy(update=override)
    problems = AnthropicProvider(cfg).config_problems()
    assert any(match in p for p in problems), problems


def test_temperature_allowed_for_older_models() -> None:
    cfg = ProviderConfig(name="anthropic", model="claude-haiku-4-5", temperature=0.0)
    assert AnthropicProvider(cfg).config_problems() == []


def test_preflight_rejects_invalid_parameters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)  # otherwise the paid-provider CI guard fires first
    cfg = apply_overrides(load_experiment(PILOT), {"provider.temperature": 0.0, "environment.backend": "local"})
    with pytest.raises(ConfigurationError, match="rejects sampling"):
        preflight(cfg)


def _patch_provider(monkeypatch: pytest.MonkeyPatch, complete: Any) -> list[Any]:
    calls: list[Any] = []

    class _P(ScriptedProvider):
        def complete(self, system, messages, tools):  # type: ignore[no-untyped-def]
            calls.append((system, messages, tools))
            return complete()

    monkeypatch.setattr(runner_mod, "build_provider", lambda config, challenge: _P(config, []))
    return calls


def _scripted_pilot() -> Any:
    return apply_overrides(load_experiment(PILOT), {"provider.name": "scripted", "provider.model": "probe"})


def test_probe_sends_exactly_one_request_with_real_prompt_and_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_provider(monkeypatch, lambda: LLMResponse(
        text="", tool_calls=[ToolCall("1", "http_request", {"method": "GET", "url": "/"})], usage=None,
        model="m-reported", stop_reason="tool_use"))
    result = probe_provider(_scripted_pilot())
    assert len(calls) == 1
    system, messages, tools = calls[0]
    assert "capture-the-flag" in system and "127.0.0.1:9" in messages[0].content
    assert [t.name for t in tools] == ["http_request", "submit_flag", "terminate"]
    assert result["ok"] and result["reported_model"] == "m-reported" and result["tool_calls"][0]["well_formed"]


@pytest.mark.parametrize(("response", "reason"), [
    (LLMResponse(text="I can't help", tool_calls=[], usage=None, model="m", stop_reason="refusal"), "refusal"),
    (LLMResponse(text="hello", tool_calls=[], usage=None, model="m", stop_reason="end_turn"), "no tool call"),
    (LLMResponse(text="", tool_calls=[ToolCall("1", "shell", {})], usage=None, model="m", stop_reason="tool_use"),
     "unknown tool"),
])
def test_probe_fails_on_unusable_responses(monkeypatch: pytest.MonkeyPatch, response: LLMResponse, reason: str) -> None:
    _patch_provider(monkeypatch, lambda: response)
    assert probe_provider(_scripted_pilot())["ok"] is False, reason


def test_probe_reports_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> LLMResponse:
        raise ProviderError("401 invalid x-api-key", recoverable=False, status_code=401)

    _patch_provider(monkeypatch, fail)
    result = probe_provider(_scripted_pilot())
    assert result["ok"] is False and result["status_code"] == 401 and result["recoverable"] is False


def test_probe_refused_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("CTF_PHANTOM_ALLOW_PAID_RUNS", raising=False)
    with pytest.raises(ConfigurationError, match="CI"):
        probe_provider(load_experiment(PILOT))
