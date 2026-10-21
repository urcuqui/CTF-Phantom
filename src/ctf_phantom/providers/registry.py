"""Provider factory."""

from __future__ import annotations

from pathlib import Path

import yaml

from ctf_phantom.challenges.spec import ChallengeSpec, ScriptStep
from ctf_phantom.providers.base import LLMProvider, ProviderConfig, ProviderError

PROVIDERS = ("anthropic", "openai", "scripted")


def _script_steps(config: ProviderConfig, challenge: ChallengeSpec) -> list[ScriptStep]:
    script = config.script
    if script is None or script == "reference":
        return list(challenge.reference_solution)
    if isinstance(script, str):
        data = yaml.safe_load(Path(script).read_text(encoding="utf-8"))
        return [ScriptStep.model_validate(s) for s in data]
    return [ScriptStep.model_validate(s) for s in script]


def build_provider(config: ProviderConfig, challenge: ChallengeSpec) -> LLMProvider:
    if config.name == "anthropic":
        from ctf_phantom.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(config)
    if config.name == "openai":
        from ctf_phantom.providers.openai_provider import OpenAIProvider

        return OpenAIProvider(config)
    if config.name == "scripted":
        from ctf_phantom.providers.scripted import ScriptedProvider

        try:
            steps = _script_steps(config, challenge)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise ProviderError(f"invalid scripted policy {config.script!r}: {exc}",
                                recoverable=False, kind="configuration") from exc
        return ScriptedProvider(config, steps)
    raise ProviderError(f"unknown provider {config.name!r}; available: {', '.join(PROVIDERS)}",
                        recoverable=False, kind="configuration")
