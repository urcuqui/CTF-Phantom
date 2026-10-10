"""Provider-neutral conversation types and the LLM provider interface.

Adding a provider = subclass ``LLMProvider`` and register it in ``providers/registry.py``.
The agent loop never sees provider-specific types; native assistant content needed for faithful
replay (e.g. Anthropic thinking blocks) is carried opaquely in ``provider_payload``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ctf_phantom.tools.base import ToolSpec


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    role: Literal["user", "assistant", "tool"]
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    tool_name: str | None = None
    is_error: bool = False
    provider_payload: Any = None

    def fingerprint(self) -> dict[str, Any]:
        """Serializable view used for hashing the request context."""
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls],
            "tool_call_id": self.tool_call_id,
        }


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_input_tokens: int | None = None
    cache_creation_input_tokens: int | None = None

    @property
    def total_tokens(self) -> int | None:
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return (self.input_tokens or 0) + (self.output_tokens or 0)


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    usage: TokenUsage | None
    model: str                         # model id reported by the provider (may differ from requested)
    stop_reason: str | None
    request_id: str | None = None
    provider_payload: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "anthropic"
    model: str = "claude-opus-5-5"
    max_tokens: int = 16000
    # Sampling parameters are sent only when set; some models reject them outright.
    temperature: float | None = None
    seed: int | None = None
    effort: str | None = None          # Anthropic output_config.effort (low|medium|high|xhigh|max)
    base_url: str | None = None        # OpenAI-compatible endpoints
    timeout_s: float = 300.0
    max_retries: int = 3
    extra: dict[str, Any] = Field(default_factory=dict)  # passed through to the provider request
    # Scripted provider only: "reference" (challenge's reference solution) or inline steps.
    script: str | list[dict[str, Any]] | None = None


class ProviderError(RuntimeError):
    """A failure to obtain a model turn. Never a property of the agent's behaviour.

    ``recoverable`` distinguishes transient infrastructure failures (rate limits, overload,
    timeouts, 5xx) that justify retrying the run, from configuration failures (bad credentials,
    unknown model, invalid request, missing SDK) that will fail identically on every run.
    """

    def __init__(self, message: str, *, recoverable: bool, status_code: int | None = None,
                 kind: str = "api") -> None:
        super().__init__(message)
        self.recoverable = recoverable
        self.status_code = status_code
        self.kind = kind  # api | connection | configuration | injected


def is_recoverable_status(status_code: int | None) -> bool:
    return status_code is None or status_code in (408, 409, 429) or status_code >= 500


class LLMProvider(abc.ABC):
    name: str

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Return the next assistant turn. Must not mutate ``messages``."""

    def describe(self) -> dict[str, Any]:
        """Provenance recorded in the trace (exclude secrets)."""
        return {
            "provider": self.name,
            "requested_model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "seed": self.config.seed,
            "effort": self.config.effort,
            "base_url": self.config.base_url,
            "extra": self.config.extra,
            "sdk_version": self.sdk_version(),
        }

    def sdk_version(self) -> str | None:
        return None
