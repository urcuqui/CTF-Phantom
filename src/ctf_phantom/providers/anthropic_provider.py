"""Anthropic Messages API provider (manual tool-use loop; the agent owns the loop for tracing).

Server-side model fallbacks are deliberately NOT enabled: a silent fallback would change the
victim model mid-episode and confound cross-model comparisons. Refusals surface as
``stop_reason == "refusal"`` and are recorded as such.
"""

from __future__ import annotations

import re
from typing import Any

from ctf_phantom.providers.base import (
    LLMProvider,
    LLMResponse,
    Message,
    ProviderConfig,
    ProviderError,
    TokenUsage,
    ToolCall,
    is_recoverable_status,
)
from ctf_phantom.tools.base import ToolSpec


def to_anthropic_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Convert neutral messages; consecutive tool results are merged into ONE user turn."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "user":
            out.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant":
            if msg.provider_payload is not None:
                content: Any = msg.provider_payload  # native blocks incl. thinking, unchanged
            else:
                content = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                content.extend(
                    {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                    for c in msg.tool_calls
                )
            out.append({"role": "assistant", "content": content})
        else:
            block = {
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id,
                "content": msg.content,
                **({"is_error": True} if msg.is_error else {}),
            }
            prev = out[-1] if out else None
            if (
                prev is not None
                and prev["role"] == "user"
                and isinstance(prev["content"], list)
                and all(b.get("type") == "tool_result" for b in prev["content"])
            ):
                prev["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


def to_anthropic_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [t.as_dict() for t in tools]


EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
# Models that reject non-default sampling parameters (temperature/top_p/top_k) with a 400.
_NO_SAMPLING = re.compile(r"^claude-(opus-(4-[78]|5)|sonnet-5|fable-5|mythos-5|haiku-5)")
# The Python SDK refuses non-streaming requests whose max_tokens implies > 10 min (~21,333 tokens).
MAX_NON_STREAMING_TOKENS = 21_333


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def config_problems(self) -> list[str]:
        c = self.config
        problems = []
        if not c.model:
            problems.append("model is required")
        if c.effort is not None and c.effort not in EFFORT_LEVELS:
            problems.append(f"effort {c.effort!r} not in {EFFORT_LEVELS}")
        if c.temperature is not None and _NO_SAMPLING.match(c.model):
            problems.append(f"{c.model} rejects sampling parameters; leave temperature unset")
        if c.max_tokens > MAX_NON_STREAMING_TOKENS:
            problems.append(f"max_tokens {c.max_tokens} > {MAX_NON_STREAMING_TOKENS} requires streaming, "
                            "which this provider does not use")
        if c.seed is not None:
            problems.append("the Anthropic API has no seed parameter; leave provider.seed unset")
        return problems

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError("install the 'anthropic' extra: pip install -e '.[anthropic]'",
                                recoverable=False, kind="configuration") from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(
            timeout=config.timeout_s,
            max_retries=config.max_retries,
            base_url=config.base_url,  # None -> SDK default / env var
        )

    def sdk_version(self) -> str | None:
        return str(self._anthropic.__version__)

    def build_request(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": to_anthropic_messages(messages),
            "tools": to_anthropic_tools(tools),
        }
        if self.config.temperature is not None:
            params["temperature"] = self.config.temperature
        if self.config.effort:
            params["output_config"] = {"effort": self.config.effort}
        params.update(self.config.extra)
        return params

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        params = self.build_request(system, messages, tools)
        try:
            resp = self._client.messages.create(**params)
        except self._anthropic.APIStatusError as exc:
            raise ProviderError(f"anthropic API error {exc.status_code}: {exc.message}",
                                recoverable=is_recoverable_status(exc.status_code),
                                status_code=exc.status_code) from exc
        except self._anthropic.APIConnectionError as exc:  # includes timeouts
            raise ProviderError(f"anthropic connection error: {exc}", recoverable=True,
                                kind="connection") from exc
        except TypeError as exc:  # raised by the SDK when no credentials can be resolved
            raise ProviderError(
                f"anthropic client misconfigured ({exc}); set ANTHROPIC_API_KEY or run `ant auth login`",
                recoverable=False, kind="configuration",
            ) from exc

        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [
            ToolCall(id=b.id, name=b.name, arguments=dict(b.input))
            for b in resp.content
            if b.type == "tool_use"
        ]
        u = resp.usage
        usage = TokenUsage(
            input_tokens=u.input_tokens,
            output_tokens=u.output_tokens,
            cache_read_input_tokens=getattr(u, "cache_read_input_tokens", None),
            cache_creation_input_tokens=getattr(u, "cache_creation_input_tokens", None),
        )
        stop_details = getattr(resp, "stop_details", None)
        return LLMResponse(
            text=text,
            tool_calls=calls,
            usage=usage,
            model=resp.model,
            stop_reason=resp.stop_reason,
            request_id=getattr(resp, "_request_id", None),
            provider_payload=resp.content,
            extra={
                "message_id": resp.id,
                "block_types": [b.type for b in resp.content],
                **({"stop_details": stop_details.model_dump()} if stop_details else {}),
            },
        )
