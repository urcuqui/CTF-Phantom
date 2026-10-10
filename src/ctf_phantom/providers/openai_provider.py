"""OpenAI Chat Completions provider. Also covers OpenAI-compatible servers (vLLM, Ollama,
OpenRouter, LM Studio) via ``base_url`` for cross-model evaluation of open-weight models."""

from __future__ import annotations

import json
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


def to_openai_messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for msg in messages:
        if msg.role == "user":
            out.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant":
            entry: dict[str, Any] = {"role": "assistant", "content": msg.content or None}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                    }
                    for c in msg.tool_calls
                ]
            out.append(entry)
        else:
            out.append({"role": "tool", "tool_call_id": msg.tool_call_id, "content": msg.content})
    return out


def to_openai_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {"name": t.name, "description": t.description,
                                          "parameters": t.input_schema}}
        for t in tools
    ]


def parse_arguments(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {"__invalid_json__": raw}
    return value if isinstance(value, dict) else {"__invalid_json__": raw}


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        try:
            import openai
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError("install the 'openai' extra: pip install -e '.[openai]'",
                                recoverable=False, kind="configuration") from exc
        self._openai = openai
        try:
            self._client = openai.OpenAI(
                timeout=config.timeout_s,
                max_retries=config.max_retries,
                base_url=config.base_url,  # None -> SDK default / env var
            )
        except openai.OpenAIError as exc:  # e.g. missing OPENAI_API_KEY
            raise ProviderError(f"openai client misconfigured: {exc}", recoverable=False,
                                kind="configuration") from exc

    def sdk_version(self) -> str | None:
        return str(self._openai.__version__)

    def build_request(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self.config.model,
            "messages": to_openai_messages(system, messages),
            "tools": to_openai_tools(tools),
        }
        # Official OpenAI uses max_completion_tokens; most compatible servers use max_tokens.
        key = "max_tokens" if self.config.base_url else "max_completion_tokens"
        params[key] = self.config.max_tokens
        if self.config.temperature is not None:
            params["temperature"] = self.config.temperature
        if self.config.seed is not None:
            params["seed"] = self.config.seed
        params.update(self.config.extra)
        return params

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        try:
            resp = self._client.chat.completions.create(**self.build_request(system, messages, tools))
        except self._openai.APIStatusError as exc:
            raise ProviderError(f"openai API error {exc.status_code}: {exc.message}",
                                recoverable=is_recoverable_status(exc.status_code),
                                status_code=exc.status_code) from exc
        except self._openai.APIConnectionError as exc:  # includes timeouts
            raise ProviderError(f"openai connection error: {exc}", recoverable=True,
                                kind="connection") from exc
        except self._openai.APIError as exc:
            raise ProviderError(f"openai API error: {exc}", recoverable=True) from exc
        choice = resp.choices[0]
        msg = choice.message
        calls = [
            ToolCall(id=tc.id, name=tc.function.name, arguments=parse_arguments(tc.function.arguments))
            for tc in (msg.tool_calls or [])
        ]
        usage = (
            TokenUsage(input_tokens=resp.usage.prompt_tokens, output_tokens=resp.usage.completion_tokens)
            if resp.usage
            else None
        )
        return LLMResponse(
            text=msg.content or "",
            tool_calls=calls,
            usage=usage,
            model=resp.model,
            stop_reason=choice.finish_reason,
            request_id=resp.id,
            extra={"system_fingerprint": getattr(resp, "system_fingerprint", None)},
        )
