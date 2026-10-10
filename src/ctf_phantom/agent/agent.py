"""Minimal single-agent ReAct-style loop over native tool calling.

Deliberately simple: no memory persistence, no planning modules, no multi-agent orchestration.
Every model turn, tool call and tool output is traced so behaviour can be audited post hoc.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ctf_phantom.agent.prompts import NO_TOOL_NUDGE
from ctf_phantom.hashing import sha256_json
from ctf_phantom.providers.base import LLMProvider, Message, ProviderError
from ctf_phantom.tools.base import Tool, ToolResult
from ctf_phantom.tracing import EventType, TraceRecorder


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_steps: int = Field(30, gt=0)               # model turns
    max_flag_submissions: int = Field(3, gt=0)
    max_observation_chars: int = Field(6000, gt=200)
    max_consecutive_no_tool: int = Field(2, ge=0)
    max_total_tokens: int | None = None            # optional budget across the episode
    prompt_profile: str = "standard"
    request_timeout_s: float = 10.0


class StopReason(StrEnum):
    FLAG_CORRECT = "flag_correct"
    SUBMISSIONS_EXHAUSTED = "submissions_exhausted"
    TERMINATED = "terminated"
    MAX_STEPS = "max_steps"
    TOKEN_BUDGET = "token_budget"
    NO_TOOL_CALLS = "no_tool_calls"
    REFUSAL = "refusal"
    PROVIDER_ERROR = "provider_error"


@dataclass
class AgentOutcome:
    stop_reason: StopReason
    steps: int
    error: str | None = None


class Agent:
    def __init__(
        self,
        provider: LLMProvider,
        tools: list[Tool],
        system_prompt: str,
        config: AgentConfig,
        recorder: TraceRecorder,
    ) -> None:
        self.provider = provider
        self.tools = {t.spec.name: t for t in tools}
        self.tool_specs = [t.spec for t in tools]
        self.system_prompt = system_prompt
        self.config = config
        self.recorder = recorder
        self.messages: list[Message] = []

    def run(self, objective: str) -> AgentOutcome:
        self.messages = [Message(role="user", content=objective)]
        tokens_used = 0
        no_tool_streak = 0

        for step in range(1, self.config.max_steps + 1):
            self.recorder.record(EventType.LLM_REQUEST, {
                "message_count": len(self.messages),
                "messages_sha256": sha256_json([m.fingerprint() for m in self.messages]),
            }, step=step)
            t0 = time.monotonic()
            try:
                resp = self.provider.complete(self.system_prompt, self.messages, self.tool_specs)
            except ProviderError as exc:
                self.recorder.record(EventType.LLM_ERROR, {
                    "error_type": type(exc).__name__, "message": str(exc)}, step=step)
                return AgentOutcome(StopReason.PROVIDER_ERROR, step, str(exc))
            latency = time.monotonic() - t0

            self.recorder.record(EventType.LLM_RESPONSE, {
                "text": resp.text,
                "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments} for c in resp.tool_calls],
                "usage": None if resp.usage is None else {
                    "input_tokens": resp.usage.input_tokens,
                    "output_tokens": resp.usage.output_tokens,
                    "cache_read_input_tokens": resp.usage.cache_read_input_tokens,
                    "cache_creation_input_tokens": resp.usage.cache_creation_input_tokens,
                },
                "model": resp.model,
                "stop_reason": resp.stop_reason,
                "request_id": resp.request_id,
                "latency_s": round(latency, 4),
                "extra": resp.extra,
            }, step=step)

            self.messages.append(Message(
                role="assistant", content=resp.text, tool_calls=list(resp.tool_calls),
                provider_payload=resp.provider_payload,
            ))
            if resp.usage and resp.usage.total_tokens is not None:
                tokens_used += resp.usage.total_tokens

            if resp.stop_reason == "refusal":
                return AgentOutcome(StopReason.REFUSAL, step)

            if not resp.tool_calls:
                no_tool_streak += 1
                if no_tool_streak > self.config.max_consecutive_no_tool:
                    return AgentOutcome(StopReason.NO_TOOL_CALLS, step)
                self.recorder.record(EventType.AGENT_NOTE, {"message": NO_TOOL_NUDGE}, step=step)
                self.messages.append(Message(role="user", content=NO_TOOL_NUDGE))
                continue
            no_tool_streak = 0

            terminal: StopReason | None = None
            for call in resp.tool_calls:
                result = self._execute(call.id, call.name, call.arguments, step)
                self.messages.append(Message(
                    role="tool", content=result.observation, tool_call_id=call.id,
                    tool_name=call.name, is_error=not result.ok,
                ))
                if result.terminal and terminal is None:
                    terminal = self._terminal_reason(call.name, result)
            # All tool results of a turn are returned before stopping, keeping the transcript valid.
            if terminal is not None:
                return AgentOutcome(terminal, step)

            if self.config.max_total_tokens is not None and tokens_used >= self.config.max_total_tokens:
                return AgentOutcome(StopReason.TOKEN_BUDGET, step)

        return AgentOutcome(StopReason.MAX_STEPS, self.config.max_steps)

    def _execute(self, call_id: str, name: str, arguments: dict[str, Any], step: int) -> ToolResult:
        self.recorder.record(EventType.TOOL_CALL, {
            "call_id": call_id, "name": name, "arguments": arguments}, step=step)
        tool = self.tools.get(name)
        if tool is None:
            result = ToolResult(ok=False, observation=f"Error: unknown tool {name!r}.")
        elif "__invalid_json__" in arguments:
            result = ToolResult(ok=False, observation="Error: tool arguments were not valid JSON.")
        else:
            try:
                result = tool(arguments)
            except Exception as exc:  # noqa: BLE001 - tool errors are observations, not crashes
                result = ToolResult(ok=False, observation=f"Error: {type(exc).__name__}: {exc}")

        self.recorder.record(EventType.TOOL_RESULT, {
            "call_id": call_id,
            "name": name,
            "ok": result.ok,
            "observation": result.observation,
            "observation_chars": len(result.observation),
            "raw_chars": result.raw_chars,
            "truncated": result.truncated,
            "terminal": result.terminal,
            "meta": json.loads(json.dumps(result.meta, default=str)),
        }, step=step)
        if sv := result.meta.get("scope_violation"):
            self.recorder.record(EventType.SCOPE_VIOLATION, {"call_id": call_id, **sv}, step=step)
        if name == "submit_flag" and "correct" in result.meta:
            self.recorder.record(EventType.FLAG_SUBMISSION, {
                "call_id": call_id, **{k: result.meta[k] for k in
                                       ("submitted", "correct", "well_formed", "submission_index")},
            }, step=step)
        return result

    @staticmethod
    def _terminal_reason(name: str, result: ToolResult) -> StopReason:
        if name == "submit_flag":
            return StopReason.FLAG_CORRECT if result.meta.get("correct") else StopReason.SUBMISSIONS_EXHAUSTED
        return StopReason.TERMINATED
