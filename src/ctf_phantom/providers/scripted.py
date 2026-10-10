"""Deterministic scripted "provider" for pipeline validation and calibration.

Not a model: it replays a fixed list of tool calls. Uses:
  * ``script: reference`` - the challenge's ground-truth solution; validates that every variant
    remains solvable through the identical path and that the harness records it correctly.
  * inline steps - synthetic policies (e.g. an agent that obeys an injection) used to verify
    that evaluation detectors fire, and do not fire, when they should.

A step's ``args`` may contain the literal string ``$EXTRACT``, replaced by the first match of
``extract_regex`` in the most recent tool observation.
"""

from __future__ import annotations

import re
from typing import Any

from ctf_phantom.challenges.spec import ScriptStep
from ctf_phantom.providers.base import LLMProvider, LLMResponse, Message, ProviderConfig, ToolCall
from ctf_phantom.tools.base import ToolSpec


class ScriptedProvider(LLMProvider):
    name = "scripted"

    def __init__(self, config: ProviderConfig, steps: list[ScriptStep]) -> None:
        super().__init__(config)
        self.steps = steps
        self._cursor = 0

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        if self._cursor >= len(self.steps):
            return LLMResponse(text="[script exhausted]", tool_calls=[], usage=None,
                               model=f"scripted/{self.config.model}", stop_reason="end_turn")
        step = self.steps[self._cursor]
        self._cursor += 1
        args = self._materialize(step, messages)
        return LLMResponse(
            text="",
            tool_calls=[ToolCall(id=f"scripted_{self._cursor}", name=step.tool, arguments=args)],
            usage=None,  # token usage is genuinely unavailable for scripted runs
            model=f"scripted/{self.config.model}",
            stop_reason="tool_use",
        )

    def _materialize(self, step: ScriptStep, messages: list[Message]) -> dict[str, Any]:
        if not step.extract_regex:
            return dict(step.args)
        last_obs = next((m.content for m in reversed(messages) if m.role == "tool"), "")
        match = re.search(step.extract_regex, last_obs)
        value = match.group(0) if match else ""
        return {k: (value if v == "$EXTRACT" else v) for k, v in step.args.items()}

    def describe(self) -> dict[str, Any]:
        return super().describe() | {"script_steps": [s.model_dump() for s in self.steps]}
