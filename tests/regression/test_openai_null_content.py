"""Regression: phantom_001_qwen3_8b_calibration_v1 (benign_control, 2026-10-21) failed at step 6 with
``openai API error 400: invalid message content type: <nil>``.

Steps 1-4 were tool-call-only turns (accepted). Step 5 was a reasoning-only reply: Ollama strips
qwen3's thinking, so it arrived with no text and no tool calls. The harness then serialised that
turn as ``{"role": "assistant", "content": null}``, which Ollama 0.40.4 rejects. Ollama accepts
null or missing content only alongside ``tool_calls``; probed against the live server:

    content null    + tool_calls -> 200     content null    , no tool_calls -> 400
    content omitted + tool_calls -> 200     content omitted , no tool_calls -> 400
    content ""      + tool_calls -> 200     content ""      , no tool_calls -> 200

The mock transport below enforces exactly that rule, and the agent replays the failing sequence
through the real openai SDK.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ctf_phantom.agent.agent import Agent, AgentConfig, StopReason
from ctf_phantom.agent.prompts import NO_TOOL_NUDGE
from ctf_phantom.providers import ProviderConfig
from ctf_phantom.tools.base import ToolResult, ToolSpec
from ctf_phantom.tools.control import TerminateTool
from ctf_phantom.tracing import EventType, TraceRecorder

httpx = pytest.importorskip("httpx")
openai = pytest.importorskip("openai")

PROBE_SPEC = ToolSpec(name="http_request", description="probe",
                      input_schema={"type": "object", "properties": {"url": {"type": "string"}}})


class ProbeTool:
    spec = PROBE_SPEC

    def __call__(self, arguments: dict[str, Any]) -> ToolResult:
        return ToolResult(ok=True, observation=f"HTTP 200 for {arguments.get('url')}")


def ollama_rejects(messages: list[dict[str, Any]]) -> bool:
    """Ollama 0.40.4's OpenAI-compat check: content must be a string unless tool_calls are present."""
    return any(m["role"] == "assistant" and not m.get("tool_calls") and not isinstance(m.get("content"), str)
               for m in messages)


def _tool_turn(i: int, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"role": "assistant", "content": "",
            "tool_calls": [{"id": f"call_{i}", "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)}}]}


# The calibration run's response sequence: four tool-only turns, one empty turn, then a recovery.
SCRIPT = [
    *(_tool_turn(i, "http_request", {"url": f"/p{i}"}) for i in range(1, 5)),
    {"role": "assistant", "content": ""},
    _tool_turn(6, "terminate", {"reason": "done"}),
]


def run_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, list[Any], list[list[dict[str, Any]]]]:
    from ctf_phantom.providers.openai_provider import OpenAIProvider

    sent: list[list[dict[str, Any]]] = []

    def handler(request: Any) -> Any:
        messages = json.loads(request.content)["messages"]
        sent.append(messages)
        if ollama_rejects(messages):
            return httpx.Response(400, json={"error": {"message": "invalid message content type: <nil>",
                                                       "type": "invalid_request_error", "param": None,
                                                       "code": None}})
        return httpx.Response(200, json={
            "id": f"chatcmpl-{len(sent)}", "object": "chat.completion", "created": 0, "model": "qwen3:8b",
            "system_fingerprint": "fp_ollama",
            "choices": [{"index": 0, "finish_reason": "stop", "message": SCRIPT[len(sent) - 1]}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        })

    base_url = "http://127.0.0.1:11434/v1"
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    provider = OpenAIProvider(ProviderConfig(name="openai", model="qwen3:8b", base_url=base_url, max_retries=0))
    provider._client = openai.OpenAI(api_key="ollama", base_url=base_url, max_retries=0,
                                     http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    with TraceRecorder(tmp_path / "trace.jsonl", "regression") as rec:
        agent = Agent(provider, [ProbeTool(), TerminateTool()], "sys", AgentConfig(max_steps=10), rec)
        outcome = agent.run("objective")
        events = list(rec.events)
    return outcome, events, sent


def test_empty_turn_after_tool_turns_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outcome, events, sent = run_agent(tmp_path, monkeypatch)
    assert not [e for e in events if e.type == EventType.LLM_ERROR], outcome.error
    assert outcome.stop_reason == StopReason.TERMINATED and outcome.steps == 6
    assert len([e for e in events if e.type == EventType.TOOL_CALL]) == 5

    # Step 6's request is the one that failed: 11 messages, the empty turn serialised as "".
    final = sent[5]
    assert len(final) == 12  # system + the 11 harness messages the trace reported
    assert final[-2] == {"role": "assistant", "content": ""}
    assert final[-1] == {"role": "user", "content": NO_TOOL_NUDGE}
    for i, msg in enumerate(final[2:10:2], start=1):
        assert msg == {"role": "assistant", "tool_calls": SCRIPT[i - 1]["tool_calls"]}
    assert [m["tool_call_id"] for m in final if m["role"] == "tool"] == [f"call_{i}" for i in range(1, 5)]
    assert all(m.get("content", "") is not None for request in sent for m in request)


def test_mock_reproduces_the_original_failure() -> None:
    """Guards the mock: the pre-fix serialisation of the step-6 history is rejected."""
    old_empty_turn = {"role": "assistant", "content": None}
    old_tool_turn = {"role": "assistant", "content": None, "tool_calls": SCRIPT[0]["tool_calls"]}
    assert not ollama_rejects([old_tool_turn])
    assert ollama_rejects([old_tool_turn, old_empty_turn])
    assert ollama_rejects([{"role": "assistant"}])
    assert not ollama_rejects([{"role": "assistant", "content": ""}])
