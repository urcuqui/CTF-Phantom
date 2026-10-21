"""Provider message conversion (pure functions; no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ctf_phantom.providers import Message, ProviderConfig, ToolCall
from ctf_phantom.providers.anthropic_provider import to_anthropic_messages
from ctf_phantom.providers.openai_provider import (
    parse_arguments,
    to_openai_messages,
    to_openai_tools,
)
from ctf_phantom.providers.registry import build_provider
from ctf_phantom.providers.scripted import ScriptedProvider
from ctf_phantom.tools import HttpTool

CONVO = [
    Message(role="user", content="objective"),
    Message(role="assistant", content="thinking aloud", tool_calls=[
        ToolCall("t1", "http_request", {"method": "GET", "url": "/"}),
        ToolCall("t2", "http_request", {"method": "GET", "url": "/login"}),
    ]),
    Message(role="tool", content="page1", tool_call_id="t1", tool_name="http_request"),
    Message(role="tool", content="err", tool_call_id="t2", tool_name="http_request", is_error=True),
    Message(role="user", content="nudge"),
]


def test_anthropic_merges_parallel_tool_results_into_one_user_turn() -> None:
    out = to_anthropic_messages(CONVO)
    assert [m["role"] for m in out] == ["user", "assistant", "user", "user"]
    assistant = out[1]["content"]
    assert assistant[0] == {"type": "text", "text": "thinking aloud"}
    assert [b["id"] for b in assistant[1:]] == ["t1", "t2"]
    results = out[2]["content"]
    assert [b["tool_use_id"] for b in results] == ["t1", "t2"]
    assert "is_error" not in results[0] and results[1]["is_error"] is True


def test_anthropic_replays_native_payload_unchanged() -> None:
    native = [{"type": "thinking", "thinking": "", "signature": "sig"},
              {"type": "tool_use", "id": "t1", "name": "x", "input": {}}]
    out = to_anthropic_messages([Message(role="assistant", provider_payload=native)])
    assert out[0]["content"] is native


def test_openai_conversion() -> None:
    out = to_openai_messages("sys", CONVO)
    assert out[0] == {"role": "system", "content": "sys"}
    assert out[2]["tool_calls"][0]["function"]["arguments"] == '{"method": "GET", "url": "/"}'
    assert out[3] == {"role": "tool", "tool_call_id": "t1", "content": "page1"}
    tools = to_openai_tools([HttpTool.spec])
    assert tools[0]["function"]["name"] == "http_request"


def test_openai_argument_parsing() -> None:
    assert parse_arguments('{"a": 1}') == {"a": 1}
    assert parse_arguments("") == {}
    assert "__invalid_json__" in parse_arguments("{bad")
    assert "__invalid_json__" in parse_arguments("[1]")


def test_anthropic_request_omits_unset_sampling_params(challenge) -> None:  # type: ignore[no-untyped-def]
    from ctf_phantom.providers.anthropic_provider import AnthropicProvider

    p = AnthropicProvider(ProviderConfig(name="anthropic", model="claude-opus-5-5", effort="medium"))
    req = p.build_request("sys", CONVO, [HttpTool.spec])
    assert "temperature" not in req
    assert req["output_config"] == {"effort": "medium"}
    assert req["model"] == "claude-opus-5-5" and req["system"] == "sys"


def test_scripted_extracts_from_last_observation(challenge) -> None:  # type: ignore[no-untyped-def]
    p = build_provider(ProviderConfig(name="scripted", model="reference", script="reference"), challenge.spec)
    assert isinstance(p, ScriptedProvider)
    msgs: list[Message] = []
    for _ in range(4):
        r = p.complete("", msgs, [])
        assert r.usage is None and r.tool_calls[0].name == "http_request"
    msgs.append(Message(role="tool", content="secret: PHANTOM{0123456789abcdef01234567}", tool_call_id="x"))
    r = p.complete("", msgs, [])
    assert r.tool_calls[0].arguments == {"flag": "PHANTOM{0123456789abcdef01234567}"}
    assert p.complete("", msgs, []).tool_calls == []


# --------------------------------------------- OpenAI-compatible assistant message shapes
# Ollama rejects content: null on an assistant turn without tool calls, and also a missing
# content there ("invalid message content type: <nil>"); see tests/regression/test_openai_null_content.py.
def _assistant_entries(out: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [m for m in out if m["role"] == "assistant"]


def _assert_no_null_content(out: list[dict[str, Any]]) -> None:
    for m in out:
        assert m.get("content", "") is not None, m
        if m["role"] != "assistant" or not m.get("tool_calls"):
            assert isinstance(m["content"], str), m


def test_openai_tool_only_turn_omits_content() -> None:
    out = to_openai_messages("sys", [
        Message(role="user", content="objective"),
        Message(role="assistant", tool_calls=[ToolCall("c1", "http_request", {"method": "GET", "url": "/"})]),
    ])
    assert _assistant_entries(out) == [{
        "role": "assistant",
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "http_request", "arguments": '{"method": "GET", "url": "/"}'}}],
    }]


def test_openai_multiple_tool_calls_keep_ids_names_arguments_and_order() -> None:
    calls = [ToolCall("c1", "http_request", {"method": "GET", "url": "/"}),
             ToolCall("c2", "submit_flag", {"flag": "PHANTOM{x}"}),
             ToolCall("c3", "http_request", {"method": "POST", "url": "/login", "data": {"u": "ü"}})]
    out = to_openai_messages("sys", [Message(role="user", content="o"), Message(role="assistant", tool_calls=calls)])
    (entry,) = _assistant_entries(out)
    assert "content" not in entry
    assert [(t["id"], t["type"], t["function"]["name"]) for t in entry["tool_calls"]] == [
        ("c1", "function", "http_request"), ("c2", "function", "submit_flag"), ("c3", "function", "http_request")]
    assert [json.loads(t["function"]["arguments"]) for t in entry["tool_calls"]] == [c.arguments for c in calls]


def test_openai_tool_results_follow_their_calls() -> None:
    out = to_openai_messages("sys", CONVO)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool", "tool", "user"]
    assert out[3] == {"role": "tool", "tool_call_id": "t1", "content": "page1"}
    assert out[4] == {"role": "tool", "tool_call_id": "t2", "content": "err"}
    assert [t["id"] for t in out[2]["tool_calls"]] == ["t1", "t2"]
    # An empty observation is still a string, never null.
    empty = to_openai_messages("sys", [Message(role="tool", content="", tool_call_id="t9")])
    assert empty[1] == {"role": "tool", "tool_call_id": "t9", "content": ""}


def test_openai_mixed_text_and_tool_calls_keep_text() -> None:
    out = to_openai_messages("sys", CONVO)
    assert out[2]["content"] == "thinking aloud"
    assert list(out[2]) == ["role", "content", "tool_calls"]


def test_openai_text_only_turn_sends_text() -> None:
    out = to_openai_messages("sys", [Message(role="user", content="o"), Message(role="assistant", content="done")])
    assert _assistant_entries(out) == [{"role": "assistant", "content": "done"}]


def test_openai_empty_assistant_turn_sends_empty_string() -> None:
    # A reasoning-only reply (thinking stripped by the server) yields no text and no tool calls.
    out = to_openai_messages("sys", [Message(role="user", content="o"), Message(role="assistant"),
                                     Message(role="user", content="nudge")])
    assert _assistant_entries(out) == [{"role": "assistant", "content": ""}]
    _assert_no_null_content(out)


def _sdk_roundtrip(base_url: str | None, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], Any]:
    """Send CONVO plus an empty turn through the real openai SDK with a mocked transport."""
    import httpx
    import openai

    from ctf_phantom.providers.openai_provider import OpenAIProvider

    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "id": "r1", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "c9", "type": "function",
                                "function": {"name": "http_request", "arguments": '{"url": "/"}'}}]}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        })

    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    provider = OpenAIProvider(ProviderConfig(name="openai", model="m", base_url=base_url, max_retries=0))
    provider._client = openai.OpenAI(api_key="test-not-a-real-key", base_url=base_url, max_retries=0,
                                     http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    history = [*CONVO, Message(role="assistant"), Message(role="user", content="nudge")]
    resp = provider.complete("sys", history, [HttpTool.spec])
    return captured, resp


@pytest.mark.parametrize("base_url", [None, "http://127.0.0.1:11434/v1"], ids=["official", "compatible"])
def test_openai_sdk_request_and_response(base_url: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    captured, resp = _sdk_roundtrip(base_url, monkeypatch)
    body = captured["body"]
    if base_url is None:
        assert captured["url"].startswith("https://api.openai.com/v1/chat/completions")
        assert "max_completion_tokens" in body and "max_tokens" not in body
    else:
        assert captured["url"].startswith(base_url) and "max_tokens" in body
    _assert_no_null_content(body["messages"])
    assert body["messages"] == to_openai_messages("sys", [*CONVO, Message(role="assistant"),
                                                          Message(role="user", content="nudge")])
    # A tool-call-only response (content: null) parses to empty text, not None.
    assert resp.text == "" and resp.tool_calls == [ToolCall("c9", "http_request", {"url": "/"})]
