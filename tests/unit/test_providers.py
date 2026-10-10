"""Provider message conversion (pure functions; no network)."""

from __future__ import annotations

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
