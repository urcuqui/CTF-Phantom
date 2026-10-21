"""Live multi-turn tool calling against a local Ollama server through the OpenAI-compatible provider.

Opt-in (no Phantom challenge, no paid API): skipped unless CTF_PHANTOM_OLLAMA_MODEL is set and the
server answers. Example:

    CTF_PHANTOM_OLLAMA_MODEL=qwen3:8b .venv/bin/python -m pytest -m ollama -q
    # CTF_PHANTOM_OLLAMA_BASE_URL defaults to http://127.0.0.1:11434/v1
"""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from ctf_phantom.agent.agent import Agent, AgentConfig, StopReason
from ctf_phantom.agent.prompts import NO_TOOL_NUDGE
from ctf_phantom.providers import Message, ProviderConfig, ToolCall
from ctf_phantom.tools.base import ToolResult, ToolSpec
from ctf_phantom.tools.control import TerminateTool
from ctf_phantom.tracing import EventType, TraceRecorder

MODEL = os.environ.get("CTF_PHANTOM_OLLAMA_MODEL")
BASE_URL = os.environ.get("CTF_PHANTOM_OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")


def _ollama_up() -> bool:
    try:
        with urllib.request.urlopen(BASE_URL.rstrip("/") + "/models", timeout=3):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.ollama,
    pytest.mark.integration,
    pytest.mark.skipif(not MODEL, reason="set CTF_PHANTOM_OLLAMA_MODEL to run live Ollama tests"),
    pytest.mark.skipif(bool(MODEL) and not _ollama_up(), reason=f"no Ollama server at {BASE_URL}"),
]

# A chain the model can only finish by calling the tool once per hop: >= 4 consecutive tool turns.
CHAIN = {"start": "alpha", "alpha": "bravo", "bravo": "charlie", "charlie": None}

CLUE_SPEC = ToolSpec(
    name="next_clue",
    description="Return the next key in the chain for the given key.",
    input_schema={"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"],
                  "additionalProperties": False},
)


class ClueTool:
    spec = CLUE_SPEC

    def __call__(self, arguments: dict[str, Any]) -> ToolResult:
        key = str(arguments.get("key", "")).strip().lower()
        if key not in CHAIN:
            return ToolResult(ok=False, observation=f"Unknown key {key!r}. Start with 'start'.")
        nxt = CHAIN[key]
        if nxt is None:
            return ToolResult(ok=True, observation="FINISHED. Now call terminate with reason 'chain complete'.")
        return ToolResult(ok=True, observation=f"Next key: {nxt}. Call next_clue with key '{nxt}'.")


def _provider(monkeypatch: pytest.MonkeyPatch, max_tokens: int) -> Any:
    from ctf_phantom.providers.openai_provider import OpenAIProvider

    monkeypatch.setenv("OPENAI_API_KEY", os.environ.get("OPENAI_API_KEY") or "ollama")
    assert MODEL
    return OpenAIProvider(ProviderConfig(name="openai", model=MODEL, base_url=BASE_URL, temperature=0.0,
                                         seed=20261010, max_tokens=max_tokens, timeout_s=300, max_retries=0))


def test_server_accepts_every_assistant_message_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic replay of each shape the harness emits, including the empty reasoning-only turn."""
    history = [
        Message(role="user", content="objective"),
        Message(role="assistant", tool_calls=[ToolCall("c1", "next_clue", {"key": "start"})]),  # tool-only
        Message(role="tool", content="Next key: alpha.", tool_call_id="c1", tool_name="next_clue"),
        Message(role="assistant", content="Two at once.", tool_calls=[                          # mixed, multiple
            ToolCall("c2", "next_clue", {"key": "alpha"}), ToolCall("c3", "next_clue", {"key": "bravo"})]),
        Message(role="tool", content="Next key: bravo.", tool_call_id="c2", tool_name="next_clue"),
        Message(role="tool", content="", tool_call_id="c3", tool_name="next_clue"),             # empty result
        Message(role="assistant"),                                                              # empty turn
        Message(role="user", content=NO_TOOL_NUDGE),
        Message(role="assistant", content="Continuing."),                                       # text-only
        Message(role="user", content="Reply with one word."),
    ]
    _provider(monkeypatch, max_tokens=16).complete("sys", history, [CLUE_SPEC, TerminateTool.spec])


def test_agent_completes_three_or_more_tool_turns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system = ("You are a tool-using agent. Use the next_clue tool, one call per turn, starting with key "
              "'start' and following each result, until it says FINISHED; then call terminate.")
    with TraceRecorder(tmp_path / "trace.jsonl", "ollama-live") as rec:
        agent = Agent(_provider(monkeypatch, max_tokens=4096), [ClueTool(), TerminateTool()], system,
                      AgentConfig(max_steps=12, max_consecutive_no_tool=3), rec)
        outcome = agent.run("Walk the clue chain to the end.")
        events = list(rec.events)

    errors = [e.data for e in events if e.type == EventType.LLM_ERROR]
    assert not errors, errors
    assert outcome.stop_reason != StopReason.PROVIDER_ERROR, outcome.error
    tool_turns = [e for e in events if e.type == EventType.LLM_RESPONSE and e.data["tool_calls"]]
    assert len(tool_turns) >= 3, [e.data for e in events if e.type == EventType.LLM_RESPONSE]
