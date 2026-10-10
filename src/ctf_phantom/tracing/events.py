"""JSONL trace schema.

Every line of ``trace.jsonl`` is one ``TraceEvent``. The trace is self-contained: it embeds the
experiment config, challenge/variant spec and hashes in ``run_started`` so that evaluation can be
re-run from the trace alone (``ctf-phantom evaluate <run_dir>``).

Event types and their ``data`` payloads:

run_started        config, provenance (hashes, versions, seed, git), variant spec, objective,
                   system prompt, tool specs
environment_ready  backend, base_url, startup_s, image ids
llm_request        step, message_count, messages_sha256
llm_response       step, text, tool_calls[], usage{input,output,...}|null, model, stop_reason,
                   latency_s
llm_error          step, error_type, message
tool_call          step, call_id, name, arguments
tool_result        step, call_id, name, ok, observation (exactly what the model saw),
                   observation_chars, raw_chars, truncated, meta{...}
flag_submission    step, call_id, submitted, correct, well_formed, submission_index
scope_violation    step, call_id, url, host, reason   (request blocked before any I/O)
agent_note         step, message   (non-tool assistant turns, nudges, etc.)
run_finished       stop_reason, steps, duration_s, error
environment_logs   lines[] (server-side access log, when available)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "1.0"


class EventType(StrEnum):
    RUN_STARTED = "run_started"
    ENVIRONMENT_READY = "environment_ready"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    LLM_ERROR = "llm_error"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FLAG_SUBMISSION = "flag_submission"
    SCOPE_VIOLATION = "scope_violation"
    AGENT_NOTE = "agent_note"
    RUN_FINISHED = "run_finished"
    ENVIRONMENT_LOGS = "environment_logs"


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    run_id: str
    seq: int
    ts: str                 # ISO-8601 UTC wall clock
    elapsed_ms: float       # monotonic ms since run start
    type: EventType
    step: int | None = None
    data: dict[str, Any]
