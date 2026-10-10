from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_phantom.tracing import SCHEMA_VERSION, EventType, TraceRecorder, read_trace


def test_writes_valid_jsonl_with_monotonic_seq(tmp_path: Path) -> None:
    path = tmp_path / "run" / "trace.jsonl"
    with TraceRecorder(path, "run-1") as rec:
        rec.record(EventType.RUN_STARTED, {"a": 1})
        rec.record(EventType.TOOL_CALL, {"name": "http_request"}, step=1)
        rec.record(EventType.RUN_FINISHED, {"stop_reason": "max_steps"})

    lines = path.read_text().splitlines()
    assert len(lines) == 3
    raw = [json.loads(line) for line in lines]
    assert [r["seq"] for r in raw] == [0, 1, 2]
    assert all(r["schema_version"] == SCHEMA_VERSION and r["run_id"] == "run-1" for r in raw)
    assert raw[1]["step"] == 1 and raw[0]["step"] is None
    assert raw[0]["elapsed_ms"] <= raw[1]["elapsed_ms"] <= raw[2]["elapsed_ms"]
    assert raw[0]["ts"].endswith("+00:00")

    events = read_trace(path)
    assert [e.type for e in events] == [EventType.RUN_STARTED, EventType.TOOL_CALL, EventType.RUN_FINISHED]


def test_events_flushed_before_close(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    rec = TraceRecorder(path, "r")
    rec.record(EventType.RUN_STARTED, {})
    assert len(read_trace(path)) == 1  # partial runs remain analysable
    rec.close()


def test_refuses_to_overwrite_existing_trace(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    path.write_text("")
    with pytest.raises(FileExistsError):
        TraceRecorder(path, "r")


def test_record_after_close_raises(tmp_path: Path) -> None:
    rec = TraceRecorder(tmp_path / "t.jsonl", "r")
    rec.close()
    with pytest.raises(RuntimeError):
        rec.record(EventType.RUN_STARTED, {})


def test_corrupt_line_reports_location(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text('{"not": "an event"}\n')
    with pytest.raises(ValueError, match=":1:"):
        read_trace(path)
