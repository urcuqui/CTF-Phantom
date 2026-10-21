"""Append-only JSONL trace recorder (flushed per event, so partial runs remain analysable).

Secrets (the run's true flag, the session signing key) are replaced by stable placeholders
*before* an event is stored in memory or written to disk, so traces, metrics and manifests can be
shared, or later exposed to a terminal-enabled agent, without disclosing ground truth.
Evaluation never needs the plaintext flag: correctness is recorded by the validator.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from ctf_phantom.tracing.events import EventType, TraceEvent


class TraceRecorder:
    def __init__(self, path: Path, run_id: str, *, redactions: Mapping[str, str] | None = None) -> None:
        self.path = path
        # secret value -> placeholder; longest first so overlapping secrets redact cleanly
        self._redactions = sorted(((k, v) for k, v in (redactions or {}).items() if k),
                                  key=lambda kv: -len(kv[0]))
        self.run_id = run_id
        self._seq = 0
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: TextIO | None = path.open("x", encoding="utf-8")
        self.events: list[TraceEvent] = []

    def record(self, type: EventType, data: dict[str, Any], *, step: int | None = None) -> TraceEvent:
        with self._lock:
            if self._fh is None:
                raise RuntimeError("recorder is closed")
            data = self._redact(data)
            event = TraceEvent(
                run_id=self.run_id,
                seq=self._seq,
                ts=datetime.now(UTC).isoformat(timespec="microseconds"),
                elapsed_ms=round((time.monotonic() - self._t0) * 1000, 3),
                type=type,
                step=step,
                data=data,
            )
            self._seq += 1
            self._fh.write(event.model_dump_json() + "\n")
            self._fh.flush()
            self.events.append(event)
            return event

    def _redact(self, data: dict[str, Any]) -> dict[str, Any]:
        if not self._redactions:
            return data
        text = json.dumps(data, ensure_ascii=False, default=str)
        for secret, placeholder in self._redactions:
            text = text.replace(secret, placeholder)
        redacted: dict[str, Any] = json.loads(text)
        return redacted

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> TraceRecorder:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def iter_trace(path: Path) -> Iterator[TraceEvent]:
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                yield TraceEvent.model_validate(json.loads(line))
            except Exception as exc:  # noqa: BLE001 - surface the location of a corrupt line
                raise ValueError(f"{path}:{lineno}: invalid trace event: {exc}") from exc


def read_trace(path: Path) -> list[TraceEvent]:
    return list(iter_trace(path))
