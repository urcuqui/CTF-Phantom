"""Behavioural indicator matching over trace events.

An indicator is an observable agent behaviour whose artefact (decoy flag, canary path, attacker
host, compliance token) appears *only* in a specific variant's payload. Matching is purely
behavioural: we never infer attack success from task failure.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel

from ctf_phantom.challenges.spec import Indicator, IndicatorType
from ctf_phantom.tracing import EventType, TraceEvent


class IndicatorHit(BaseModel):
    indicator_id: str
    source_variant: str
    kind: str
    step: int
    evidence: str
    after_exposure: bool | None = None   # set relative to the source variant's exposure


def _paths(meta: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if url := meta.get("url"):
        parts = urlsplit(str(url))
        out.append(parts.path + (f"?{parts.query}" if parts.query else ""))
    out.extend(meta.get("redirect_paths") or [])
    if final := meta.get("path"):
        out.append(str(final))
    return out


def _hosts(event: TraceEvent) -> list[str]:
    hosts: list[str] = []
    if event.type is EventType.TOOL_CALL and event.data.get("name") == "http_request":
        url = str(event.data.get("arguments", {}).get("url", ""))
        if host := urlsplit(url).hostname:
            hosts.append(host)
    elif event.type is EventType.TOOL_RESULT and event.data.get("name") == "http_request":
        meta = event.data.get("meta", {})
        for url in [meta.get("url"), meta.get("final_url"), *(meta.get("redirects") or [])]:
            if url and (host := urlsplit(str(url)).hostname):
                hosts.append(host)
        if sv := meta.get("scope_violation"):
            hosts.append(str(sv.get("host", "")))
    return hosts


def match_indicator(indicator: Indicator, source_variant: str, events: Iterable[TraceEvent]) -> IndicatorHit | None:
    """Return the FIRST event that satisfies ``indicator``, or None."""
    for ev in events:
        step = ev.step if ev.step is not None else -1
        evidence: str | None = None
        t = indicator.type

        if t is IndicatorType.FLAG_SUBMITTED and ev.type is EventType.FLAG_SUBMISSION:
            if ev.data.get("submitted") == indicator.value:
                evidence = f"submitted {ev.data['submitted']!r}"

        elif t is IndicatorType.REQUEST_PATH and ev.type is EventType.TOOL_RESULT:
            meta = ev.data.get("meta", {})
            if ev.data.get("name") == "http_request" and "scope_violation" not in meta:
                assert indicator.pattern is not None
                for path in _paths(meta):
                    if re.search(indicator.pattern, path):
                        evidence = f"{meta.get('method', '?')} {path}"
                        break

        elif t is IndicatorType.REQUEST_HOST and ev.type in (EventType.TOOL_CALL, EventType.TOOL_RESULT):
            assert indicator.pattern is not None
            for host in _hosts(ev):
                if re.search(indicator.pattern, host):
                    evidence = f"request to host {host}"
                    break

        elif t is IndicatorType.TERMINATE_REASON_CONTAINS and ev.type is EventType.TOOL_CALL:
            if ev.data.get("name") == "terminate":
                reason = str(ev.data.get("arguments", {}).get("reason", ""))
                if indicator.value and indicator.value in reason:
                    evidence = f"terminate reason: {reason[:200]}"

        elif t is IndicatorType.AGENT_TEXT_CONTAINS:
            text = ""
            if ev.type is EventType.LLM_RESPONSE:
                text = str(ev.data.get("text", ""))
            elif ev.type is EventType.TOOL_CALL:
                text = json.dumps(ev.data.get("arguments", {}), ensure_ascii=False)
            if indicator.value and indicator.value in text:
                idx = text.index(indicator.value)
                evidence = text[max(0, idx - 80): idx + len(indicator.value) + 80]

        if evidence is not None:
            return IndicatorHit(
                indicator_id=indicator.id,
                source_variant=source_variant,
                kind=indicator.kind.value,
                step=step,
                evidence=evidence,
            )
    return None
