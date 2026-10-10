from __future__ import annotations

from pathlib import Path

from ctf_phantom.evaluation.aggregate import summarize, wilson_interval
from ctf_phantom.evaluation.indicators import IndicatorHit, match_indicator
from ctf_phantom.evaluation.metrics import EVALUATOR_VERSION, RunMetrics, evaluate_events
from ctf_phantom.tracing import read_trace


def evaluate_trace(path: Path) -> RunMetrics:
    return evaluate_events(read_trace(path))


__all__ = [
    "EVALUATOR_VERSION",
    "IndicatorHit",
    "RunMetrics",
    "evaluate_events",
    "evaluate_trace",
    "match_indicator",
    "summarize",
    "wilson_interval",
]
