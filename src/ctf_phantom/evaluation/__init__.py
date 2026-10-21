from __future__ import annotations

from pathlib import Path

from ctf_phantom.evaluation.acceptance import check_acceptance
from ctf_phantom.evaluation.aggregate import (
    IncompatibleRunsError,
    check_compatibility,
    refusal_report,
    summarize,
    wilson_interval,
)
from ctf_phantom.evaluation.indicators import IndicatorHit, match_indicator, match_indicator_all
from ctf_phantom.evaluation.metrics import (
    ASR_INTERPRETATION,
    EVALUATOR_VERSION,
    AdversarialActions,
    RunMetrics,
    comparability_key,
    evaluate_events,
)
from ctf_phantom.evaluation.paired import mcnemar_exact, paired_comparisons
from ctf_phantom.tracing import read_trace


def evaluate_trace(path: Path) -> RunMetrics:
    return evaluate_events(read_trace(path))


__all__ = [
    "ASR_INTERPRETATION",
    "EVALUATOR_VERSION",
    "AdversarialActions",
    "IncompatibleRunsError",
    "IndicatorHit",
    "RunMetrics",
    "check_acceptance",
    "check_compatibility",
    "comparability_key",
    "evaluate_events",
    "evaluate_trace",
    "match_indicator",
    "match_indicator_all",
    "mcnemar_exact",
    "paired_comparisons",
    "refusal_report",
    "summarize",
    "wilson_interval",
]
