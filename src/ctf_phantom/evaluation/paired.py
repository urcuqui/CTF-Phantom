"""Paired comparisons of each variant against the benign control, using shared seeds.

Repetition ``r`` of every variant uses seed ``base_seed + r`` (same flag, same session secret),
so runs with equal seeds form natural pairs. Pairing removes between-seed variance and lets us
use exact paired tests:

* binary outcomes (completion, payload-specific action) - exact McNemar test on discordant
  pairs (two-sided binomial, p=0.5);
* continuous cost (tool calls, tokens, duration) - mean/median paired difference and an exact
  two-sided sign test.

For the payload-specific action outcome the control arm is scored with the *treatment's*
indicators (any occurrence): this is the base rate of the same behaviour without the payload.
Holm-Bonferroni adjusted p-values are reported across all binary tests in one call.
Only valid runs are paired; seeds with a missing or invalid arm are reported, not imputed.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from typing import Any

from ctf_phantom.evaluation.aggregate import IncompatibleRunsError
from ctf_phantom.evaluation.metrics import RunMetrics

CONTROL_VARIANT = "benign_control"


def binom_two_sided(k: int, n: int) -> float:
    """Exact two-sided p-value for k successes in n trials under p=0.5."""
    if n == 0:
        return 1.0
    k = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return float(min(1.0, 2 * tail))


def mcnemar_exact(b: int, c: int) -> float:
    """b = control-only positives, c = treatment-only positives."""
    return binom_two_sided(min(b, c), b + c)


def holm(pvalues: list[float]) -> list[float]:
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted = [0.0] * len(pvalues)
    running = 0.0
    m = len(pvalues)
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adjusted[i] = round(running, 6)
    return adjusted


def _binary(pairs: list[tuple[bool, bool]]) -> dict[str, Any]:
    """pairs: (control_positive, treatment_positive)."""
    b = sum(1 for c, t in pairs if c and not t)
    c_ = sum(1 for c, t in pairs if t and not c)
    n = len(pairs)
    return {
        "n_pairs": n,
        "control_rate": round(sum(c for c, _ in pairs) / n, 4) if n else None,
        "treatment_rate": round(sum(t for _, t in pairs) / n, 4) if n else None,
        "difference": round((c_ - b) / n, 4) if n else None,  # treatment - control
        "discordant_control_only": b,
        "discordant_treatment_only": c_,
        "p_mcnemar_exact": round(mcnemar_exact(b, c_), 6),
    }


def _continuous(pairs: list[tuple[float, float]]) -> dict[str, Any]:
    diffs = [t - c for c, t in pairs]
    nonzero = [d for d in diffs if d != 0]
    pos = sum(1 for d in nonzero if d > 0)
    return {
        "n_pairs": len(diffs),
        "mean_difference": round(statistics.fmean(diffs), 4) if diffs else None,
        "median_difference": round(statistics.median(diffs), 4) if diffs else None,
        "p_sign_test": round(binom_two_sided(pos, len(nonzero)), 6) if nonzero else 1.0,
    }


def _control_has_actions(control: RunMetrics, treatment_variant: str) -> bool:
    """Did the control run perform any action named by the treatment's indicators (any step)?

    Deliberately more permissive than the treatment arm (which requires post-exposure timing),
    so the comparison is conservative with respect to detecting a payload effect.
    """
    return any(h.source_variant == treatment_variant and h.kind == "action" for h in control.indicator_hits)


def paired_comparisons(runs: list[RunMetrics], control: str = CONTROL_VARIANT) -> list[dict[str, Any]]:
    by_config: dict[tuple[str, str], list[RunMetrics]] = defaultdict(list)
    for r in runs:
        by_config[(r.challenge_id, str(r.comparability_key))].append(r)

    results: list[dict[str, Any]] = []
    for (challenge, key), rs in sorted(by_config.items()):
        index: dict[tuple[str, int], RunMetrics] = {}
        invalid: dict[str, int] = defaultdict(int)
        for r in rs:
            if r.seed is None:
                continue
            if not r.valid:
                invalid[r.variant_id] += 1
                continue
            slot = (r.variant_id, r.seed)
            if slot in index:
                raise IncompatibleRunsError(
                    f"two valid runs for variant {r.variant_id} with seed {r.seed} in config {key}; "
                    "pairing is ambiguous (merge duplicate experiments explicitly)"
                )
            index[slot] = r
        control_seeds = {seed for (v, seed) in index if v == control}
        if not control_seeds:
            continue
        variants = sorted({v for (v, _) in index if v != control})
        for variant in variants:
            seeds = {seed for (v, seed) in index if v == variant}
            shared = sorted(seeds & control_seeds)
            pairs = [(index[(control, s)], index[(variant, s)]) for s in shared]
            treatment = bool(pairs) and pairs[0][1].condition == "treatment"
            row: dict[str, Any] = {
                "challenge": challenge,
                "config_key": key,
                "model": rs[0].requested_model,
                "variant": variant,
                "control": control,
                "n_pairs": len(pairs),
                "unpaired_seeds": {variant: sorted(seeds - control_seeds),
                                   control: sorted(control_seeds - seeds)},
                "invalid_runs": {variant: invalid.get(variant, 0), control: invalid.get(control, 0)},
                "completion": _binary([(bool(c.challenge_completed), bool(t.challenge_completed)) for c, t in pairs]),
                "payload_specific_action": _binary(
                    [(_control_has_actions(c, variant), bool(t.attack_success)) for c, t in pairs]
                ) if treatment else None,
                "tool_calls": _continuous([(float(c.tool_call_count), float(t.tool_call_count)) for c, t in pairs]),
                "total_tokens": _continuous([
                    (float(c.tokens.total_tokens), float(t.tokens.total_tokens)) for c, t in pairs
                    if c.tokens.total_tokens is not None and t.tokens.total_tokens is not None
                ]),
                "duration_s": _continuous([
                    (float(c.duration_s), float(t.duration_s)) for c, t in pairs
                    if c.duration_s is not None and t.duration_s is not None
                ]),
            }
            results.append(row)

    tests = [(i, name) for i, row in enumerate(results) for name in ("completion", "payload_specific_action")
             if row[name] is not None and row[name]["n_pairs"] > 0]
    adjusted = holm([results[i][name]["p_mcnemar_exact"] for i, name in tests])
    for (i, name), p in zip(tests, adjusted, strict=True):
        results[i][name]["p_holm"] = p
    return results
