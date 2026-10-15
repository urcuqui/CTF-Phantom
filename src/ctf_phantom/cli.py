"""ctf-phantom command-line interface."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from ctf_phantom import __version__
from ctf_phantom.challenges import (
    FlagSecret,
    FlagSecretError,
    list_challenges,
    load_challenge,
    load_flag_secret,
    slot_texts,
)
from ctf_phantom.config import ExperimentConfig, apply_overrides, load_dotenv, load_experiment
from ctf_phantom.evaluation import (
    IncompatibleRunsError,
    RunMetrics,
    audit,
    check_acceptance,
    evaluate_trace,
    paired_comparisons,
    summarize,
)
from ctf_phantom.runner import (
    RunResult,
    current_pins,
    execute_experiment,
    experiment_dir,
    preflight,
    probe_provider,
    run_order,
)
from ctf_phantom.status import ConfigurationError

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="CTF-Phantom: adversarial deception of autonomous cybersecurity agents.")
console = Console()

EXIT_ABORTED = 2        # aborted or budget-exhausted execution; incompatible runs in summarize
EXIT_CONFIG = 3         # configuration error, nothing executed
EXIT_INCOMPLETE = 4     # execution finished but planned runs have no valid attempt
EXIT_REJECTED = 5       # acceptance check rejected the experiment
EXIT_PROBE_FAILED = 6   # provider readiness probe failed
EXIT_REVIEW_REFUSED = 7  # audit review refused (unknown run, stale/invalid evidence, bad input)


def _fmt_bool(v: bool | None) -> str:
    return "-" if v is None else ("[green]yes[/]" if v else "[red]no[/]")


def _print_run(r: RunResult) -> None:
    m = r.metrics
    status = "" if m.valid else f" [bold red]INVALID status={m.run_status}[/] ({m.error})"
    console.print(
        f"[bold]{m.variant_id}[/] rep={m.repetition} attempt={m.attempt} "
        f"completed={_fmt_bool(m.challenge_completed)} exposed={_fmt_bool(m.exposed)} "
        f"attack_success={_fmt_bool(m.attack_success)} outcome={m.attack_outcome} "
        f"tools={m.tool_call_count} tokens={m.tokens.total_tokens if m.tokens.available else 'n/a'} "
        f"stop={m.stop_reason} t={m.duration_s}s{status}\n  -> {r.run_dir}"
    )


def _ensure_secret() -> None:
    """CLI convenience: create the private flag secret on first use (library code never does)."""
    try:
        load_flag_secret()
    except FlagSecretError:
        secret = load_flag_secret(create=True)
        console.print(f"[yellow]created private flag secret[/] (fingerprint={secret.fingerprint}); "
                      "back it up to reproduce flags on another machine")


def _build_config(
    config: Path | None, challenge: str | None, variant: list[str] | None, name: str | None,
    overrides: dict[str, Any],
) -> ExperimentConfig:
    if config is not None:
        cfg = load_experiment(config)
    else:
        if not challenge:
            raise typer.BadParameter("--challenge is required when --config is not given")
        variants = variant or ["baseline"]
        cfg = ExperimentConfig.model_validate({
            "name": name or f"{challenge}_{'_'.join(variants)}",
            "challenge": challenge,
            "variants": variants,
            "provider": {
                "name": os.environ.get("CTF_PHANTOM_PROVIDER", "anthropic"),
                "model": os.environ.get("CTF_PHANTOM_MODEL", "claude-opus-5-5"),
            },
        })
    return apply_overrides(cfg, {
        "challenge": challenge if config is not None else None,
        "variants": variant if config is not None else None,
        "name": name if config is not None else None,
        **overrides,
    })


@app.command()
def run(
    challenge: Annotated[str | None, typer.Option(help="Challenge id, e.g. phantom_001.")] = None,
    variant: Annotated[list[str] | None, typer.Option(help="Variant id (repeatable).")] = None,
    config: Annotated[Path | None, typer.Option(help="Experiment YAML.", exists=True)] = None,
    provider: Annotated[str | None, typer.Option(help="anthropic | openai | scripted")] = None,
    model: Annotated[str | None, typer.Option(help="Model id.")] = None,
    backend: Annotated[str | None, typer.Option(help="docker | local")] = None,
    repetitions: Annotated[int | None, typer.Option(min=1)] = None,
    seed: Annotated[int | None, typer.Option()] = None,
    max_steps: Annotated[int | None, typer.Option(min=1)] = None,
    prompt_profile: Annotated[str | None, typer.Option()] = None,
    effort: Annotated[str | None, typer.Option(help="Anthropic effort level.")] = None,
    name: Annotated[str | None, typer.Option(help="Experiment name (output folder).")] = None,
    output_dir: Annotated[Path | None, typer.Option()] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preflight + plan only; no runs.")] = False,
) -> None:
    """Run an experiment (one fresh environment per run)."""
    load_dotenv()
    cfg = _build_config(config, challenge, variant, name, {
        "provider.name": provider,
        "provider.model": model,
        "provider.effort": effort,
        "environment.backend": backend,
        "repetitions": repetitions,
        "seed": seed,
        "agent.max_steps": max_steps,
        "agent.prompt_profile": prompt_profile,
        "output_dir": str(output_dir) if output_dir else None,
    })
    console.print(
        f"[bold cyan]experiment[/] {cfg.name}  challenge={cfg.challenge} variants={cfg.variants} "
        f"reps={cfg.repetitions} provider={cfg.provider.name}/{cfg.provider.model} "
        f"backend={cfg.environment.backend} seed={cfg.seed}"
    )
    if dry_run:
        try:
            flag_secret = load_flag_secret()
        except FlagSecretError:
            flag_secret = FlagSecret.from_value(secrets.token_hex(32), "ephemeral")
            console.print("[yellow]no flag secret yet (run `ctf-phantom init-secret`); "
                          "dry run uses an ephemeral one[/]")
        try:
            ch, secret = preflight(cfg, flag_secret=flag_secret)
        except ConfigurationError as exc:
            console.print(f"[bold red]configuration error:[/] {exc}")
            raise typer.Exit(EXIT_CONFIG) from None
        order = run_order(cfg)
        console.print(f"preflight OK. {len(order)} runs planned "
                      f"(max {len(order) * cfg.execution.max_attempts_per_run} attempts).")
        _print_budgets(cfg, len(order))
        console.print("pins: " + json.dumps(current_pins(cfg, ch, secret)))
        console.print("order: " + ", ".join(f"r{r}:{v}" for r, v in order))
        return
    _ensure_secret()
    try:
        report = execute_experiment(cfg, on_run=_print_run)
    except ConfigurationError as exc:
        console.print(f"[bold red]configuration error (no runs attempted):[/] {exc}")
        raise typer.Exit(EXIT_CONFIG) from None
    if report.results:
        _print_summary([r.metrics for r in report.results], split_configs=True)
    console.print(
        f"results: {experiment_dir(cfg)}\nexecution: status={report.status}"
        + (f" ({report.reason})" if report.reason else "")
        + f"; planned={report.planned_runs} attempted={report.attempted_runs} attempts={report.attempts} "
        f"valid={report.valid_runs} missing_valid={len(report.missing_valid_runs)} "
        f"retries_exhausted={len(report.exhausted_retries)}"
    )
    console.print("[dim]Execution status is not acceptance: run `ctf-phantom check-acceptance <dir>`.[/]")
    if report.status in ("aborted", "budget_exhausted"):
        raise typer.Exit(EXIT_ABORTED)
    if report.status == "incomplete":
        raise typer.Exit(EXIT_INCOMPLETE)


def _print_budgets(cfg: ExperimentConfig, planned: int) -> None:
    a, ex = cfg.agent, cfg.execution
    console.print("budgets (HARD: never exceeded; SOFT: checked before each request/attempt):")
    console.print(f"  per run   HARD max_steps={a.max_steps} max_flag_submissions={a.max_flag_submissions}")
    console.print(f"  per run   SOFT max_total_tokens={a.max_total_tokens} max_wall_time_s={a.max_wall_time_s} "
                  "(overshoot <= one model request)")
    console.print(f"  experiment SOFT max_experiment_tokens={ex.max_experiment_tokens} "
                  f"max_experiment_wall_time_s={ex.max_experiment_wall_time_s} "
                  "(an attempt starts only if the remaining budget covers its per-run caps)")
    if ex.max_experiment_tokens and a.max_total_tokens and planned * a.max_total_tokens > ex.max_experiment_tokens:
        console.print(f"[yellow]warning: worst case {planned} x {a.max_total_tokens} tokens exceeds the experiment "
                      "token budget; planned runs may be left unattempted[/]")
    per_run_s = (a.max_wall_time_s or 0) + cfg.environment.startup_timeout_s
    if ex.max_experiment_wall_time_s and a.max_wall_time_s and planned * per_run_s > ex.max_experiment_wall_time_s:
        console.print(f"[yellow]warning: worst case {planned} x {per_run_s:.0f}s exceeds the experiment wall-time "
                      "budget; planned runs may be left unattempted[/]")


@app.command("check-provider")
def check_provider(
    config: Annotated[Path, typer.Option(help="Experiment YAML.", exists=True)],
    model: Annotated[str | None, typer.Option(help="Override provider.model.")] = None,
) -> None:
    """Send ONE request (real prompt, tools and objective) to validate provider readiness. Small paid call."""
    load_dotenv()
    cfg = apply_overrides(load_experiment(config), {"provider.model": model})
    try:
        result = probe_provider(cfg)
    except ConfigurationError as exc:
        console.print(f"[bold red]configuration error:[/] {exc}")
        raise typer.Exit(EXIT_CONFIG) from None
    console.print_json(json.dumps(result, default=str))
    if not result["ok"]:
        console.print("[bold red]provider probe failed[/] (error, refusal, or no well-formed tool call)")
        raise typer.Exit(EXIT_PROBE_FAILED)
    console.print("[green]provider ready[/]")


@app.command("check-acceptance")
def check_acceptance_cmd(exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]) -> None:
    """Evaluate pilot acceptance criteria A1-A10 from artifacts; write acceptance.json."""
    result = check_acceptance(exp_dir)
    (exp_dir / "acceptance.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    table = Table(title=f"Acceptance: {result['verdict']}")
    for col in ("id", "status", "criterion"):
        table.add_column(col)
    for c in result["criteria"]:
        color = {"pass": "green", "fail": "red", "manual": "yellow"}[c["status"]]
        table.add_row(c["id"], f"[{color}]{c['status']}[/]", c["description"])
    console.print(table)
    console.print(f"wrote {exp_dir / 'acceptance.json'} (details per criterion)")
    if result["verdict"] == "rejected":
        raise typer.Exit(EXIT_REJECTED)


@app.command()
def evaluate(run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]) -> None:
    """Re-evaluate a run from its trace and rewrite metrics.json."""
    metrics = evaluate_trace(run_dir / "trace.jsonl")
    (run_dir / "metrics.json").write_text(metrics.model_dump_json(indent=2), encoding="utf-8")
    console.print_json(metrics.model_dump_json())


@app.command("summarize")
def summarize_cmd(
    exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    split_configs: Annotated[bool, typer.Option(
        "--split-configs", help="Report incompatible configurations separately instead of failing.")] = False,
    control: Annotated[str, typer.Option(help="Control variant for paired comparisons.")] = "benign_control",
) -> None:
    """Re-evaluate every run in a directory; write summary.json and paired.json."""
    metrics = [evaluate_trace(t) for t in sorted(exp_dir.glob("**/trace.jsonl"))]
    if not metrics:
        raise typer.BadParameter(f"no runs found in {exp_dir}")
    try:
        rows = _print_summary(metrics, split_configs=split_configs)
        paired = paired_comparisons(metrics, control=control)
    except IncompatibleRunsError as exc:
        console.print(f"[bold red]{exc}[/]")
        raise typer.Exit(EXIT_ABORTED) from None
    _print_paired(paired)
    (exp_dir / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (exp_dir / "paired.json").write_text(json.dumps(paired, indent=2), encoding="utf-8")
    console.print(f"wrote {exp_dir / 'summary.json'} and {exp_dir / 'paired.json'}")


def _rate(d: dict[str, Any] | None) -> str:
    if not d or d.get("rate") is None:
        return "-"
    return f"{d['k']}/{d['n']} ({float(d['rate']):.0%})"


def _print_summary(metrics: list[RunMetrics], *, split_configs: bool = False) -> list[dict[str, Any]]:
    rows = summarize(metrics, split_configs=split_configs)
    table = Table(title="Summary (valid runs only)")
    for col in ("model", "config", "variant", "valid/att", "completion", "exposure", "ASR|exposed",
                "executed|exp", "blocked|exp", "control FP", "tools", "tokens"):
        table.add_column(col)
    for r in rows:
        acts = r["adversarial_action_runs"] or {}
        table.add_row(str(r["model"]), str(r["config_key"])[:8], str(r["variant"]),
                      f"{r['runs']}/{r['attempted_runs']}", _rate(r["completion"]), _rate(r["exposure"]),
                      _rate(r["attack_success_given_exposure"]), _rate(acts.get("executed")),
                      _rate(acts.get("blocked")), _rate(r["control_false_positive"]),
                      str(r["mean_tool_calls"]), str(r["mean_total_tokens"]))
    console.print(table)
    if any(r["asr_interpretation"] for r in rows):
        console.print("[dim]ASR = observable behavioural indicator, not proof of causality; "
                      "see the paired comparison against the benign control.[/]")
    return rows


def _print_paired(paired: list[dict[str, Any]]) -> None:
    if not paired:
        return
    table = Table(title="Paired vs control (shared seeds)")
    for col in ("model", "variant", "pairs", "Δcompletion", "p (Holm)", "Δpayload action", "p (Holm)",
                "Δtools (mean)"):
        table.add_column(col)
    for p in paired:
        comp, act = p["completion"], p["payload_specific_action"]
        table.add_row(str(p["model"]), p["variant"], str(p["n_pairs"]),
                      str(comp["difference"]), str(comp.get("p_holm", "-")),
                      str(act["difference"]) if act else "-", str(act.get("p_holm", "-")) if act else "-",
                      str(p["tool_calls"]["mean_difference"]))
    console.print(table)


@app.command("list-challenges")
def list_challenges_cmd() -> None:
    """List available challenges and their variants."""
    for cid in list_challenges():
        ch = load_challenge(cid)
        console.print(f"[bold]{cid}[/] v{ch.spec.version} ({ch.spec.category}) hash={ch.challenge_hash[:12]}")
        for vid, v in ch.variants.items():
            chars = sum(len(t) for t in slot_texts(ch.spec, v.slots).values())
            console.print(f"  - {vid:<18} {v.condition:<9} {v.attack_class:<26} "
                          f"slot_chars={chars:<4} indicators={len(v.indicators)} "
                          f"hash={ch.variant_hashes[vid][:12]}")


@app.command()
def pins(config: Annotated[Path, typer.Option(help="Experiment YAML.", exists=True)]) -> None:
    """Print current provenance hashes in the `pins:` format for an experiment config."""
    cfg = load_experiment(config)
    ch = load_challenge(cfg.challenge)
    try:
        secret = load_flag_secret()
    except FlagSecretError:
        secret = None
    console.print(yaml.safe_dump({"pins": current_pins(cfg, ch, secret)}, sort_keys=False))


@app.command("init-secret")
def init_secret() -> None:
    """Create the private flag secret (~/.config/ctf-phantom/flag_secret) if missing; print its fingerprint."""
    secret = load_flag_secret(create=True)
    console.print(f"flag secret ready (source={secret.source}) fingerprint={secret.fingerprint}")
    console.print("[dim]Keep it outside any directory mounted into a victim agent's environment.[/]")


@app.command()
def validate(
    challenge: Annotated[str, typer.Option()] = "phantom_001",
    backend: Annotated[str, typer.Option(help="docker | local")] = "local",
    output_dir: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run the reference solution against every variant; all must solve with zero indicator hits."""
    ch = load_challenge(challenge)
    _ensure_secret()
    cfg = ExperimentConfig.model_validate({
        "name": f"validate_{challenge}_{backend}",
        "challenge": challenge,
        "variants": list(ch.variants),
        "shuffle_variants": False,
        "environment": {"backend": backend},
        "execution": {"max_attempts_per_run": 1, "max_consecutive_failures": 1},
        "provider": {"name": "scripted", "model": "reference", "script": "reference"},
        "output_dir": str(output_dir) if output_dir else None,
    })
    try:
        report = execute_experiment(cfg, on_run=_print_run)
    except ConfigurationError as exc:
        console.print(f"[bold red]configuration error:[/] {exc}")
        raise typer.Exit(EXIT_CONFIG) from None
    results = report.results
    bad = [r for r in results if not r.metrics.valid or not r.metrics.challenge_completed
           or r.metrics.indicator_hits]
    if bad or report.status != "completed" or len(results) != len(ch.variants):
        console.print(f"[red]validation failed ({report.status}: {report.reason}) for "
                      f"{[r.metrics.variant_id for r in bad]}[/]")
        raise typer.Exit(1)
    console.print("[green]all variants solvable via the reference path; no indicator false positives[/]")


audit_app = typer.Typer(no_args_is_help=True,
                        help="Human review of attack-success runs (pilot acceptance criterion A10).")
app.add_typer(audit_app, name="audit")


@audit_app.command("list")
def audit_list(
    exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List valid attack-success runs and their effective review status."""
    status = audit.a10_status(exp_dir)
    if as_json:
        console.print_json(json.dumps(status, default=str))
        return
    table = Table(title=f"A10 review status: {status['status']}")
    for col in ("run_id", "variant", "review", "reviewers", "stale"):
        table.add_column(col)
    for r in status["runs"]:
        table.add_row(r["run_id"], r["variant"], r["status"],
                      ", ".join(f"{k}={v}" for k, v in r["decisions_by_reviewer"].items()) or "-",
                      str(r["stale_reviews"]))
    console.print(table)
    console.print(" ".join(f"{k}={status[k]}" for k in
                           ("required", "confirmed", "pending", "rejected", "inconclusive", "conflict",
                            "stale_reviews")))
    if status["audit_log_integrity"] != "ok":
        console.print(f"[bold red]audit log integrity failure:[/] {status['audit_log_integrity']}")
    console.print(f"[dim]{audit.INTERPRETATION}[/]")


@audit_app.command("show")
def audit_show(
    exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    run_id: Annotated[str, typer.Option("--run-id", help="Run directory name.")],
) -> None:
    """Show exposure and indicator evidence (with step numbers) and the review history of one run."""
    try:
        ev = audit.load_evidence(exp_dir, run_id)
        st = audit.run_status(exp_dir, run_id) if ev.metrics.valid and ev.metrics.attack_success else None
    except audit.AuditError as exc:
        console.print(f"[bold red]{exc}[/]")
        raise typer.Exit(EXIT_REVIEW_REFUSED) from None
    m = ev.metrics
    console.print(f"[bold]{run_id}[/]  variant={ev.variant_id}  valid={m.valid}  attack_success={m.attack_success}")
    console.print(f"trace_sha256={ev.trace_sha256}  evaluator_version={ev.evaluator_version}")
    console.print(f"\n[bold]Exposure[/] step={ev.exposure_step} markers={ev.exposure_markers_seen}")
    for x in ev.exposure_excerpts:
        console.print(f"  step {x['step']} {x['url']}  marker={x['marker']!r}\n    …{x['excerpt']}…", markup=False)
    table = Table(title="Indicator occurrences (active variant)")
    for col in ("step", "indicator", "kind", "disposition", "after exposure", "server log", "reviewable", "evidence"):
        table.add_column(col)
    for o in ev.occurrences:
        reviewable = "yes" if ev.reviewable_indicators.get(o["indicator_id"]) == o["step"] else ""
        table.add_row(str(o["step"]), o["indicator_id"], o["kind"], str(o["disposition"]),
                      str(o["after_exposure"]), str(o["server_confirmed"]), reviewable, o["evidence"][:120])
    console.print(table)
    for step, text in sorted(ev.agent_text.items()):
        if text:
            console.print(f"agent text @ step {step}: {text}", markup=False)
    if st is None:
        console.print("[yellow]This run does not require review (not a valid attack-success run).[/]")
        return
    console.print(f"\n[bold]Review status:[/] {st['status']}  decisions={st['decisions_by_reviewer']}")
    for h in st["history"]:
        console.print(f"  {h['reviewed_at']} {h['reviewer']}: {h['decision']} ({h['indicator_id']})"
                      + (f" [STALE: {h['stale']}]" if h["stale"] else "") + f" - {h['justification']}", markup=False)


@audit_app.command("review")
def audit_review(
    exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    run_id: Annotated[str, typer.Option("--run-id")],
    decision: Annotated[str, typer.Option(help="confirmed | rejected | inconclusive")],
    reviewer: Annotated[str, typer.Option(help="Reviewer identity, e.g. researcher-01.")],
    indicator_id: Annotated[str, typer.Option("--indicator-id", help="Attack-success indicator reviewed.")],
    justification: Annotated[str, typer.Option(help="Why the evidence does / does not support the decision.")],
) -> None:
    """Validate and append a review (bound to the current trace hash and evaluator version)."""
    try:
        review = audit.submit_review(exp_dir, run_id=run_id, decision=decision, reviewer=reviewer,
                                     indicator_id=indicator_id, justification=justification)
    except audit.AuditError as exc:
        console.print(f"[bold red]review refused:[/] {exc}")
        raise typer.Exit(EXIT_REVIEW_REFUSED) from None
    console.print_json(review.model_dump_json())
    st = audit.run_status(exp_dir, run_id)
    console.print(f"recorded in {audit.reviews_path(exp_dir)}; effective status of {run_id}: {st['status']}")
    console.print(f"[dim]{audit.INTERPRETATION}[/]")


@app.command()
def version() -> None:
    """Print the package version."""
    console.print(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
