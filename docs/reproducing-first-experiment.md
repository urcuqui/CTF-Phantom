# Reproducing the First Experiment

Goal: measure the unperturbed **baseline** behaviour of one model on Phantom-001, then extend it
to all four variants.

## 0. Prerequisites

* macOS or Linux, Python 3.12+, [uv](https://docs.astral.sh/uv/) (or pip)
* Docker Desktop / Docker Engine with Compose v2.20+ (`docker compose version`)
* An API key for the model under test (e.g. `ANTHROPIC_API_KEY`)

## 1. Install

```bash
git clone <this repo> && cd CTF-Phantom
make install                 # uv venv + editable install with all extras + dev tools
cp .env.example .env         # add your API key(s)
ctf-phantom init-secret      # private flag secret (~/.config/ctf-phantom/flag_secret); back it up
```

Flags are derived from this private secret and the seed. The same secret and seed reproduce the
same flags, and nothing in the repo or in results lets anyone (or any agent) compute them. Every
trace records the secret's fingerprint.

## 2. Verify the harness (no API key, no Docker)

```bash
make test                    # unit + integration tests (docker test auto-skips)
make smoke                   # scripted reference agent on all 4 variants, local backend
```

Expected: every variant shows `completed=yes`, and both treatment variants show
`attack_success=no` (`outcome=no_adversarial_action`). The reference script solves the
challenge without taking any bait.

## 3. Verify the isolated environment

```bash
make build-challenge         # builds ctf-phantom/phantom_001
make validate-docker         # reference solution against each variant, in Docker
make test-docker             # also asserts the challenge container has no egress
```

Each run's `environment_ready` event should contain `"egress_blocked": true`.

## 4. Preflight (no API calls)

```bash
ctf-phantom run --config experiments/phantom_001_baseline.yaml --dry-run
```

This validates the challenge, variants, prompt profile, pins, provider parameters, budgets and
Docker availability, then prints the run plan. Configuration problems exit with code 3 before
any run. To also verify credentials and that the model accepts the task, run
`ctf-phantom check-provider --config <file>`, which makes one small paid request.

## 5. Run the baseline experiment

```bash
ctf-phantom run --challenge phantom_001 --variant baseline        # quick single run
# or the pinned configuration (5 repetitions, docker backend):
ctf-phantom run --config experiments/phantom_001_baseline.yaml
```

Overrides: `--provider`, `--model`, `--effort`, `--repetitions`, `--seed`, `--max-steps`,
`--backend`, `--prompt-profile`, `--name`, `--output-dir`.

## 6. Inspect results

```
results/phantom_001_baseline/
├── experiment.json                 # config, pins, host provenance, run order, final status
├── runs.jsonl                      # one metrics record per ATTEMPT (valid or not)
└── 20261009T…_phantom_001_baseline_r000_a1_ab12cd/
    ├── trace.jsonl                 # full event trace (source of truth; flag redacted)
    ├── metrics.json                # evaluation of the trace
    └── manifest.json               # per-run config + provenance
```

```bash
ctf-phantom summarize results/phantom_001_baseline     # summary.json + paired.json
ctf-phantom evaluate  results/phantom_001_baseline/<run_id>
jq -c 'select(.type=="tool_call") | .data' results/phantom_001_baseline/*/trace.jsonl
```

## 7. Full Phase-1 comparison and the real-agent pilot

```bash
ctf-phantom run --config experiments/phantom_001_all_variants.yaml   # 4 variants × 10 reps
ctf-phantom summarize results/phantom_001_all_variants
```

The pinned, budgeted pilot (4 variants × 10 paired repetitions) and its acceptance criteria
are in [pilot-protocol.md](pilot-protocol.md). To test another model, copy a config, change
`provider`, and **rename the experiment**: runs with different configurations are never
aggregated together. Use
`experiments/phantom_001_openai_compatible.yaml` as a template for OpenAI-compatible servers
(Ollama, vLLM, OpenRouter).

## 8. Reporting checklist

- [ ] `validate --backend docker` passed on the reported commit
- [ ] `git.dirty == false` in every reported trace
- [ ] backend `docker`, `egress_blocked: true`
- [ ] requested model and every provider-reported model string reported
- [ ] invalid runs reported by status (never counted as failures)
- [ ] ASR | exposed and unconditional ASR with Wilson 95% CI, alongside control false-positive rates
- [ ] paired McNemar contrasts vs `benign_control` (`paired.json`); causal claims only from these
- [ ] solve rate and cost vs. `benign_control`, not only vs. `baseline`
