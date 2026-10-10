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
```

## 2. Verify the harness (no API key, no Docker)

```bash
make test                    # unit + integration tests (docker test auto-skips)
make smoke                   # scripted reference agent on all 4 variants, local backend
```

Expected: every variant shows `completed=yes`, and both treatment variants show
`attack_success=no`. The reference script solves the challenge without taking any bait.

## 3. Verify the isolated environment

```bash
make build-challenge         # builds ctf-phantom/phantom_001
make validate-docker         # reference solution against each variant, in Docker
make test-docker             # also asserts the challenge container has no egress
```

Each run's `environment_ready` event should contain `"egress_blocked": true`.

## 4. Run the baseline experiment

```bash
ctf-phantom run --challenge phantom_001 --variant baseline        # quick single run
# or the pinned configuration (5 repetitions, docker backend):
ctf-phantom run --config experiments/phantom_001_baseline.yaml
```

Overrides: `--provider`, `--model`, `--effort`, `--repetitions`, `--seed`, `--max-steps`,
`--backend`, `--prompt-profile`, `--name`, `--output-dir`.

## 5. Inspect results

```
results/phantom_001_baseline/
├── experiment.json                 # config, hashes, host provenance, run order
├── runs.jsonl                      # one metrics record per run
└── 20261009T…_phantom_001_baseline_r000_ab12cd/
    ├── trace.jsonl                 # full event trace (source of truth)
    ├── metrics.json                # evaluation of the trace
    └── manifest.json               # per-run config + provenance
```

```bash
ctf-phantom summarize results/phantom_001_baseline     # table + summary.json
ctf-phantom evaluate  results/phantom_001_baseline/<run_id>
jq -c 'select(.type=="tool_call") | .data' results/phantom_001_baseline/*/trace.jsonl
```

## 6. Full Phase-1 comparison

```bash
ctf-phantom run --config experiments/phantom_001_all_variants.yaml   # 4 variants × 10 reps
ctf-phantom summarize results/phantom_001_all_variants
```

To test another model, copy the config and change `provider`. Use
`experiments/phantom_001_openai_compatible.yaml` as a template for OpenAI-compatible servers
(Ollama, vLLM, OpenRouter).

## 7. Reporting checklist

- [ ] `validate --backend docker` passed on the reported commit
- [ ] `git.dirty == false` in every reported trace
- [ ] backend `docker`, `egress_blocked: true`
- [ ] requested model and every provider-reported model string reported
- [ ] ASR | exposed with Wilson 95% CI, alongside control false-positive rates
- [ ] solve rate and cost vs. `benign_control`, not only vs. `baseline`
