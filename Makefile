# Convenience targets. PYTHONPATH=src makes these work even when the editable install's .pth
# file is ignored (see README "Troubleshooting").
PY ?= .venv/bin/python
RUN = PYTHONPATH=src $(PY) -m ctf_phantom
PILOT = experiments/pilot/phantom_001_pilot.yaml

.PHONY: install test test-docker regression lint typecheck ci validate validate-docker smoke \
        baseline build-challenge init-secret pilot-dry-run pilot regenerate-golden

install:
	uv venv --python 3.12 .venv && uv pip install -e ".[all,dev]"
	@# macOS: Python skips .pth files carrying the UF_HIDDEN flag, which breaks editable installs.
	@[ "$$(uname)" = "Darwin" ] && chflags -R nohidden .venv || true

test:
	$(PY) -m pytest -q

test-docker:
	$(PY) -m pytest -q -m docker

regression:          ## evaluator regression (golden + legacy traces)
	$(PY) -m pytest -q tests/regression

lint:
	$(PY) -m ruff check src tests

typecheck:
	$(PY) -m mypy

ci: lint typecheck test   ## what .github/workflows/ci.yml runs (minus Docker)

validate:            ## reference solution on every variant (local backend)
	$(RUN) validate --backend local

validate-docker:     ## reference solution on every variant (docker backend, egress probe)
	$(RUN) validate --backend docker

smoke:               ## full harness without API keys or Docker
	$(RUN) run --config experiments/phantom_001_scripted_smoke.yaml

baseline:            ## single-variant real-model experiment (paid API, Docker)
	$(RUN) run --config experiments/phantom_001_baseline.yaml

build-challenge:     ## compose requires PHANTOM_FLAG even to build; the value is irrelevant here
	PHANTOM_FLAG='PHANTOM{000000000000000000000000}' docker compose -f challenges/phantom_001/docker-compose.yml build

init-secret:         ## create the private flag secret (~/.config/ctf-phantom/flag_secret)
	$(RUN) init-secret

pilot-dry-run:       ## preflight + plan for the pilot, no API calls
	$(RUN) run --config $(PILOT) --dry-run

pilot:               ## gated real-agent pilot: provider probe first (PAID API CALLS; see docs/pilot-protocol.md)
	$(RUN) launch --config $(PILOT)

regenerate-golden:   ## only after an intentional evaluator change (bump EVALUATOR_VERSION)
	PYTHONPATH=src:. $(PY) -m tests.regression.regenerate_golden
