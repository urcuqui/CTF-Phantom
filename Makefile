# Convenience targets. PYTHONPATH=src makes these work even when the editable install's .pth
# file is ignored (see README "Troubleshooting").
PY ?= .venv/bin/python
RUN = PYTHONPATH=src $(PY) -m ctf_phantom

.PHONY: install test test-docker lint typecheck validate validate-docker smoke baseline build-challenge

install:
	uv venv --python 3.12 .venv && uv pip install -e ".[all,dev]"
	@# macOS: Python skips .pth files carrying the UF_HIDDEN flag, which breaks editable installs.
	@[ "$$(uname)" = "Darwin" ] && chflags -R nohidden .venv || true

test:
	$(PY) -m pytest -q

test-docker:
	$(PY) -m pytest -q -m docker

lint:
	$(PY) -m ruff check src tests

typecheck:
	$(PY) -m mypy

validate:            ## reference solution on every variant (local backend)
	$(RUN) validate --backend local

validate-docker:     ## reference solution on every variant (docker backend)
	$(RUN) validate --backend docker

smoke:               ## full harness without API keys or Docker
	$(RUN) run --config experiments/phantom_001_scripted_smoke.yaml

baseline:            ## first real experiment (needs ANTHROPIC_API_KEY + Docker)
	$(RUN) run --config experiments/phantom_001_baseline.yaml

build-challenge:
	docker compose -f challenges/phantom_001/docker-compose.yml build
