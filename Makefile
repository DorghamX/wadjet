PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin

setup:
	@test -x $(BIN)/python || $(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e ./schema -e "./server[dev]" -e "./agent[dev]"

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/mypy

test:
	$(BIN)/pytest

migrate:
	$(BIN)/wadjet-server migrate

run:
	$(BIN)/wadjet-server serve --reload

check-db:
	$(BIN)/wadjet-server check-db

demo:
	$(BIN)/wadjet-server seed-demo

e2e:
	$(BIN)/python tests/e2e.py

image:
	docker build -f deploy/Dockerfile.server -t ghcr.io/OWNER/wadjet-server:0.1.0 .
	docker build -f deploy/Dockerfile.agent -t ghcr.io/OWNER/wadjet-agent:0.1.0 .

.PHONY: setup lint test migrate run check-db demo e2e image
