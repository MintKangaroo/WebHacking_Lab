SHELL := /bin/bash

.PHONY: bootstrap dev backend-dev frontend-dev lint test build compose-up compose-down

bootstrap:
	cd backend && python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
	cd frontend && npm ci

dev:
	docker compose up --build

backend-dev:
	cd backend && .venv/bin/uvicorn webhacking_lab.api.app:app --reload

frontend-dev:
	cd frontend && npm run dev

lint:
	cd backend && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy webhacking_lab
	cd frontend && npm run lint && npm run typecheck

test:
	cd backend && .venv/bin/pytest --cov=webhacking_lab --cov-report=term-missing
	cd frontend && npm run test

build:
	cd frontend && npm run build

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
