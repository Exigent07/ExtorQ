# ExtorQ operator entry point (owner: platform). `make help` lists the targets.
#
# Conventions: Python runs through `uv run`; Docker through `docker compose` (project "extorq").
# Nothing here prints secrets. Targets owned by other teams only delegate to their scripts and
# say so when a script does not exist yet.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

COMPOSE ?= docker compose
UV ?= uv
PYTEST := $(UV) run pytest
# Python paths checked by lint/format (frontend has its own toolchain). detection_tests/ is
# the detection-test runner (`make test-detections`), included once it exists.
PY_PATHS := backend/src collectors/src scanners/src tests scripts eval $(wildcard detection_tests)
# Services of the "full" profile (frontend: frontend/Dockerfile, grafana: infra/grafana/Dockerfile).
FULL_SERVICES := detector ai-worker api frontend grafana
CORE_SERVICES := clickhouse migrate ingest writer
# `up --wait` budget: the first console build and Grafana's plugin start take a while.
WAIT := --wait --wait-timeout 600
HEARTBEAT_CONFIG := collectors/src/extorq_collectors/sdk/examples/heartbeat.yaml
ARGS ?=

# Run the first script matching a pattern, or explain who owns the missing piece.
# $(call delegate,<glob>,<owner>,<args>)
define delegate
	@script="$(firstword $(wildcard $(1)))"; \
	if [ -z "$$script" ]; then \
	  echo "not available yet: no script matches $(1) (owner: $(2))" >&2; exit 3; \
	fi; \
	echo "+ $$script $(3)"; bash "$$script" $(3)
endef

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-27s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── setup ─────────────────────────────────────────────────────────────────────
.PHONY: bootstrap rotate rotate-apply
bootstrap: ## Check prerequisites, create var/ secrets + TLS + producers.json (idempotent), uv sync
	@# stdlib-only script: runs before the Python environment exists
	python3 scripts/bootstrap.py $(ARGS)
	$(UV) sync

rotate: ## Rotate ClickHouse passwords, service secrets, producer tokens and the gateway cert
	python3 scripts/bootstrap.py --rotate

rotate-apply: ## After `make rotate`: re-sync RBAC passwords and recreate services with new secrets
	$(COMPOSE) up -d --force-recreate clickhouse
	$(COMPOSE) up -d --force-recreate --no-deps migrate
	$(COMPOSE) up -d --force-recreate --no-deps ingest writer
	@echo "restart collectors (make collectors) and full-profile services (make up-full)"

# ── stack ─────────────────────────────────────────────────────────────────────
.PHONY: up up-full up-demo up-debug down ps logs migrate smoke build
build: ## Build the backend image
	$(COMPOSE) build ingest

up: ## Start the core stack: clickhouse, migrate, ingest (8443), writer
	$(COMPOSE) up -d --build --wait $(CORE_SERVICES)

up-full: ## EVERYTHING: core + detector, ai-worker, api 8000, console 3000, grafana 3001 (AI triage OFF)
	$(COMPOSE) --profile full up -d --build $(WAIT) $(CORE_SERVICES) $(FULL_SERVICES)

up-demo: ## up-full with Jev AI triage ON in the ai-worker (live, budgeted calls with a daily cap)
	$(COMPOSE) -f compose.yaml -f compose.jev.yaml --profile full up -d --build $(WAIT) $(CORE_SERVICES) $(FULL_SERVICES)

up-debug: ## Start the loopback-only ClickHouse debug proxy on 127.0.0.1:18123 (never in demos)
	$(COMPOSE) --profile debug up -d clickhouse-debug

down: ## Stop all ExtorQ containers (volumes and collected data are kept)
	$(COMPOSE) --profile full --profile debug down

ps: ## Show service status
	$(COMPOSE) --profile full --profile debug ps

logs: ## Follow logs (SERVICES="ingest writer" to filter)
	$(COMPOSE) --profile full --profile debug logs -f --tail 100 $(SERVICES)

migrate: ## Apply ClickHouse migrations + RBAC password sync (one-shot; rebuilds the image first)
	@# migrations are baked into the backend image: rebuild so new files are included
	$(COMPOSE) up --build --no-deps --exit-code-from migrate migrate

smoke: ## Send one SYNTHETIC event over HTTPS and read it back from ClickHouse (needs up-debug)
	$(UV) run python scripts/smoke_ingest.py

# ── collectors / scanners ─────────────────────────────────────────────────────
.PHONY: collectors collectors-start collectors-stop collectors-once collectors-status \
	collectors-flush sdk-selftest scan
collectors: ## Run every enabled collector in config/collectors/ (foreground, Ctrl-C to stop)
	$(UV) run extorq-collect run $(ARGS)

collectors-start: ## Run every enabled host collector in the BACKGROUND (ONLY=a,b to limit; var/log/collectors.log)
	$(UV) run python scripts/collectors_ctl.py start $(if $(ONLY),--only $(ONLY))

collectors-stop: ## Stop the background collectors (SIGTERM; current cycle commits; SIGKILL after 90 s)
	$(UV) run python scripts/collectors_ctl.py stop

collectors-once: ## One collection cycle per collector, deliver, exit (non-zero on failure)
	$(UV) run extorq-collect run --once $(ARGS)

collectors-status: ## Background runner state + per-collector outbox / dead letters / last health
	@$(UV) run python scripts/collectors_ctl.py status || true

collectors-flush: ## Deliver buffered collector records without collecting
	$(UV) run extorq-collect flush $(ARGS)

sdk-selftest: ## Heartbeat example through the real gateway (producer extorq-selftest)
	$(UV) run extorq-collect run --once --config $(HEARTBEAT_CONFIG)

scan: ## Run every configured scanner (owner: C3)
	$(UV) run extorq-scan run all $(ARGS)

# ── monitored assets (delegated) ──────────────────────────────────────────────
.PHONY: vm-up vm-down vm-ssh vm-status kind-up kind-down kind-status
vm-up: ## Start the Ubuntu VM linux:lab-vm-01 (owner: Linux telemetry)
	$(call delegate,infra/vm/vm.sh,Linux telemetry,up)
vm-down: ## Stop the Ubuntu VM (owner: Linux telemetry)
	$(call delegate,infra/vm/vm.sh,Linux telemetry,down)
vm-ssh: ## SSH into the Ubuntu VM as the admin user (owner: Linux telemetry)
	$(call delegate,infra/vm/vm.sh,Linux telemetry,ssh $(ARGS))
vm-status: ## Ubuntu VM status (owner: Linux telemetry)
	$(call delegate,infra/vm/vm.sh,Linux telemetry,status)
kind-up: ## Create/refresh the extorq-lab kind cluster (owner: Kubernetes telemetry; never other clusters)
	$(call delegate,infra/kind/kind.sh,Kubernetes telemetry,up)
kind-down: ## Delete ONLY the extorq-lab cluster (owner: Kubernetes telemetry)
	$(call delegate,infra/kind/kind.sh,Kubernetes telemetry,down)
kind-status: ## extorq-lab cluster status (owner: Kubernetes telemetry)
	$(call delegate,infra/kind/kind.sh,Kubernetes telemetry,status)

# ── detection tests (real activity on the monitored assets; PLAN section 12) ─
# Each test performs genuine activity, then the runner verifies by asset, rule and time
# window that the rule fired (positive) or stayed silent (negative control), and cleans up.
# Reports: var/reports/detection-tests-*.json (read by `make demo-check`). ARGS passes options.
.PHONY: test-detections test-detections-linux test-detections-kubernetes \
	test-detections-github test-detections-macos
test-detections: ## Detection-test matrix on EVERY asset (real activity, negative controls, cleanup)
	$(UV) run python -m detection_tests run --asset all $(ARGS)
test-detections-linux: ## Detection tests on the Ubuntu VM (SSH, systemd, account, cron, HTTP, app)
	$(UV) run python -m detection_tests run --asset linux $(ARGS)
test-detections-kubernetes: ## Detection tests on the extorq-lab kind cluster
	$(UV) run python -m detection_tests run --asset kubernetes $(ARGS)
test-detections-github: ## Detection tests in the private repository Exigent07/extorq-lab
	$(UV) run python -m detection_tests run --asset github $(ARGS)
test-detections-macos: ## Detection tests on this Mac (never sudo, never loads launch items)
	$(UV) run python -m detection_tests run --asset macos $(ARGS)

# ── frontend (owner: D2) ──────────────────────────────────────────────────────
.PHONY: frontend-dev frontend-build
frontend-dev: ## Console dev server on 127.0.0.1:3100 (owner: D2)
	cd frontend && pnpm install --frozen-lockfile && pnpm dev
frontend-build: ## Production build of the console (owner: D2)
	cd frontend && pnpm install --frozen-lockfile && pnpm build

# ── quality ───────────────────────────────────────────────────────────────────
.PHONY: lint fmt typecheck test test-unit test-integration test-failure test-security
lint: ## ruff check (Python)
	$(UV) run ruff check $(PY_PATHS)

fmt: ## ruff format + autofix (Python)
	$(UV) run ruff format $(PY_PATHS)
	$(UV) run ruff check --fix $(PY_PATHS)

typecheck: ## mypy (packages from pyproject)
	$(UV) run mypy

test: test-unit ## Default test run (unit + security + rule harness; no live stack needed)

test-unit: ## Unit, security and rule-harness tests (markers integration/lab/live_ai/failure excluded)
	$(PYTEST) -q

test-integration: ## Integration tests against the running stack (make up && make up-debug first)
	$(PYTEST) -q -m integration tests/integration

test-failure: ## Failure-injection tests: STOP/START shared services (owner A only; announce first)
	$(PYTEST) -q -m failure tests/failure

test-security: ## Security assurance suite (owner F)
	$(PYTEST) -q tests/security

# ── demo ──────────────────────────────────────────────────────────────────────
.PHONY: demo-check reset-data
demo-check: ## Read-only readiness report: stack, telemetry per asset, collectors, rules, detection tests
	$(UV) run python scripts/demo_check.py $(ARGS)

reset-data: ## Clean-slate reset plan. Authorized reset needs YES=1 and recovery flags from docs/recovery.md
	$(UV) run python scripts/reset_data.py $(if $(filter 1 yes true,$(YES)),--yes) $(ARGS)
