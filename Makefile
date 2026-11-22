# ExtorQ operator entry point (owner: agent A). `make help` lists the targets.
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
# Python paths checked by lint/format/typecheck (frontend has its own toolchain).
PY_PATHS := backend/src collectors/src scanners/src tests scripts eval
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
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

up-full: ## EVERYTHING: core + detector, ai-worker, api 8000, console 3000, grafana 3001 (AI flags OFF)
	$(COMPOSE) --profile full up -d --build $(WAIT) $(CORE_SERVICES) $(FULL_SERVICES)

up-demo: ## up-full with AI ON (Jev triage in ai-worker, Gemini summaries in api): live calls, daily caps
	@# Only the two flags differ from up-full; `make up-full` switches AI off again.
	EXTORQ_JEV_ENABLED=true EXTORQ_GEMINI_ENABLED=true \
		$(COMPOSE) --profile full up -d --build $(WAIT) $(CORE_SERVICES) $(FULL_SERVICES)

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

# ── lab assets (delegated) ────────────────────────────────────────────────────
.PHONY: vm-up vm-down vm-ssh vm-status kind-up kind-down kind-status
vm-up: ## Start the Ubuntu lab VM (owner: B1)
	$(call delegate,infra/vm/vm.sh,B1,up)
vm-down: ## Stop the lab VM (owner: B1)
	$(call delegate,infra/vm/vm.sh,B1,down)
vm-ssh: ## SSH into the lab VM as the admin user (owner: B1)
	$(call delegate,infra/vm/vm.sh,B1,ssh $(ARGS))
vm-status: ## Lab VM status (owner: B1)
	$(call delegate,infra/vm/vm.sh,B1,status)
kind-up: ## Create/refresh the extorq-lab kind cluster (owner: B2; never touches other clusters)
	$(call delegate,infra/kind/kind.sh,B2,up)
kind-down: ## Delete ONLY the extorq-lab cluster (owner: B2)
	$(call delegate,infra/kind/kind.sh,B2,down)
kind-status: ## extorq-lab cluster status (owner: B2)
	$(call delegate,infra/kind/kind.sh,B2,status)

# ── simulations (delegated; ARGS="--run-id ..." passes options through) ───────
.PHONY: sim-vm-001 sim-vm-002 sim-http sim-k8s-001 sim-k8s-002 sim-gh-001 sim-mac-001 sim-cleanup
sim-vm-001: ## VM-001 failed SSH authentication burst (owner: B1)
	$(call delegate,simulations/vm/vm_001*.sh,B1,$(ARGS))
sim-vm-002: ## VM-002 systemd persistence (owner: B1; revert with sim-cleanup)
	$(call delegate,simulations/vm/vm_002*.sh,B1,$(ARGS))
sim-http: ## HTTP probing against the lab web app (owner: B1)
	$(call delegate,simulations/http/http_probe*.sh,B1,$(ARGS))
sim-k8s-001: ## K8S-001 privileged pod denied (owner: B2)
	$(call delegate,simulations/k8s/k8s_001*.sh,B2,$(ARGS))
sim-k8s-002: ## K8S-002 risky RBAC (owner: B2)
	$(call delegate,simulations/k8s/k8s_002*.sh,B2,$(ARGS))
sim-gh-001: ## GH-001 workflow permission escalation in the lab repo (owner: C1)
	$(call delegate,simulations/github/gh_001*.sh,C1,$(ARGS))
sim-mac-001: ## MAC-001 macOS persistence (owner: B3)
	$(call delegate,simulations/macos/mac_001*.sh,B3,$(ARGS))
sim-cleanup: ## Revert a scenario: make sim-cleanup SCENARIO=vm-002 RUN_ID=<id>
	@test -n "$(SCENARIO)" -a -n "$(RUN_ID)" || { echo "usage: make sim-cleanup SCENARIO=<vm-001|vm-002|k8s-001|k8s-002|gh-001|mac-001> RUN_ID=<id>" >&2; exit 2; }
	@$(MAKE) --no-print-directory sim-$(SCENARIO) ARGS="--cleanup --run-id $(RUN_ID)"

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
.PHONY: demo-check
demo-check: ## Read-only readiness report: stack health, gateway, collectors, data freshness
	$(UV) run python scripts/demo_check.py $(ARGS)
