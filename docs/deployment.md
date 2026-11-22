# Deployment (Apple Silicon lab)

Owner: agent F. Describes how the ExtorQ lab is brought up on one Apple
Silicon Mac. The `Makefile` (owner A, `make help`) wraps every step; the
commands below are what the targets run and can be used directly from the
repository root.

## 1. Prerequisites

| Tool | Used for | Verified version in the build environment |
|---|---|---|
| Docker Desktop (compose v2) | platform stack, kind node, scanners | Docker 29.7, compose 5.5 (Linux VM about 7.75 GiB RAM) |
| `uv` | Python 3.12 workspace | 0.12 |
| `kind`, `kubectl` | lab cluster `extorq-lab` | kind 0.33, kubectl 1.36 |
| `qemu-system-aarch64` + edk2 firmware (`/opt/homebrew/share/qemu`) | Ubuntu VM with HVF | QEMU 11.1 |
| `pnpm`, Node 20 | console development | pnpm 12, Node 20.11 |
| `openssl` | bootstrap (CA, certificates) | system |
| `gh` (optional) | GitHub lab repository creation (approval required) | authenticated |

Never touch other kind clusters on the machine (for example
`motorq-security`): every ExtorQ script names `extorq-lab` explicitly and uses
its own kubeconfig under `var/kube/`.

## 2. Bootstrap

```sh
make bootstrap        # = python3 scripts/bootstrap.py && uv sync
```

`scripts/bootstrap.py` is idempotent and prints no secret values. It creates:

* `var/secrets/clickhouse/<user>_password` for every ClickHouse identity and the
  admin users.d XML;
* `var/secrets/tokens/<producer_id>.token` and `var/secrets/producers.json`
  (token digests and per-producer authorisation);
* console, API and Grafana secrets in `var/secrets/`;
* a local CA and the gateway certificate in `var/tls/`.

Files are 0600 in 0700 directories. Rotation: `--rotate` (passwords, service
secrets, tokens, gateway certificate) and `--rotate-ca` (also the CA); restart
the affected services and collectors afterwards.

The AI keys come from the user-owned `.env` (`JEV_API_KEY`, `GEMINI_API_KEY`);
ExtorQ tooling never reads, prints or modifies it. Compose mounts each key only
into the service that needs it (Jev into `ai-worker`, Gemini into `api`). Both
providers stay disabled unless the operator opts in: compose interpolates
`EXTORQ_JEV_ENABLED` / `EXTORQ_GEMINI_ENABLED` (default `false`) from the shell;
`make up-demo` sets both to `true`, and running `make up-full` again switches AI
off.

## 3. Platform stack (`compose.yaml`, owner A)

```sh
make up          # = docker compose up -d --build --wait (core: clickhouse, migrate, ingest, writer)
make up-full     # + detector, ai-worker, api, frontend, grafana (profile "full"), AI off; waits up to 600 s
make up-demo     # up-full with EXTORQ_JEV_ENABLED=true and EXTORQ_GEMINI_ENABLED=true
make up-debug    # loopback ClickHouse proxy for tests and read-only tools (profile "debug"); never in demos
make ps          # status of every service, all profiles
make demo-check  # read-only readiness report (scripts/demo_check.py); without the proxy it queries inside the api container
make migrate     # rebuild the backend image and apply new migrations (one-shot)
```

`migrate` applies `infra/clickhouse/migrations/` (0001 core tables, 0002 RBAC,
0003 findings views, 0004 services, 0005 findings services view, 0006 refresh
of `v_alerts`) as `extorq_admin` and exits. The `full` profile builds
`infra/grafana/Dockerfile` and `frontend/Dockerfile`. Check the console with
D2's smoke script after `make up-full`
([demo-runbook.md section 2](demo-runbook.md#2-pre-flight-checklist); state of
that check: [testing.md](testing.md#34-integration-and-live-checks)).

Checks:

```sh
curl --cacert var/tls/ca.crt https://127.0.0.1:8443/healthz      # gateway (no auth, no detail)
docker compose ps --format '{{.Name}} {{.Status}}'                # running services and health
make smoke                                                        # = uv run python scripts/smoke_ingest.py (needs up-debug)
```

`scripts/smoke_ingest.py` sends one synthetic event labelled
`labels.synthetic=true` and reads it back as `extorq_api_ro` through the debug
proxy.

## 4. Lab VM (`infra/vm/vm.sh`, owner B1)

```sh
infra/vm/vm.sh up        # download + verify image (OpenPGP + SHA-256), keys, cloud-init, boot
infra/vm/vm.sh status
infra/vm/vm.sh ssh       # operator shell as extorq-admin (sudo)
infra/vm/vm.sh redeploy  # push dispatcher, lab portal and config changes into the running VM
infra/vm/vm.sh down
```

The VM listens on `127.0.0.1:2222` (SSH) and `127.0.0.1:8088` (nginx -> lab
portal). Everything lives in `var/vm/` (keys, disk, seed, state).
`destroy --yes` deletes the VM disk and needs the operator's decision because
it discards collected state on the VM.

## 5. Lab Kubernetes cluster (`infra/kind/kind.sh`, owner B2)

```sh
infra/kind/kind.sh up          # create extorq-lab, verify audit logging, apply manifests (make kind-up)
infra/kind/kind.sh status      # (make kind-status)
infra/kind/kind.sh netcheck    # pods reach the gateway over TLS (host.docker.internal:8443)
infra/kind/kind.sh token       # short-lived inventory token + kubeconfig in var/kube/
infra/kind/kind.sh audit-check # audit policy guarantees checked against the real audit log
```

The inventory token is valid for 24 hours by default
(`EXTORQ_K8S_TOKEN_DURATION`); re-mint it before it expires, otherwise the
`k8s-inventory` collector fails with 401. The admin kubeconfig is
`var/kube/extorq-lab-admin.kubeconfig` (`infra/kind/kind.sh kubeconfig` prints
its path, never its contents).

## 6. Collectors and scanners

```sh
make collectors-start                     # every enabled host collector as one background runner (ONLY=a,b)
make collectors-status                    # runner state + outbox, dead letters, last health per collector
make collectors-stop                      # SIGTERM: the current cycle commits; SIGKILL after 90 s
uv run extorq-collect run                 # foreground instead (make collectors; ARGS="--only a,b")
uv run extorq-collect run --only <id> --once
uv run extorq-collect status              # make collectors-status
uv run extorq-collect flush               # deliver buffered outbox records (make collectors-flush)
uv run extorq-scan list                   # configured scan targets (config/scanners.yaml)
uv run extorq-scan run all                # make scan
```

Collector ids: `macos-workstation-01`, `linux-ssh-lab-vm-01`, `k8s-inventory`,
`github-repos`. Collector state lives in
`var/collectors/<collector_id>/state.db`. GitHub token: the committed
`config/collectors/github.yaml` enables the GitHub CLI token fallback
(`gh_cli_token_fallback: true`), approved by the user for the lab on
2026-11-22; that token carries broad OAuth scopes (`repo`, `workflow`) and the
collector reports this as a health warning. The preferred setup is a
fine-grained read-only token file (`token_file` or `EXTORQ_GITHUB_TOKEN_FILE`)
with the fallback switched off.

## 7. Simulations

`make sim-<scenario>` runs `simulations/**` (`ARGS="..."` passes options;
revert with `make sim-cleanup SCENARIO=<scenario> RUN_ID=<id>`). Every
simulation is reversible and records `SimulationRun`s through
`extorq-collect sim-record`. The GitHub simulation needs `--repo`
(`make sim-gh-001 ARGS="--repo Exigent07/extorq-lab"`, a dry run by default);
its `--execute` mode pushes to the private lab repository and needs the
operator's explicit approval, and its cleanup is
`make sim-gh-001 ARGS="--repo Exigent07/extorq-lab --cleanup --run-id <id>"`
(`make sim-cleanup SCENARIO=gh-001` does not pass `--repo`). Scenario details:
[attack-scenarios.md](attack-scenarios.md); demonstration plan:
[demo-runbook.md](demo-runbook.md).

## 8. Teardown (operator decisions)

* `make down` (= `docker compose --profile full --profile debug down`) stops
  the stack and keeps volumes. Only the platform owner runs it on a shared
  environment.
* `docker compose down -v` **deletes collected data** (ClickHouse, spool,
  Grafana volumes): explicit authorisation only.
* `infra/vm/vm.sh down` / `infra/kind/kind.sh down` stop the lab assets;
  `kind.sh down` deletes only `extorq-lab`.
