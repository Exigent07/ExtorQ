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
into the service that needs it. Both providers stay disabled unless
`EXTORQ_JEV_ENABLED=true` / `EXTORQ_GEMINI_ENABLED=true` are set for the
`ai-worker` / `api` services.

## 3. Platform stack (`compose.yaml`, owner A)

```sh
make up          # = docker compose up -d --build --wait (core: clickhouse, migrate, ingest, writer)
make up-full     # + detector, ai-worker, api, frontend, grafana (profile "full")
make up-debug    # loopback ClickHouse proxy for tests only (profile "debug"); never in demos
make ps
make demo-check  # read-only readiness report (script being added by A)
```

`migrate` applies `infra/clickhouse/migrations/` (0001 core tables, 0002 RBAC,
0003 findings views, 0004 services, 0005 findings services view) as
`extorq_admin` and exits. The `full` profile builds `infra/grafana/Dockerfile`
and `frontend/Dockerfile`; the console image is still being added by D2.

Checks:

```sh
curl --cacert var/tls/ca.crt https://127.0.0.1:8443/healthz      # gateway (no auth, no detail)
docker compose ps --format '{{.Name}} {{.Status}}'                # healthy services
uv run python scripts/smoke_ingest.py                             # end-to-end synthetic event round trip
```

`scripts/smoke_ingest.py` sends one synthetic event labelled
`labels.synthetic=true` and reads it back as `extorq_api_ro`.

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
infra/kind/kind.sh up          # create extorq-lab, verify audit logging, apply manifests
infra/kind/kind.sh status
infra/kind/kind.sh netcheck    # pods reach the gateway over TLS (host.docker.internal:8443)
infra/kind/kind.sh token       # short-lived inventory token + kubeconfig in var/kube/
```

The admin kubeconfig is `var/kube/extorq-lab-admin.kubeconfig`
(`infra/kind/kind.sh kubeconfig` prints its path, never its contents).

## 6. Collectors and scanners

```sh
uv run extorq-collect run                 # every enabled collector in config/collectors/*.yaml
uv run extorq-collect run --only <id> --once
uv run extorq-collect status
uv run extorq-collect flush               # deliver buffered outbox records
uv run extorq-scan list                   # configured scan targets (config/scanners.yaml)
uv run extorq-scan run all
```

Collector state lives in `var/collectors/<collector_id>/state.db`. The GitHub
collector needs a read-only token file (`EXTORQ_GITHUB_TOKEN_FILE`); see
`config/collectors/github.yaml`.

## 7. Simulations

See [demo-runbook.md](demo-runbook.md). Every simulation is reversible and
records `SimulationRun`s through `extorq-collect sim-record`. The GitHub
simulation's `--execute` mode pushes to the lab repository and needs the
operator's explicit approval.

## 8. Teardown (operator decisions)

* `docker compose down` stops the stack and keeps volumes. Only the platform
  owner runs it on a shared environment.
* `docker compose down -v` **deletes collected data** (ClickHouse, spool,
  Grafana volumes): explicit authorisation only.
* `infra/vm/vm.sh down` / `infra/kind/kind.sh down` stop the lab assets;
  `kind.sh down` deletes only `extorq-lab`.
