# Operations

Owner: agent F. Day-to-day operation of the lab: health, coverage, gaps,
troubleshooting and safe maintenance. Commands refer to what exists today;
items marked planned are not built yet.

## 1. What "healthy" means

| Layer | Signal | Where |
|---|---|---|
| Gateway | `GET /healthz` 200; `GET /v1/status` (token) shows spool depth and counters | `https://127.0.0.1:8443` |
| Writer | container healthy (heartbeat file); dead letters counted in `pipeline_health` | `docker compose ps`, `extorq.v_pipeline_latest` |
| Collectors | one `CollectorHealth` per cycle: status, `last_success_at`, `lag_seconds`, `records_buffered`, sanitised `last_error` | `extorq-collect status`, `extorq.v_collector_latest` |
| Sources | stale when `now - last_success_at > 3 x interval_seconds`; gaps as `extorq.collector.gap_detected` events | `extorq.events`, console health view |
| Services | `adapter_support` and `monitoring_status` with a `coverage_note` per service | `extorq.v_services`, console services view |
| Detector | one `rule_runs` row per evaluation: status, rows, alerts, duration, `missing_sources` | `extorq.v_rule_latest_run` |
| AI | provider flags, daily caps, failures in `pipeline_health` | `extorq.v_pipeline_latest` |

Absence of alerts never proves absence of activity: check collector freshness
and service coverage first.

## 2. Reading the data safely

Use the read-only identities. From the Mac, with the debug proxy running
(`docker compose --profile debug up -d clickhouse-debug`), the Python helper
reads the password file itself:

```sh
uv run python - <<'PY'
from extorq.storage.clickhouse import get_client
ch = get_client("api_ro")
print(ch.query("SELECT collector_id, status, last_success_at FROM extorq.v_collector_latest").result_rows)
PY
```

Never paste passwords into commands or chat; never use the admin identity for
reads. Stop the debug proxy when finished (`docker compose stop
clickhouse-debug`, platform owner) and keep it off during demos.

Useful duplicate-safe queries (parameters as `{name:Type}`):

```sql
-- events per source in the last hour
SELECT source_type, uniqExact(event_id) FROM extorq.events
WHERE event_time > now() - INTERVAL 1 HOUR GROUP BY source_type;

-- services and their coverage on one asset
SELECT name, service_kind, adapter_support, monitoring_status, coverage_note
FROM extorq.v_services WHERE asset_id = {asset:String} AND present = 1;

-- why records were quarantined (excerpts are redacted)
SELECT received_at, producer_id, reason FROM extorq.ingest_quarantine
ORDER BY received_at DESC LIMIT 20;

-- authorisation denials at the gateway
SELECT occurred_at, authenticated_producer, decision, reason FROM extorq.ingest_audit
ORDER BY occurred_at DESC LIMIT 20;
```

Column names follow `infra/clickhouse/migrations/`; check them there if a
query fails.

## 3. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Collector `buffered` (exit 75) | gateway down or unreachable | records are safe in the outbox; restore the gateway, then `uv run extorq-collect flush` |
| Every host collector stale | the background runner is not running | `make collectors-status`; `make collectors-start` (log `var/log/collectors.log`) |
| API answers 503 for up to a minute | the `extorq_api_ro` quota (1200 queries per minute) is exhausted, for example by smoke or test runs | wait for the next minute; do not run load-heavy checks while presenting |
| Gateway `401` | wrong or rotated token | re-run `scripts/bootstrap.py`; restart the collector |
| Gateway `403` | producer not allowed this kind, asset or source type | read `ingest_audit`; fix the collector or request a registry change (A) |
| `202` but nothing stored | records quarantined or writer failing | read `ingest_quarantine`; `docker compose ps`; writer health |
| `503` with `Retry-After` | spool full or unavailable | the gateway sheds load; check writer and ClickHouse health |
| Linux collector errors | VM down, host key changed, dispatcher denial (exit 77) | `infra/vm/vm.sh status`; host-key and authentication failures are never retried automatically |
| Kubernetes events missing | OTel DaemonSet down or cannot reach the gateway | `infra/kind/kind.sh status`, `infra/kind/kind.sh netcheck` |
| `k8s-inventory` collector fails with 401; K8S-002 alerts only medium | the 24-hour inventory token expired | `infra/kind/kind.sh token`, then restart the collector |
| GitHub collector health shows warnings or gaps | token source and plan limits: the gh CLI token is broader than read-only; branch protection, rules and rulesets on a private free-plan repository answer 403 | expected for the lab ([known limitations](known-limitations.md) C6 to C8); a fine-grained read-only token removes the breadth warning |
| Rule never fires | missing sources or no matching telemetry | `rule_runs.missing_sources`; `uv run extorq rules test --only <ID>` |
| Service shows `unmonitored` | no adapter, planned adapter, adapter disabled | read its `coverage_note`; see [known limitations](known-limitations.md) S1 |
| Service shows `degraded` | source failing, no telemetry yet, or stale | check the adapter's collector health and source |

## 4. Maintenance

* **Secret rotation:** `uv run python scripts/bootstrap.py --rotate`, then
  restart services and collectors (platform owner); `--rotate-ca` additionally
  requires redistributing `var/tls/ca.crt` (collectors, kind Secret via
  `infra/kind/kind.sh deploy`).
* **Retention:** ClickHouse TTLs enforce retention automatically
  ([security.md section 5](security.md#5-data-retention-clickhouse-ttls)).
* **Lab resets:** simulations clean up after themselves (`--cleanup`);
  `infra/vm/vm.sh redeploy` re-applies VM configuration without losing
  telemetry.
* **Destructive actions** (deleting volumes, destroying the VM, deleting the
  cluster) need the operator's explicit decision; see [AGENTS.md section 10](../AGENTS.md#10-actions-requiring-explicit-human-authorisation).

## 5. Readiness check

`make demo-check` (`scripts/demo_check.py`, owner A) prints a read-only
readiness report and exits 1 when a check fails: compose services, gateway
health, spool and acceptance window, API, console and Grafana (including the
datasource), applied migrations, the five mandatory scenarios with all evidence
stored, fresh host collectors, rule runs, plus informational freshness,
pipeline, services, simulations and the Kubernetes token lifetime. Its
ClickHouse queries use the debug proxy when it is up and otherwise run inside
the `api` container, so the proxy can stay off. It prints names, counts, ids and
timestamps only. Run it before any demonstration together with
`make test-security`, not while presenting (it issues many queries against the
API identity's per-minute quota); the full pre-flight list is in
[demo-runbook.md section 2](demo-runbook.md#2-pre-flight-checklist).
