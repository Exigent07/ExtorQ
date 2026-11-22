# ExtorQ evidence retention and recovery

## Evidence retention

Raw events are retained until the ClickHouse TTL reaches 90 days after source
`event_time`. The TTL uses whole-second precision and deletion occurs during
merges. An accepted event can arrive late or spend time queued, which reduces
its remaining time in ClickHouse. The clock starts at the source event time.
Keep the gateway retention setting aligned with the ClickHouse TTL.

Alerts, evidence associations and investigation contexts have no automatic TTL.
The API still shows an association when its event is unavailable. For missing
events whose stored evidence timestamp has reached the TTL, the API reports the
ID in `expired_evidence_ids`. This is an expiration classification from the
policy and timestamp. The API has no per-row ClickHouse TTL deletion ledger.
For missing events still within the retention window, or historical references
without a trusted timestamp, the cause remains unresolved. A record that is
still present resolves normally, including while a TTL merge is pending.

Backups contain sensitive evidence, including queued and quarantined data.
Keep them on a private encrypted filesystem with directories mode 0700 and
files mode 0600. Store them locally under operator control. Review bundles when
their source evidence crosses 90 days and retain extended copies only for an
authorized investigation or recovery requirement. Live TTLs do not clean up
backup archives. [Other table retention periods](data-model.md#6-retention)

## Isolated acceptance

Use a separate checkout and Compose project with its own `var` directory,
generated credentials and persistent volumes. Review the rendered port
bindings for collisions and the project/volume labels before routing producers.
Use explicitly designated ExtorQ test assets, a distinct node-state directory
for each OTel Collector and fresh local collector databases. Record source
cutoff times and the first accepted native IDs because retained source files
can be replayed into an empty receiver. Keep acquisition, acceptance and
storage counts and verify both event-to-alert and alert-to-event links.

## Backup and reset

`make reset-data` prints a plan and table counts. An approved maintenance
window is required for either operation below because both quiesce pipeline
services. A destructive reset requires separate explicit authorization for
the exact deployment, recovery point, tables and downtime.

1. Stop external senders and scanners and wait for any in-flight work to
   settle. For Kubernetes, capture each OTel Collector's stopped node-local
   state directory (`/var/lib/extorq-otel`), collector configuration and
   identity together. Preserve retained container and API audit logs where
   available. Record node identity, source cutoff and queue ownership in the
   recovery record. The script backs up managed local SQLite files. Verify
   the external snapshots and reconcile pending records before resuming
   external senders.
2. Generate and rehearse a backup against a disposable server. Use a new
   backup path each time.

   ```sh
   mkdir -p -m 700 var/backups
   uv run python scripts/reset_data.py --backup-only --sources-paused \
     --backup-dir var/backups/rehearsal
   uv run python scripts/reset_data.py --verify-backup var/backups/rehearsal \
     --restore-sqlite var/backups/rehearsal-sqlite
   ```

3. After a successful rehearsal and explicit reset authorization, rerun the
   preflight and use a fresh backup directory for the actual reset.

   ```sh
   make reset-data YES=1 ARGS='--sources-paused --backup-dir var/backups/pre-reset'
   ```

The reset stops host collectors and Compose gateway, writer, detector, Jev
worker and analyst API. It verifies that the writers and migration service are
stopped. It then captures a ClickHouse archive and each SQLite recovery file,
records table counts and migration checksums, verifies the ZIP and SHA-256
checksums, and only then changes the stored data. SQLite Backup API and
`integrity_check` validate outboxes, dedup and replay state, native checkpoints
and committed WAL data together. The source-only SQLite and ClickHouse
archives remain paired in the same private directory.

On success, the script restarts previously running core and analyst services
and host collectors. It leaves the Jev worker stopped because clearing
`ai_assessments` also clears the persisted UTC daily usage counter. Restore
the accounting state or wait for the next UTC budget period before enabling
paid calls. Refresh scanner findings and verify source freshness after
reconciling external queues. [Reset table scope](data-model.md#61-clean-slate)

## ClickHouse restoration and verification

Run the commands from a separately bootstrapped checkout of the same release.
Set `RESTORE_PROJECT` to a new, verified disposable Compose project and
`RECOVERY` to the absolute recovery bundle path. Verify Compose's target
before writing to it. Use backup and restore tools from the same backend
revision.

```sh
uv run python scripts/reset_data.py --verify-backup "$RECOVERY" \
  --restore-sqlite "$RECOVERY-sqlite"
ARCHIVE=$(jq -er '.clickhouse.archive' "$RECOVERY/manifest.json")
SCHEMA=$(jq -er '.clickhouse.schema_sha256' "$RECOVERY/manifest.json")
docker compose -p "$RESTORE_PROJECT" up -d --wait --no-deps clickhouse
docker compose -p "$RESTORE_PROJECT" build migrate
docker compose -p "$RESTORE_PROJECT" run --rm --no-deps -T migrate
docker compose -p "$RESTORE_PROJECT" exec -T clickhouse sh -c \
  'set -eu; umask 077; directory=/var/lib/clickhouse/extorq-backups;
   mkdir -p "$directory"; set -C; cat > "$directory/$1"' sh "$ARCHIVE" < "$RECOVERY/$ARCHIVE"
docker compose -p "$RESTORE_PROJECT" run --rm --no-deps -T migrate \
  data restore "$ARCHIVE" --yes --expected-schema "$SCHEMA" > "$RECOVERY/clickhouse-rehearsal.json"
jq -e --slurpfile manifest "$RECOVERY/manifest.json" \
  '.status == "RESTORED" and .archive == $manifest[0].clickhouse.archive
   and .migrations == $manifest[0].clickhouse.migrations' "$RECOVERY/clickhouse-rehearsal.json"
```

The native archive contains the `extorq` database, including its migration
ledger. The recovery project gets its own access entities and credentials
through bootstrap and migrations. The prepared restore requires all data
tables empty with identical migration checksums and retains the target's
migration ledger. A data-only check can restore to a server that has no
`extorq` database by omitting `--expected-schema` and the migration invocation.
The restore command refuses existing data. Treat any failed restore as an
incomplete disposable target and preserve the untouched bundle.

Compare restored counts with the manifest before starting any writers.
MergeTree background deduplication and TTL processing can change physical
counts. Reconcile differences against logical event, alert and association IDs
and source retention windows. Resolve known alert evidence via the API and
verify that historical missing associations are labelled correctly. Verify
the restored outbox/dead-letter counts and source cursors before replay. A
checksum and a successful archive parse establish file integrity. Complete
rehearsal also requires the native restore and evidence checks.

## Failure and resumption

If a backup or preflight fails, no stored data has been reset. A failure
after truncation begins leaves managed writers stopped. Keep external senders
paused and retain the bundle, staged state and sanitized counts. Choose an
authorized recovery point before proceeding because a second reset could
destroy evidence of the failure.

Rebuild into a fresh target first and attach SQLite files from that same
manifest. Assign the verified spool copy to
`/var/lib/extorq/spool/spool.db` in the new writer volume with its service UID
ownership. Place the corresponding collector copies at
`var/collectors/<collector_id>/state.db` and the scanner copy at the configured
`outbox.db`. Install into empty paths before starting their owners. Keep
unrelated or newer queue and cursor generations separate and reconcile
unacknowledged work explicitly. Restore external checkpoint/exporter queue
pairs on the matching source and node; do not run two OTel processes against
the same state. Validate gateway and writer health, dedup, analyst evidence
and oldest pending data before restarting collection, the detector and alerts.
Any cutover or replacement of existing persistent data requires its own
authorization.
