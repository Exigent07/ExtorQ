-- VM-004 v1.0.0: cron persistence (cron file added or modified) on a Linux host.
--
-- Trigger: persistence.cron.changed from the inventory diff (linux.inventory) with
-- attributes.change 'added' or 'modified' for a file in the collected cron locations
-- (/etc/crontab, /etc/anacrontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly},
-- /var/spool/cron/crontabs). Removals are not persistence and are never alerted. Baseline
-- snapshots never produce events; baseline-flagged rows and exact {allowlist_paths} are
-- ignored.
--
-- Corroboration (optional source linux.auditd, watch key {audit_key} on /etc/cron.d): a
-- successful create/modify syscall from the allowlist {change_syscalls} whose written path
-- (CREATE/NORMAL item, or the CREATE item of a rename) is exactly the changed file, within
-- [diff time - {corroboration_seconds} s, diff time + {snapshot_read_lag_seconds} s] (the
-- dispatcher reads the cron files just after it stamps the snapshot; both times come from
-- the host's clock). The writer
-- executable and syscall are reported; a writer in {package_manager_executables} is
-- reported as package_manager_writer (context only: root can run dpkg too).
--
-- Confidence (evidence completeness): high when the inventory diff and an auditd write of
-- the same path agree; medium for the inventory diff alone (also every location without an
-- audit watch: /etc/crontab, the periodic directories and user crontabs).
-- Identity: asset, path and content digest (identical content re-written extends the alert).
-- Duplicate-safe via LIMIT 1 BY event_id; the join only feeds conditional aggregates.
WITH
    cron AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(resource_path) AS path,
            JSONExtractString(attributes, 'change') AS change,
            JSONExtractString(attributes, 'sha256') AS sha256,
            JSONExtractString(attributes, 'previous_sha256') AS previous_sha256,
            JSONExtractString(attributes, 'file_mode') AS file_mode,
            JSONExtract(attributes, 'owner_uid', 'Nullable(Int64)') AS owner_uid
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.inventory'
          AND event_type = 'persistence.cron.changed'
          AND resource_path IS NOT NULL
          AND JSONExtractString(attributes, 'change') IN ('added', 'modified')
          AND NOT JSONExtractBool(attributes, 'baseline')
          AND NOT has({allowlist_paths:Array(String)}, assumeNotNull(resource_path))
        LIMIT 1 BY event_id
    ),
    cron_writes AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            ifNull(process_executable, '') AS executable,
            JSONExtractString(attributes, 'syscall') AS syscall,
            if(JSONExtractString(attributes, 'nametype') IN ('CREATE', 'NORMAL')
                   AND ifNull(resource_path, '') != '',
               assumeNotNull(resource_path),
               substring(arrayFirst(p -> startsWith(p, 'CREATE:/'),
                                    JSONExtract(attributes, 'paths', 'Array(String)')), 8))
                AS written_path
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
                            - toIntervalSecond({corroboration_seconds:UInt32})
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.auditd'
          AND event_type = 'file.audit.watch'
          AND JSONExtractString(attributes, 'audit_key') = {audit_key:String}
          AND JSONExtractBool(attributes, 'success')
          AND has({change_syscalls:Array(String)}, JSONExtractString(attributes, 'syscall'))
        LIMIT 1 BY event_id
    ),
    joined AS (
        SELECT
            c.event_id AS event_id,
            c.event_time AS event_time,
            c.asset_id AS asset_id,
            c.asset_type AS asset_type,
            c.path AS path,
            c.change AS change,
            c.sha256 AS sha256,
            c.previous_sha256 AS previous_sha256,
            c.file_mode AS file_mode,
            c.owner_uid AS owner_uid,
            w.event_id AS write_id,
            w.executable AS writer,
            w.syscall AS write_syscall,
            w.event_id != ''
                AND w.event_time >= c.event_time - toIntervalSecond({corroboration_seconds:UInt32})
                AND w.event_time <= c.event_time + toIntervalSecond({snapshot_read_lag_seconds:UInt32})
                AS corroborates
        FROM cron AS c
        LEFT JOIN cron_writes AS w ON w.asset_id = c.asset_id AND w.written_path = c.path
    )
SELECT
    concat(j.asset_id, '|', j.path) AS group_key,
    j.asset_id AS asset_id,
    any(j.asset_type) AS asset_type,
    min(j.event_time) AS first_seen,
    max(j.event_time) AS last_seen,
    toUInt64(uniqExact(j.event_id) + uniqExactIf(j.write_id, j.corroborates)) AS event_count,
    arrayConcat(arrayMap(x -> x.2, groupArraySorted(100)(tuple(j.event_time, j.event_id))),
                arraySort(groupUniqArrayIf(100)(j.write_id, j.corroborates)))
        AS evidence_event_ids,
    arraySort(groupUniqArrayIf(100)(j.write_id, j.corroborates)) AS supporting_event_ids,
    map('path', j.path, 'sha256', j.sha256) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArray(2)(j.change)),
        multiIf(j.path IN ('/etc/crontab', '/etc/anacrontab'), 'system_crontab',
                startsWith(j.path, '/etc/cron.d/'), 'cron.d',
                match(j.path, '^/etc/cron[.](hourly|daily|weekly|monthly)/'), 'periodic_script',
                startsWith(j.path, '/var/spool/cron/'), 'user_crontab',
                'other'),
        j.sha256,
        any(j.previous_sha256),
        any(j.file_mode),
        any(j.owner_uid),
        match(any(j.file_mode), '[2367]$'),
        toBool(countIf(j.corroborates) > 0),
        arraySort(groupUniqArrayIf(8)(j.writer, j.corroborates AND j.writer != '')),
        arraySort(groupUniqArrayIf(8)(j.write_syscall, j.corroborates)),
        hasAny({package_manager_executables:Array(String)},
               groupUniqArrayIf(8)(j.writer, j.corroborates AND j.writer != ''))
    ), concat('Tuple(change_types Array(String), cron_location String, sha256 String, ',
              'previous_sha256 String, file_mode String, owner_uid Nullable(Int64), ',
              'world_writable Bool, audit_corroborated Bool, writer_executables Array(String), ',
              'writer_syscalls Array(String), package_manager_writer Bool)'))) AS features,
    if(j.sha256 != '', j.sha256, concat('sha256-unknown:', min(j.event_id))) AS signature,
    if(countIf(j.corroborates) > 0, 'high', 'medium') AS confidence
FROM joined AS j
GROUP BY j.asset_id, j.path, j.sha256
ORDER BY first_seen
