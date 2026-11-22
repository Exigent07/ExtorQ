-- VM-003 v1.0.0: local account created on a Linux host.
--
-- Trigger: account.user.created from the inventory diff (linux.inventory): a user that
-- was not in the previous snapshot of /etc/passwd. The collector's first (baseline)
-- snapshot never produces these events; baseline-flagged rows are ignored anyway.
--
-- Corroboration (optional source linux.auditd): a successful auditd watch hit with key
-- {audit_key} that CREATES OR MODIFIES one of {identity_files} within
-- [account seen - {corroboration_seconds} s, account seen]. Both timestamps come from the
-- host's clock and the dispatcher reads /etc/passwd before it stamps the snapshot, so a write
-- after the snapshot time (for example the userdel of a cleanup) never corroborates. The
-- written path is the hit's CREATE/NORMAL path item, or the CREATE item of a rename (real
-- useradd shape: openat /etc/passwd, then renameat /etc/passwd+ -> /etc/passwd). Only
-- syscalls in the allowlist {change_syscalls} count; unknown or numeric syscall values,
-- failed attempts and deletions fail closed. The writer executable is reported.
--
-- No account-name, uid-range or shell allowlist: an account name is chosen by whoever
-- creates it and an attacker can pick a system uid and a nologin shell as easily as a
-- package can. Those attributes are reported (system_uid_range, login_shell, uid_zero,
-- privileged_groups) so the analyst can tell a service account from a login account.
--
-- Confidence (evidence completeness): high when the inventory diff and an auditd write of
-- an identity file agree (two independent sources; writer known), medium for the diff alone.
-- Identity: one alert per account-creation event (its event id is deterministic, so a
-- re-sent diff collapses). Duplicate-safe via LIMIT 1 BY event_id; the join only feeds
-- conditional aggregates.
WITH
    accounts AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            substring(assumeNotNull(actor_name), 1, 64) AS account,
            JSONExtract(attributes, 'uid', 'Nullable(Int64)') AS uid,
            JSONExtract(attributes, 'gid', 'Nullable(Int64)') AS gid,
            substring(JSONExtractString(attributes, 'shell'), 1, 128) AS shell,
            substring(JSONExtractString(attributes, 'home'), 1, 256) AS home,
            arraySlice(JSONExtract(attributes, 'groups', 'Array(String)'), 1, 32) AS groups
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.inventory'
          AND event_type = 'account.user.created'
          AND ifNull(actor_name, '') != ''
          AND NOT JSONExtractBool(attributes, 'baseline')
        LIMIT 1 BY event_id
    ),
    identity_writes AS (
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
          AND has({identity_files:Array(String)}, written_path)
        LIMIT 1 BY event_id
    ),
    joined AS (
        SELECT
            a.event_id AS event_id,
            a.event_time AS event_time,
            a.asset_id AS asset_id,
            a.asset_type AS asset_type,
            a.account AS account,
            a.uid AS uid,
            a.gid AS gid,
            a.shell AS shell,
            a.home AS home,
            a.groups AS groups,
            w.event_id AS write_id,
            w.executable AS writer,
            w.syscall AS write_syscall,
            -- A LEFT JOIN miss leaves write_id empty; the time test keeps only writes that
            -- precede the snapshot that first saw the account.
            w.event_id != ''
                AND w.event_time >= a.event_time - toIntervalSecond({corroboration_seconds:UInt32})
                AND w.event_time <= a.event_time
                AS corroborates
        FROM accounts AS a
        LEFT JOIN identity_writes AS w ON w.asset_id = a.asset_id
    )
SELECT
    concat(j.asset_id, '|', j.account) AS group_key,
    j.asset_id AS asset_id,
    any(j.asset_type) AS asset_type,
    min(j.event_time) AS first_seen,
    max(j.event_time) AS last_seen,
    toUInt64(1 + uniqExactIf(j.write_id, j.corroborates)) AS event_count,
    arrayConcat([j.event_id], arraySort(groupUniqArrayIf(50)(j.write_id, j.corroborates)))
        AS evidence_event_ids,
    arraySort(groupUniqArrayIf(50)(j.write_id, j.corroborates)) AS supporting_event_ids,
    map('account', j.account, 'uid', ifNull(toString(any(j.uid)), '')) AS entities,
    toJSONString(CAST(tuple(
        j.account,
        any(j.uid),
        any(j.gid),
        any(j.shell),
        any(j.home),
        arraySort(any(j.groups)),
        if(any(j.shell) = '', NULL, NOT has({nologin_shells:Array(String)}, any(j.shell))),
        if(any(j.uid) IS NULL, NULL, any(j.uid) > 0 AND any(j.uid) < {uid_min:UInt32}),
        if(any(j.uid) IS NULL, NULL, any(j.uid) = 0),
        arraySort(arrayIntersect(any(j.groups), {privileged_groups:Array(String)})),
        toBool(countIf(j.corroborates) > 0),
        arraySort(groupUniqArrayIf(8)(j.writer, j.corroborates AND j.writer != '')),
        arraySort(groupUniqArrayIf(8)(j.write_syscall, j.corroborates))
    ), concat('Tuple(account String, uid Nullable(Int64), gid Nullable(Int64), shell String, ',
              'home String, groups Array(String), login_shell Nullable(Bool), ',
              'system_uid_range Nullable(Bool), uid_zero Nullable(Bool), ',
              'privileged_groups Array(String), audit_corroborated Bool, ',
              'writer_executables Array(String), writer_syscalls Array(String))'))) AS features,
    j.event_id AS signature,
    if(countIf(j.corroborates) > 0, 'high', 'medium') AS confidence
FROM joined AS j
GROUP BY j.asset_id, j.account, j.event_id
ORDER BY first_seen
