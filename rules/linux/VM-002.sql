-- VM-002 v1.0.0: new or modified systemd unit (persistence) on a Linux host.
--
-- Trigger: persistence.systemd.unit_created / unit_modified inventory diffs (snapshot
-- comparison over SSH) for unit files not in {allowlist_paths}. Baseline snapshots are
-- never alerted. Supporting evidence (optional sources):
--   * auditd watch hits with key {audit_key} on exactly the same path (linux.auditd)
--   * persistence.systemd.unit_enabled for the same unit name
-- Confidence: high when the auditd watch corroborates the inventory diff on the exact
-- path, medium otherwise. A unit that is only *enabled* (existing file, no content
-- change in the window) produces its own row, confidence medium.
-- Identity (PLAN 5.3): asset, unit path, content sha256 (enable-only rows: asset, unit,
-- 'enabled:<wanted_by>'). Duplicate-safe via LIMIT 1 BY event_id; joins only feed
-- uniqExact / distinct arrays.
WITH
    inv AS (
        SELECT
            event_id,
            event_time,
            event_type,
            asset_id,
            asset_type,
            assumeNotNull(resource_path) AS unit_path,
            if(ifNull(resource_name, '') != '', assumeNotNull(resource_name),
               arrayLast(x -> x != '', splitByChar('/', assumeNotNull(resource_path)))) AS unit,
            JSONExtractString(attributes, 'sha256') AS sha256,
            JSONExtractString(attributes, 'previous_sha256') AS previous_sha256,
            JSONExtractString(attributes, 'exec_start') AS exec_start,
            JSONExtractBool(attributes, 'vendor_unit') AS vendor_unit,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.inventory'
          AND event_type IN ('persistence.systemd.unit_created', 'persistence.systemd.unit_modified')
          AND resource_path IS NOT NULL
          AND NOT has({allowlist_paths:Array(String)}, assumeNotNull(resource_path))
          AND NOT JSONExtractBool(attributes, 'baseline')
        LIMIT 1 BY event_id
    ),
    enabled AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(resource_name, '') AS unit,
            JSONExtractString(attributes, 'wanted_by') AS wanted_by,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.inventory'
          AND event_type = 'persistence.systemd.unit_enabled'
          AND ifNull(resource_name, '') != ''
          AND NOT has({allowlist_units:Array(String)}, ifNull(resource_name, ''))
          AND NOT JSONExtractBool(attributes, 'baseline')
        LIMIT 1 BY event_id
    ),
    watched AS (
        SELECT
            event_id,
            asset_id,
            ifNull(resource_path, '') AS path,
            ifNull(process_executable, '') AS executable,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.auditd'
          AND event_type = 'file.audit.watch'
          AND JSONExtractString(attributes, 'audit_key') = {audit_key:String}
        LIMIT 1 BY event_id
    )
SELECT
    concat(i.asset_id, '|', i.unit_path) AS group_key,
    any(i.asset_id) AS asset_id,
    any(i.asset_type) AS asset_type,
    min(i.event_time) AS first_seen,
    max(i.event_time) AS last_seen,
    uniqExact(i.event_id) + uniqExactIf(w.event_id, w.event_id != '')
        + uniqExactIf(en.event_id, en.event_id != '') AS event_count,
    arraySlice(arrayDistinct(arrayConcat(
        arrayMap(x -> x.2, groupArraySorted(100)(tuple(i.event_time, i.event_id))),
        arraySort(groupUniqArrayIf(100)(w.event_id, w.event_id != '')),
        arraySort(groupUniqArrayIf(100)(en.event_id, en.event_id != '')))), 1, 500)
        AS evidence_event_ids,
    arrayConcat(arraySort(groupUniqArrayIf(100)(w.event_id, w.event_id != '')),
                arraySort(groupUniqArrayIf(100)(en.event_id, en.event_id != '')))
        AS supporting_event_ids,
    map('unit', any(i.unit), 'unit_path', i.unit_path, 'sha256', i.sha256) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArray(4)(i.event_type)),
        substring(any(i.exec_start), 1, 512),
        any(i.previous_sha256),
        toBool(max(i.vendor_unit)),
        toBool(uniqExactIf(w.event_id, w.event_id != '') > 0),
        arraySort(groupUniqArrayIf(8)(w.executable, w.executable != '')),
        arraySort(groupUniqArrayIf(8)(en.wanted_by, en.wanted_by != ''))
    ), concat('Tuple(change_types Array(String), exec_start String, previous_sha256 String, ',
              'vendor_unit Bool, audit_corroborated Bool, writer_executables Array(String), ',
              'wanted_by Array(String))'))) AS features,
    if(i.sha256 != '', i.sha256, 'sha256-unknown') AS signature,
    if(uniqExactIf(w.event_id, w.event_id != '') > 0, 'high', 'medium') AS confidence,
    arrayDistinct(arrayConcat(groupUniqArray(16)(i.simulation_run_id),
                              groupUniqArray(16)(w.simulation_run_id))) AS simulation_run_ids
FROM inv AS i
LEFT JOIN watched AS w ON w.asset_id = i.asset_id AND w.path = i.unit_path
LEFT JOIN enabled AS en ON en.asset_id = i.asset_id AND en.unit = i.unit
GROUP BY i.asset_id, i.unit_path, i.sha256

UNION ALL

SELECT
    concat(e.asset_id, '|', e.unit) AS group_key,
    any(e.asset_id) AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    CAST([], 'Array(String)') AS supporting_event_ids,
    map('unit', e.unit, 'unit_path', '', 'sha256', '') AS entities,
    toJSONString(CAST(tuple(
        ['persistence.systemd.unit_enabled'],
        '',
        '',
        false,
        false,
        CAST([], 'Array(String)'),
        arraySort(groupUniqArrayIf(8)(e.wanted_by, e.wanted_by != ''))
    ), concat('Tuple(change_types Array(String), exec_start String, previous_sha256 String, ',
              'vendor_unit Bool, audit_corroborated Bool, writer_executables Array(String), ',
              'wanted_by Array(String))'))) AS features,
    concat('enabled:', arrayStringConcat(arraySort(groupUniqArray(4)(e.wanted_by)), ',')) AS signature,
    'medium' AS confidence,
    groupUniqArray(16)(e.simulation_run_id) AS simulation_run_ids
FROM enabled AS e
WHERE (e.asset_id, e.unit) NOT IN (SELECT asset_id, unit FROM inv)
GROUP BY e.asset_id, e.unit
