-- MAC-001 v2.0.0: new or modified LaunchAgent / LaunchDaemon plist on a macOS host.
--
-- Input: persistence.launchd.item_created / item_modified events (macos.launchd) from the
-- macOS collector's snapshot diff of ~/Library/LaunchAgents, /Library/LaunchAgents and
-- /Library/LaunchDaemons. The collector's first scan is a baseline (no events). Only
-- *.plist files are items, so other files in those directories never produce events.
--
-- Allowlist (v2.0.0): exact plist content digests ({allowlist_sha256}) of reviewed items.
-- The collector's label allow-list (attributes.allowlisted) is reported as context but no
-- longer suppresses: a label is whatever the plist author writes into it, so an attacker can
-- reuse an allow-listed label; a content digest cannot be reused for different content.
--
-- Identity (event dedup): asset + plist path + content sha256 (one alert per distinct
-- content of a plist). Confidence (evidence completeness): high when the plist was read and
-- parsed (program and digest known), medium when it could not be read or parsed (what it
-- runs is unknown). MAC-002 additionally flags items that run a shell/interpreter or a
-- program in a temporary or shared location. Duplicate-safe via LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            event_type,
            asset_id,
            asset_type,
            assumeNotNull(resource_path) AS path,
            JSONExtractString(attributes, 'label') AS label,
            JSONExtractString(attributes, 'scope') AS scope,
            JSONExtractString(attributes, 'kind') AS kind,
            substring(JSONExtractString(attributes, 'program'), 1, 512) AS program,
            JSONExtractString(attributes, 'sha256') AS sha256,
            JSONExtractString(attributes, 'previous_sha256') AS previous_sha256,
            JSONExtractString(attributes, 'parse_error') AS parse_error,
            JSONExtractString(attributes, 'read_error') AS read_error,
            JSONExtractRaw(attributes, 'run_at_load') = 'true' AS run_at_load,
            JSONExtractRaw(attributes, 'keep_alive') NOT IN ('', 'false', 'null') AS keep_alive,
            JSONExtractBool(attributes, 'world_writable') AS world_writable,
            JSONExtractBool(attributes, 'allowlisted') AS collector_label_allowlisted
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.launchd'
          AND event_type IN ('persistence.launchd.item_created', 'persistence.launchd.item_modified')
          AND resource_path IS NOT NULL
          AND NOT has({allowlist_sha256:Array(String)}, JSONExtractString(attributes, 'sha256'))
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.asset_id, '|', e.path) AS group_key,
    any(e.asset_id) AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('path', e.path, 'label', any(e.label), 'scope', any(e.scope)) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArray(2)(e.event_type)),
        any(e.label),
        any(e.scope),
        any(e.kind),
        any(e.program),
        e.sha256,
        any(e.previous_sha256),
        toBool(max(e.run_at_load)),
        toBool(max(e.keep_alive)),
        toBool(max(e.world_writable)),
        toBool(max(e.parse_error != '' OR e.read_error != '')),
        toBool(max(e.collector_label_allowlisted))
    ), concat('Tuple(change_types Array(String), label String, scope String, kind String, ',
              'program String, sha256 String, previous_sha256 String, run_at_load Bool, ',
              'keep_alive Bool, world_writable Bool, unreadable Bool, ',
              'collector_label_allowlisted Bool)'))) AS features,
    if(e.sha256 != '', e.sha256, concat('no-digest:', min(e.event_id))) AS signature,
    if(max(e.parse_error != '' OR e.read_error != '') OR e.sha256 = '', 'medium', 'high')
        AS confidence
FROM ev AS e
GROUP BY e.asset_id, e.path, e.sha256
ORDER BY first_seen
