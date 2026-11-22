-- MAC-002 v1.0.0: launch item that runs a shell/interpreter or a program from a temporary
-- or shared location (high-risk subset of MAC-001).
--
-- Input: persistence.launchd.item_created / item_modified events (macos.launchd) whose plist
-- was parsed (attributes.program and attributes.program_arguments known). A row matches when
-- at least one condition holds (all are reported in matched_conditions):
--   interpreter      the program, or the first argument, is a shell or script interpreter
--                    ({interpreter_pattern} on the basename: sh, bash, zsh, python, perl,
--                    ruby, osascript, node, ... and /usr/bin/env launching one): the item
--                    runs text that can be changed without touching the plist
--   temp_path        the program or any argument is in a world-writable or shared location
--                    ({temp_path_pattern}: /tmp, /private/tmp, /var/tmp, /var/folders,
--                    /Users/Shared, ~/Downloads): anyone can replace what runs
--   daemon_runs_user_path  a LaunchDaemon (runs as root unless the plist sets UserName)
--                    whose program is under /Users/: a user-writable binary executed by
--                    launchd at boot with elevated rights is a privilege-escalation vector
-- Allowlist: exact plist content digests ({allowlist_sha256}); never labels or paths.
--
-- Identity: asset + plist path + content sha256 (same as MAC-001). Confidence: high (the
-- conditions are evaluated on the parsed plist; unparseable plists cannot match and stay
-- MAC-001 medium). Duplicate-safe via LIMIT 1 BY event_id.
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
            arraySlice(arrayMap(a -> substring(a, 1, 256),
                                JSONExtract(attributes, 'program_arguments', 'Array(String)')),
                       1, 16) AS arguments,
            JSONExtractString(attributes, 'sha256') AS sha256,
            JSONExtractRaw(attributes, 'run_at_load') = 'true' AS run_at_load,
            JSONExtractRaw(attributes, 'keep_alive') NOT IN ('', 'false', 'null') AS keep_alive
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.launchd'
          AND event_type IN ('persistence.launchd.item_created', 'persistence.launchd.item_modified')
          AND resource_path IS NOT NULL
          AND JSONExtractString(attributes, 'program') != ''
          AND NOT has({allowlist_sha256:Array(String)}, JSONExtractString(attributes, 'sha256'))
        LIMIT 1 BY event_id
    ),
    classified AS (
        SELECT
            *,
            arrayLast(x -> x != '', splitByChar('/', program)) AS program_name,
            if(length(arguments) > 1, arrayLast(x -> x != '', splitByChar('/', arguments[2])), '')
                AS second_name,
            arrayFilter(a -> match(a, {temp_path_pattern:String}), arrayConcat([program], arguments))
                AS temp_paths,
            match(program_name, {interpreter_pattern:String})
                OR (program_name = 'env' AND match(second_name, {interpreter_pattern:String}))
                AS is_interpreter,
            kind = 'daemon' AND startsWith(program, '/Users/') AS daemon_runs_user_path
        FROM ev
    ),
    matched AS (
        SELECT
            *,
            arrayFilter(x -> x != '', [
                if(is_interpreter, 'interpreter', ''),
                if(notEmpty(temp_paths), 'temp_path', ''),
                if(daemon_runs_user_path, 'daemon_runs_user_path', '')]) AS conditions
        FROM classified
        WHERE is_interpreter OR notEmpty(temp_paths) OR daemon_runs_user_path
    )
SELECT
    concat(m.asset_id, '|', m.path) AS group_key,
    any(m.asset_id) AS asset_id,
    any(m.asset_type) AS asset_type,
    min(m.event_time) AS first_seen,
    max(m.event_time) AS last_seen,
    uniqExact(m.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(m.event_time, m.event_id))) AS evidence_event_ids,
    map('path', m.path, 'label', any(m.label), 'scope', any(m.scope)) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArrayArray(4)(m.conditions)),
        any(m.program),
        any(m.arguments),
        arraySort(groupUniqArrayArray(8)(m.temp_paths)),
        any(m.label),
        any(m.scope),
        any(m.kind),
        arraySort(groupUniqArray(2)(m.event_type)),
        toBool(max(m.run_at_load)),
        toBool(max(m.keep_alive)),
        m.sha256
    ), concat('Tuple(matched_conditions Array(String), program String, arguments Array(String), ',
              'temp_paths Array(String), label String, scope String, kind String, ',
              'change_types Array(String), run_at_load Bool, keep_alive Bool, sha256 String)')))
        AS features,
    if(m.sha256 != '', m.sha256, concat('no-digest:', min(m.event_id))) AS signature,
    'high' AS confidence
FROM matched AS m
GROUP BY m.asset_id, m.path, m.sha256
ORDER BY first_seen
