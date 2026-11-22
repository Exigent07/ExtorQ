-- MAC-004 v1.0.0: burst of sudo authentication failures for one account on a macOS host.
--
-- Input: auth.sudo.failure events (macos.unified_log) whose reason is an authentication
-- failure ({auth_failure_pattern}: "N incorrect password attempt(s)", "authentication
-- failure"). Authorisation denials ("user NOT in sudoers", "command not allowed") and
-- "a password is required" (sudo -n) are not password guesses and are not counted.
-- Each record counts the attempts sudo reports in its reason (one invocation can report up to
-- three); attributes.failed_attempts from the collector is used when present.
--
-- Sliding window: a record is a crossing when the trailing {window_seconds} window of the
-- same account holds >= {min_failed_attempts} failed attempts. One row per (asset, account,
-- bucket of the crossing); the engine merges a continuous burst into one alert.
--
-- Corroboration (same source type, independent subsystem): opendirectoryd password
-- verification failures (auth.local.failure, attributes.auth_service = opendirectoryd) for
-- the same account within the burst +/- {corroboration_seconds}. Context: whether the account
-- later ran sudo successfully (auth.sudo.command) in the window (typo pattern).
-- Confidence (evidence completeness): high when sudo's own log and opendirectoryd agree;
-- medium for sudo's log alone. Duplicate-safe via LIMIT 1 BY event_id.
WITH
    fails AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(actor_name) AS account,
            substring(JSONExtractString(attributes, 'reason'), 1, 200) AS reason,
            -- sudo writes "3 incorrect password attempts"; any other auth failure counts once.
            if(JSONHas(attributes, 'failed_attempts'),
               greatest(toUInt64(1), JSONExtract(attributes, 'failed_attempts', 'UInt64')),
               greatest(toUInt64(1), toUInt64OrZero(
                   extract(JSONExtractString(attributes, 'reason'), '([0-9]+) incorrect password attempt')))
            ) AS attempts,
            substring(JSONExtractString(attributes, 'tty'), 1, 64) AS tty
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.unified_log'
          AND event_type = 'auth.sudo.failure'
          AND ifNull(actor_name, '') != ''
          AND match(JSONExtractString(attributes, 'reason'), {auth_failure_pattern:String})
        LIMIT 1 BY event_id
    ),
    scored AS (
        SELECT
            asset_id,
            account,
            event_time,
            sum(attempts) OVER w AS attempts_in_window
        FROM fails
        WINDOW w AS (
            PARTITION BY asset_id, account
            ORDER BY toUnixTimestamp64Milli(event_time)
            RANGE BETWEEN {window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW
        )
    ),
    crossings AS (
        SELECT
            asset_id,
            account,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket_start,
            min(event_time) AS first_crossing,
            max(event_time) AS last_crossing,
            max(attempts_in_window) AS peak_attempts
        FROM scored
        WHERE attempts_in_window >= {min_failed_attempts:UInt32}
        GROUP BY asset_id, account, bucket_start
    ),
    burst AS (
        SELECT
            c.asset_id AS asset_id,
            c.account AS account,
            c.bucket_start AS bucket_start,
            c.peak_attempts AS peak_attempts,
            f.event_id AS event_id,
            f.event_time AS event_time,
            f.asset_type AS asset_type,
            f.attempts AS attempts,
            f.reason AS reason,
            f.tty AS tty
        FROM crossings AS c
        INNER JOIN fails AS f ON f.asset_id = c.asset_id AND f.account = c.account
        WHERE f.event_time >= c.first_crossing - toIntervalMillisecond({window_seconds:UInt32} * 1000)
          AND f.event_time <= c.last_crossing
    ),
    spans AS (
        SELECT asset_id, account, bucket_start, min(event_time) AS t0, max(event_time) AS t1
        FROM burst
        GROUP BY asset_id, account, bucket_start
    ),
    od AS (
        SELECT event_id, event_time, asset_id, assumeNotNull(actor_name) AS account
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
                            - toIntervalSecond({corroboration_seconds:UInt32})
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.unified_log'
          AND event_type = 'auth.local.failure'
          AND JSONExtractString(attributes, 'auth_service') = 'opendirectoryd'
          AND ifNull(actor_name, '') != ''
        LIMIT 1 BY event_id
    ),
    od_matched AS (
        SELECT s.asset_id, s.account, s.bucket_start, groupUniqArray(50)(o.event_id) AS od_ids
        FROM spans AS s
        INNER JOIN od AS o ON o.asset_id = s.asset_id AND o.account = s.account
        WHERE o.event_time >= s.t0 - toIntervalSecond({corroboration_seconds:UInt32})
          AND o.event_time <= s.t1 + toIntervalSecond({corroboration_seconds:UInt32})
        GROUP BY s.asset_id, s.account, s.bucket_start
    ),
    sudo_ok AS (
        SELECT s.asset_id, s.account, s.bucket_start, uniqExact(ok.event_id) AS successes
        FROM spans AS s
        INNER JOIN (
            SELECT event_id, event_time, asset_id, assumeNotNull(actor_name) AS account
            FROM events
            WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
              AND event_time < {window_end:DateTime64(3, 'UTC')}
              AND source_type = 'macos.unified_log'
              AND event_type = 'auth.sudo.command'
              AND ifNull(actor_name, '') != ''
            LIMIT 1 BY event_id
        ) AS ok ON ok.asset_id = s.asset_id AND ok.account = s.account
        WHERE ok.event_time >= s.t0
          AND ok.event_time <= s.t1 + toIntervalSecond({window_seconds:UInt32})
        GROUP BY s.asset_id, s.account, s.bucket_start
    )
SELECT
    concat(b.asset_id, '|', b.account) AS group_key,
    b.asset_id AS asset_id,
    any(b.asset_type) AS asset_type,
    min(b.event_time) AS first_seen,
    max(b.event_time) AS last_seen,
    toUInt64(uniqExact(b.event_id) + length(any(om.od_ids))) AS event_count,
    arrayConcat(arrayMap(x -> x.2, groupArraySorted(400)(tuple(b.event_time, b.event_id))),
                arraySort(any(om.od_ids))) AS evidence_event_ids,
    arraySort(any(om.od_ids)) AS supporting_event_ids,
    map('account', b.account) AS entities,
    toJSONString(CAST(tuple(
        toUInt32(sum(b.attempts)),
        toUInt32(uniqExact(b.event_id)),
        toUInt32(max(b.peak_attempts)),
        arraySort(groupUniqArray(4)(b.reason)),
        arraySort(groupUniqArrayIf(4)(b.tty, b.tty != '')),
        toUInt32(length(any(om.od_ids))),
        toBool(ifNull(any(so.successes), 0) > 0),
        toUInt32({window_seconds:UInt32}),
        toUInt32({min_failed_attempts:UInt32})
    ), concat('Tuple(failed_attempts UInt32, sudo_failure_records UInt32, ',
              'peak_window_attempts UInt32, reasons Array(String), ttys Array(String), ',
              'opendirectory_failures UInt32, sudo_success_after Bool, window_seconds UInt32, ',
              'threshold_attempts UInt32)'))) AS features,
    b.bucket_start AS bucket_start,
    if(length(any(om.od_ids)) > 0, 'high', 'medium') AS confidence
FROM burst AS b
LEFT JOIN od_matched AS om
    ON om.asset_id = b.asset_id AND om.account = b.account AND om.bucket_start = b.bucket_start
LEFT JOIN sudo_ok AS so
    ON so.asset_id = b.asset_id AND so.account = b.account AND so.bucket_start = b.bucket_start
GROUP BY b.asset_id, b.account, b.bucket_start
ORDER BY first_seen
