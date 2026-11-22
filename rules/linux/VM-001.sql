-- VM-001 v1.1.0: burst of failed SSH authentication from one source address.
--
-- Sliding-window threshold. An event is a "crossing" when the trailing window ending at
-- it ({window_seconds}) holds >= {threshold_connections} distinct (src_ip, src_port)
-- connections that failed authentication, or >= {threshold_failures} 'Failed <method>'
-- attempts (one connection may try several passwords). Every sshd failure shape counts
-- as a failed connection: login_failed, invalid_user, preauth_closed (a client that
-- offered a rejected key and gave up) and max_auth_exceeded. Successful logins never do.
--
-- One row per (asset, src_ip, bucket of the crossing); the engine merges rows of one
-- continuous burst into a single alert, so a burst that crosses a bucket boundary is
-- neither missed nor duplicated. Evidence: every failure from the source between
-- (first crossing - window) and the last crossing in the bucket, earliest first.
--
-- Confidence (evidence completeness, not maliciousness):
--   high    the connection threshold was reached from an attributable source
--   medium  the source is a shared NAT/gateway address ({shared_nat_ips}: the burst is
--           real, its origin is not attributable), or only the attempt threshold was met
-- Duplicate-safe: events are de-duplicated by event_id before any counting.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            event_type,
            asset_id,
            asset_type,
            assumeNotNull(src_ip) AS src,
            src_port,
            substring(ifNull(actor_name, ''), 1, 64) AS user_name
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.journald'
          AND event_type IN ('auth.ssh.login_failed', 'auth.ssh.invalid_user',
                             'auth.ssh.preauth_closed', 'auth.ssh.max_auth_exceeded')
          AND src_ip IS NOT NULL
        LIMIT 1 BY event_id
    ),
    scored AS (
        SELECT
            asset_id,
            src,
            event_time,
            uniqExact(tuple(src, src_port)) OVER w AS conns,
            countIf(event_type = 'auth.ssh.login_failed') OVER w AS failures
        FROM ev
        WINDOW w AS (
            PARTITION BY asset_id, src
            ORDER BY toUnixTimestamp64Milli(event_time)
            RANGE BETWEEN {window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW
        )
    ),
    crossings AS (
        SELECT
            asset_id,
            src,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket_start,
            min(event_time) AS first_crossing,
            max(event_time) AS last_crossing,
            max(conns) AS peak_connections,
            max(failures) AS peak_failures
        FROM scored
        WHERE conns >= {threshold_connections:UInt32} OR failures >= {threshold_failures:UInt32}
        GROUP BY asset_id, src, bucket_start
    )
SELECT
    concat(c.asset_id, '|', c.src) AS group_key,
    c.asset_id AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('src_ip', c.src) AS entities,
    toJSONString(CAST(tuple(
        toUInt32(uniqExact(tuple(e.src, e.src_port))),
        toUInt32(countIf(e.event_type = 'auth.ssh.login_failed')),
        toUInt32(countIf(e.event_type = 'auth.ssh.invalid_user')),
        toUInt32(countIf(e.event_type = 'auth.ssh.preauth_closed')),
        toUInt32(uniqExactIf(e.user_name, e.user_name != '')),
        arraySort(groupUniqArrayIf(10)(e.user_name, e.user_name != '')),
        toUInt32(max(c.peak_connections)),
        toUInt32(max(c.peak_failures)),
        has({shared_nat_ips:Array(String)}, c.src),
        toUInt32({window_seconds:UInt32}),
        toUInt32({threshold_connections:UInt32}),
        toUInt32({threshold_failures:UInt32})
    ), concat('Tuple(distinct_connections UInt32, failed_attempts UInt32, invalid_user_events UInt32, ',
              'preauth_closed_events UInt32, distinct_usernames UInt32, usernames Array(String), ',
              'peak_window_connections UInt32, peak_window_failures UInt32, src_ip_shared_nat Bool, ',
              'window_seconds UInt32, threshold_connections UInt32, threshold_failures UInt32)'))) AS features,
    c.bucket_start AS bucket_start,
    multiIf(
        has({shared_nat_ips:Array(String)}, c.src), 'medium',
        max(c.peak_connections) >= {threshold_connections:UInt32}, 'high',
        'medium') AS confidence
FROM crossings AS c
INNER JOIN ev AS e ON e.asset_id = c.asset_id AND e.src = c.src
WHERE e.event_time >= c.first_crossing - toIntervalMillisecond({window_seconds:UInt32} * 1000)
  AND e.event_time <= c.last_crossing
GROUP BY c.asset_id, c.src, c.bucket_start
ORDER BY first_seen
