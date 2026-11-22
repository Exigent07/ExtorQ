-- APP-001 v1.1.0: burst of failed logins against an instrumented web application.
--
-- Input: app.auth.login_failed (structured application security events of the web
-- application: on the Linux VM via linux.app, the same application in Kubernetes via
-- k8s.container_log). Successful logins are never counted.
-- Two non-overlapping variants, each a sliding {window_seconds} window:
--   guessing  >= {min_failures} failures for ONE user name (any sources) in one app
--   spraying  >= {min_failures} failures from ONE source across >= {min_spray_users}
--             distinct user names in one app
-- One row per (asset, app, variant, key, bucket); the engine merges continuous bursts.
-- The app is the attributed service (service_name), else the Kubernetes workload, pod or
-- the app's own service field. Confidence: high when every involved source address is
-- known and none is a shared NAT/gateway address; medium otherwise (traffic from the Mac
-- arrives via 10.0.2.2 on the VM and 10.244.0.1 in kind). Duplicate-safe (LIMIT 1 BY
-- event_id, uniqExact).
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            coalesce(nullIf(service_name, ''),
                     nullIf(JSONExtractString(payload, 'kubernetes', 'workload_name'), ''),
                     nullIf(k8s_pod_name, ''),
                     nullIf(JSONExtractString(attributes, 'service'), ''),
                     'unknown') AS app,
            substring(ifNull(actor_name, ''), 1, 64) AS user_name,
            ifNull(src_ip, '') AS src,
            JSONExtractString(attributes, 'reason') AS reason
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND event_type = 'app.auth.login_failed'
          AND source_type IN ('linux.app', 'k8s.container_log')
        LIMIT 1 BY event_id
    ),
    by_user AS (
        SELECT asset_id, app, user_name AS k, event_time,
               count() OVER w AS n, toUInt64(1) AS users
        FROM ev
        WHERE user_name != ''
        WINDOW w AS (PARTITION BY asset_id, app, user_name
                     ORDER BY toUnixTimestamp64Milli(event_time)
                     RANGE BETWEEN {window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW)
    ),
    by_src AS (
        SELECT asset_id, app, src AS k, event_time,
               count() OVER w AS n, uniqExact(user_name) OVER w AS users
        FROM ev
        WHERE src != ''
        WINDOW w AS (PARTITION BY asset_id, app, src
                     ORDER BY toUnixTimestamp64Milli(event_time)
                     RANGE BETWEEN {window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW)
    ),
    crossings AS (
        SELECT 'guessing' AS variant, asset_id, app, k,
               toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                   AS bucket_start,
               min(event_time) AS first_crossing, max(event_time) AS last_crossing
        FROM by_user
        WHERE n >= {min_failures:UInt32}
        GROUP BY asset_id, app, k, bucket_start
        UNION ALL
        SELECT 'spraying' AS variant, asset_id, app, k,
               toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                   AS bucket_start,
               min(event_time) AS first_crossing, max(event_time) AS last_crossing
        FROM by_src
        WHERE n >= {min_failures:UInt32} AND users >= {min_spray_users:UInt32}
        GROUP BY asset_id, app, k, bucket_start
    )
SELECT
    concat(c.asset_id, '|', c.app, '|', c.variant, ':', c.k) AS group_key,
    c.asset_id AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('app', c.app, 'variant', c.variant,
        if(c.variant = 'guessing', 'user', 'src_ip'), c.k) AS entities,
    toJSONString(CAST(tuple(
        c.variant,
        toUInt32(uniqExact(e.event_id)),
        toUInt32(uniqExactIf(e.user_name, e.user_name != '')),
        arraySort(groupUniqArrayIf(10)(e.user_name, e.user_name != '')),
        arraySort(groupUniqArrayIf(8)(e.src, e.src != '')),
        arraySort(groupUniqArrayIf(8)(e.reason, e.reason != '')),
        hasAny({shared_nat_ips:Array(String)}, groupUniqArrayIf(8)(e.src, e.src != '')),
        toUInt32({window_seconds:UInt32})
    ), concat('Tuple(variant String, failed_logins UInt32, distinct_users UInt32, ',
              'users Array(String), src_ips Array(String), reasons Array(String), ',
              'src_ip_shared_nat Bool, window_seconds UInt32)'))) AS features,
    c.bucket_start AS bucket_start,
    if(hasAny({shared_nat_ips:Array(String)}, groupUniqArrayIf(8)(e.src, e.src != ''))
       OR countIf(e.src = '') > 0, 'medium', 'high') AS confidence
FROM crossings AS c
INNER JOIN ev AS e
    ON e.asset_id = c.asset_id AND e.app = c.app
WHERE ((c.variant = 'guessing' AND e.user_name = c.k) OR (c.variant = 'spraying' AND e.src = c.k))
  AND e.event_time >= c.first_crossing - toIntervalMillisecond({window_seconds:UInt32} * 1000)
  AND e.event_time <= c.last_crossing
GROUP BY c.asset_id, c.app, c.variant, c.k, c.bucket_start
ORDER BY first_seen
