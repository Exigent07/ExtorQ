-- HTTP-001 v1.0.0: web probing from one source against one asset.
--
-- Sliding-window threshold (like VM-001): a request is a "crossing" when the trailing
-- {window_seconds} window of client-error (4xx) responses to the same source on the same
-- asset holds >= {min_requests} requests AND >= {min_probe_routes} distinct probe-like
-- routes (routes matching {probe_route_pattern}; the route never includes the query
-- string). One row per (asset, source, bucket of the crossing); the engine merges rows of
-- one continuous probe into a single alert.
--
-- Inputs: http.request access lines from nginx/Apache (linux.nginx, linux.apache), the
-- lab application (linux.app) and Kubernetes container logs (k8s.container_log).
-- Confidence: high when the source is not a shared NAT/gateway address; medium when it is
-- (probing is real, its origin is not attributable). Duplicate-safe (LIMIT 1 BY event_id,
-- uniqExact). Simulation-tagged events are NOT filtered.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(src_ip) AS src,
            substring(ifNull(http_route, ''), 1, 256) AS route,
            http_status AS status,
            substring(ifNull(http_user_agent, ''), 1, 200) AS user_agent,
            ifNull(service_name, '') AS service,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND event_type = 'http.request'
          AND source_type IN ('linux.nginx', 'linux.apache', 'linux.app', 'k8s.container_log')
          AND src_ip IS NOT NULL
          AND http_status >= 400 AND http_status < 500
        LIMIT 1 BY event_id
    ),
    scored AS (
        SELECT
            asset_id,
            src,
            event_time,
            count() OVER w AS n_4xx,
            uniqExactIf(route, match(route, {probe_route_pattern:String})) OVER w AS n_probe
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
            max(n_4xx) AS peak_requests,
            max(n_probe) AS peak_probe_routes
        FROM scored
        WHERE n_4xx >= {min_requests:UInt32} AND n_probe >= {min_probe_routes:UInt32}
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
        toUInt32(uniqExact(e.event_id)),
        toUInt32(uniqExact(e.route)),
        toUInt32(uniqExactIf(e.route, match(e.route, {probe_route_pattern:String}))),
        arraySort(groupUniqArrayIf(10)(e.route, match(e.route, {probe_route_pattern:String}))),
        arraySort(groupUniqArray(8)(toString(e.status))),
        toUInt32(uniqExact(e.user_agent)),
        arraySort(groupUniqArrayIf(4)(e.service, e.service != '')),
        toUInt32(max(c.peak_requests)),
        toUInt32(max(c.peak_probe_routes)),
        has({shared_nat_ips:Array(String)}, c.src),
        toUInt32({window_seconds:UInt32})
    ), concat('Tuple(client_error_requests UInt32, distinct_routes UInt32, ',
              'probe_routes_distinct UInt32, probe_routes Array(String), statuses Array(String), ',
              'distinct_user_agents UInt32, services Array(String), peak_window_requests UInt32, ',
              'peak_window_probe_routes UInt32, src_ip_shared_nat Bool, window_seconds UInt32)')))
        AS features,
    c.bucket_start AS bucket_start,
    if(has({shared_nat_ips:Array(String)}, c.src), 'medium', 'high') AS confidence,
    groupUniqArray(16)(e.simulation_run_id) AS simulation_run_ids
FROM crossings AS c
INNER JOIN ev AS e ON e.asset_id = c.asset_id AND e.src = c.src
WHERE e.event_time >= c.first_crossing - toIntervalMillisecond({window_seconds:UInt32} * 1000)
  AND e.event_time <= c.last_crossing
GROUP BY c.asset_id, c.src, c.bucket_start
ORDER BY first_seen
LIMIT 1000
