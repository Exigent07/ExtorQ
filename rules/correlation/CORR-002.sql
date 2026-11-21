-- CORR-002 v1.1.0: ordered multi-stage activity on one Linux host:
--   stage 1  HTTP probing      >= {probe_min_requests} 4xx responses to one source, of which
--                              >= {probe_min_routes} distinct probe-like routes, within
--                              {probe_window_seconds} (sliding window, web-server access logs)
--   stage 2  SSH auth failures  >= {ssh_min_connections} failed connections or
--                              >= {ssh_min_failures} 'Failed <method>' attempts from one source
--                              within {ssh_window_seconds} (sliding window, sshd journald)
--   stage 3  systemd persistence  a unit file created/modified/enabled (inventory diff,
--                              not baseline, not allowlisted) or an auditd watch hit with key
--                              {audit_key} on a unit path that is not a deletion
--                              ({deletion_syscalls}: removing a unit is not persistence)
-- in this order, stage 3 at most {sequence_seconds} after stage 1. Each stage time is the
-- moment its threshold was reached (stage 3: the change itself). ClickHouse windowFunnel
-- gates the assets whose stage markers form the ordered chain; the matching chains are
-- then materialised with explicit time comparisons to collect the evidence.
--
-- This shows ordered co-occurrence on one host, NOT causation. Confidence: medium when the
-- probing and the SSH failures share a source IP that is not a shared NAT/gateway address
-- ({shared_nat_ips}); low otherwise (different sources, or only a NAT address such as the
-- QEMU gateway 10.0.2.2 through which all lab traffic from the Mac arrives).
-- Duplicate-safe: every input is de-duplicated with LIMIT 1 BY event_id; counts are
-- uniqExact; one row per (asset, {bucket_seconds} bucket of the first probe crossing).
WITH
    http AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(src_ip) AS src,
            substring(ifNull(http_route, ''), 1, 256) AS route,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND event_type = 'http.request'
          AND source_type IN ('linux.nginx', 'linux.apache', 'linux.app')
          AND asset_type = 'linux_host'
          AND src_ip IS NOT NULL
          AND http_status >= 400 AND http_status < 500
        LIMIT 1 BY event_id
    ),
    probe_scored AS (
        SELECT
            asset_id,
            src,
            event_time,
            count() OVER w AS n_4xx,
            uniqExactIf(route, match(route, {probe_route_pattern:String})) OVER w AS n_probe_routes
        FROM http
        WINDOW w AS (
            PARTITION BY asset_id, src
            ORDER BY toUnixTimestamp64Milli(event_time)
            RANGE BETWEEN {probe_window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW
        )
    ),
    probe_marks AS (
        SELECT asset_id, src, min(event_time) AS t
        FROM probe_scored
        WHERE n_4xx >= {probe_min_requests:UInt32} AND n_probe_routes >= {probe_min_routes:UInt32}
        GROUP BY asset_id, src,
                 toStartOfInterval(event_time, toIntervalSecond({probe_window_seconds:UInt32}))
    ),
    ssh AS (
        SELECT
            event_id,
            event_time,
            event_type,
            asset_id,
            assumeNotNull(src_ip) AS src,
            src_port,
            substring(ifNull(actor_name, ''), 1, 64) AS user_name,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'linux.journald'
          AND event_type IN ('auth.ssh.login_failed', 'auth.ssh.invalid_user',
                             'auth.ssh.preauth_closed', 'auth.ssh.max_auth_exceeded')
          AND src_ip IS NOT NULL
        LIMIT 1 BY event_id
    ),
    ssh_scored AS (
        SELECT
            asset_id,
            src,
            event_time,
            uniqExact(tuple(src, src_port)) OVER w AS conns,
            countIf(event_type = 'auth.ssh.login_failed') OVER w AS failures
        FROM ssh
        WINDOW w AS (
            PARTITION BY asset_id, src
            ORDER BY toUnixTimestamp64Milli(event_time)
            RANGE BETWEEN {ssh_window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW
        )
    ),
    ssh_marks AS (
        SELECT asset_id, src, min(event_time) AS t
        FROM ssh_scored
        WHERE conns >= {ssh_min_connections:UInt32} OR failures >= {ssh_min_failures:UInt32}
        GROUP BY asset_id, src,
                 toStartOfInterval(event_time, toIntervalSecond({ssh_window_seconds:UInt32}))
    ),
    persist AS (
        SELECT
            event_id,
            event_time,
            event_type,
            asset_id,
            if(ifNull(resource_name, '') != '', assumeNotNull(resource_name),
               arrayLast(x -> x != '', splitByChar('/', ifNull(resource_path, '')))) AS unit,
            ifNull(resource_path, '') AS unit_path,
            ifNull(process_executable, '') AS writer,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND asset_type = 'linux_host'
          AND ((source_type = 'linux.inventory'
                AND event_type IN ('persistence.systemd.unit_created',
                                   'persistence.systemd.unit_modified',
                                   'persistence.systemd.unit_enabled')
                AND NOT JSONExtractBool(attributes, 'baseline'))
               OR (source_type = 'linux.auditd'
                   AND event_type = 'file.audit.watch'
                   AND JSONExtractString(attributes, 'audit_key') = {audit_key:String}
                   AND NOT has({deletion_syscalls:Array(String)},
                               JSONExtractString(attributes, 'syscall'))))
          AND NOT has({allowlist_paths:Array(String)}, ifNull(resource_path, ''))
        LIMIT 1 BY event_id
    ),
    marks AS (
        SELECT asset_id, t, toUInt8(1) AS stage FROM probe_marks
        UNION ALL
        SELECT asset_id, t, toUInt8(2) AS stage FROM ssh_marks
        UNION ALL
        SELECT asset_id, event_time AS t, toUInt8(3) AS stage FROM persist
    ),
    funnel AS (
        SELECT
            asset_id,
            windowFunnel({sequence_seconds:UInt32} * 1000)(
                toUInt64(toUnixTimestamp64Milli(t)), stage = 1, stage = 2, stage = 3) AS level
        FROM marks
        GROUP BY asset_id
    ),
    chains AS (
        SELECT
            p.asset_id AS asset_id,
            toDateTime64(toStartOfInterval(p.t, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket_start,
            min(p.t) AS probe_t,
            min(s.t) AS ssh_t,
            min(x.event_time) AS persist_t,
            max(x.event_time) AS last_persist_t,
            arraySort(groupUniqArray(16)(p.src)) AS probe_srcs,
            arraySort(groupUniqArray(16)(s.src)) AS ssh_srcs
        FROM probe_marks AS p
        INNER JOIN ssh_marks AS s ON s.asset_id = p.asset_id
        INNER JOIN persist AS x ON x.asset_id = p.asset_id
        WHERE s.t > p.t
          AND x.event_time > s.t
          AND x.event_time <= p.t + toIntervalSecond({sequence_seconds:UInt32})
          AND p.asset_id IN (SELECT asset_id FROM funnel WHERE level = 3)
        GROUP BY asset_id, bucket_start
    ),
    probe_ev AS (
        SELECT
            c.asset_id AS asset_id,
            c.bucket_start AS bucket_start,
            any(h.asset_type) AS asset_type,
            min(h.event_time) AS first_t,
            uniqExact(h.event_id) AS n,
            arrayMap(x -> x.2, groupArraySorted(150)(tuple(h.event_time, h.event_id))) AS ids,
            uniqExactIf(h.route, match(h.route, {probe_route_pattern:String})) AS n_routes,
            arraySort(groupUniqArrayIf(10)(h.route, match(h.route, {probe_route_pattern:String})))
                AS routes,
            groupUniqArray(16)(h.simulation_run_id) AS sims
        FROM chains AS c
        INNER JOIN http AS h ON h.asset_id = c.asset_id
        WHERE has(c.probe_srcs, h.src)
          AND h.event_time >= c.probe_t - toIntervalSecond({probe_window_seconds:UInt32})
          AND h.event_time <= c.last_persist_t
        GROUP BY c.asset_id, c.bucket_start
    ),
    ssh_ev AS (
        SELECT
            c.asset_id AS asset_id,
            c.bucket_start AS bucket_start,
            uniqExact(e.event_id) AS n,
            arrayMap(x -> x.2, groupArraySorted(150)(tuple(e.event_time, e.event_id))) AS ids,
            toUInt32(uniqExact(tuple(e.src, e.src_port))) AS connections,
            arraySort(groupUniqArrayIf(10)(e.user_name, e.user_name != '')) AS users,
            groupUniqArray(16)(e.simulation_run_id) AS sims
        FROM chains AS c
        INNER JOIN ssh AS e ON e.asset_id = c.asset_id
        WHERE has(c.ssh_srcs, e.src)
          AND e.event_time >= c.ssh_t - toIntervalSecond({ssh_window_seconds:UInt32})
          AND e.event_time <= c.last_persist_t
        GROUP BY c.asset_id, c.bucket_start
    ),
    persist_ev AS (
        SELECT
            c.asset_id AS asset_id,
            c.bucket_start AS bucket_start,
            max(x.event_time) AS last_t,
            uniqExact(x.event_id) AS n,
            arrayMap(y -> y.2, groupArraySorted(150)(tuple(x.event_time, x.event_id))) AS ids,
            arraySort(groupUniqArrayIf(10)(x.unit, x.unit != '')) AS units,
            arraySort(groupUniqArray(4)(x.event_type)) AS change_types,
            arraySort(groupUniqArrayIf(4)(x.writer, x.writer != '')) AS writers,
            groupUniqArray(16)(x.simulation_run_id) AS sims
        FROM chains AS c
        INNER JOIN persist AS x ON x.asset_id = c.asset_id
        WHERE x.event_time > c.ssh_t
          AND x.event_time <= c.probe_t + toIntervalSecond({sequence_seconds:UInt32})
        GROUP BY c.asset_id, c.bucket_start
    )
SELECT
    c.asset_id AS group_key,
    c.asset_id AS asset_id,
    pe.asset_type AS asset_type,
    pe.first_t AS first_seen,
    xe.last_t AS last_seen,
    toUInt64(pe.n + se.n + xe.n) AS event_count,
    arraySlice(arrayConcat(pe.ids, se.ids, xe.ids), 1, 500) AS evidence_event_ids,
    map('probe_src_ips', arrayStringConcat(c.probe_srcs, ','),
        'ssh_src_ips', arrayStringConcat(c.ssh_srcs, ','),
        'units', arrayStringConcat(xe.units, ',')) AS entities,
    toJSONString(CAST(tuple(
        'http_probe>ssh_auth_failures>systemd_persistence',
        c.probe_t,
        c.ssh_t,
        c.persist_t,
        toUInt32(dateDiff('second', c.probe_t, c.persist_t)),
        toUInt32(pe.n),
        toUInt32(pe.n_routes),
        pe.routes,
        toUInt32(se.n),
        se.connections,
        se.users,
        toUInt32(xe.n),
        xe.units,
        xe.change_types,
        xe.writers,
        length(arrayIntersect(c.probe_srcs, c.ssh_srcs)) > 0,
        length(arrayFilter(ip -> NOT has({shared_nat_ips:Array(String)}, ip),
                           arrayIntersect(c.probe_srcs, c.ssh_srcs))) > 0,
        hasAny({shared_nat_ips:Array(String)}, arrayConcat(c.probe_srcs, c.ssh_srcs)),
        false
    ), concat('Tuple(stage_order String, probe_stage_at DateTime64(3, \'UTC\'), ',
              'ssh_stage_at DateTime64(3, \'UTC\'), persistence_stage_at DateTime64(3, \'UTC\'), ',
              'sequence_seconds UInt32, probe_requests UInt32, probe_routes_distinct UInt32, ',
              'probe_routes Array(String), ssh_failure_events UInt32, ',
              'ssh_failed_connections UInt32, ssh_usernames Array(String), ',
              'persistence_events UInt32, persistence_units Array(String), ',
              'persistence_change_types Array(String), persistence_writers Array(String), ',
              'same_source_ip Bool, same_non_nat_source_ip Bool, source_ip_shared_nat Bool, ',
              'causation_established Bool)')))
        AS features,
    c.bucket_start AS bucket_start,
    if(length(arrayFilter(ip -> NOT has({shared_nat_ips:Array(String)}, ip),
                          arrayIntersect(c.probe_srcs, c.ssh_srcs))) > 0,
       'medium', 'low') AS confidence,
    arraySort(arrayDistinct(arrayConcat(pe.sims, se.sims, xe.sims))) AS simulation_run_ids
FROM chains AS c
INNER JOIN probe_ev AS pe ON pe.asset_id = c.asset_id AND pe.bucket_start = c.bucket_start
INNER JOIN ssh_ev AS se ON se.asset_id = c.asset_id AND se.bucket_start = c.bucket_start
INNER JOIN persist_ev AS xe ON xe.asset_id = c.asset_id AND xe.bucket_start = c.bucket_start
ORDER BY first_seen
LIMIT 1000
