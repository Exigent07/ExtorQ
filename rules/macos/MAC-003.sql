-- MAC-003 v1.0.0: TCP listener exposed on all interfaces by a non-allowlisted process.
--
-- Input: network.listener.opened events (macos.inventory) from the macOS collector's
-- listening-socket diff (lsof): a TCP socket in LISTEN state bound to an "any" address
-- ({any_addresses}: 0.0.0.0 or ::) that was not present in the previous scan. Such a socket
-- accepts connections from every network the Mac joins (a bind shell, a debug server, a
-- tool started with --host 0.0.0.0). Loopback listeners are local-only and never match.
-- UDP is out of scope: lsof lists every bound, unconnected UDP client socket (DNS, mDNS,
-- QUIC) as a "listener", which is noise, not exposure.
--
-- Allowlist: exact executable paths ({allowlist_executables}) of software that is supposed
-- to listen on all interfaces. The defaults are Apple system daemons under
-- SIP-protected locations (Continuity, AirPlay receiver, launchd socket activation): their
-- path cannot be occupied by another binary while System Integrity Protection is on. A
-- listener whose owning executable is unknown is never allowlisted (fails closed).
--
-- One row per (asset, port, executable, bucket). Confidence (evidence completeness): high
-- when lsof attributed the socket to an executable; medium when the owner is unknown.
-- Duplicate-safe via LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(dst_ip) AS address,
            assumeNotNull(dst_port) AS port,
            ifNull(process_executable, '') AS executable,
            ifNull(process_name, '') AS process,
            JSONExtract(attributes, 'pids', 'Array(UInt32)') AS pids,
            JSONExtract(attributes, 'users', 'Array(String)') AS users,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.inventory'
          AND event_type = 'network.listener.opened'
          AND net_protocol = 'tcp'
          AND has({any_addresses:Array(String)}, ifNull(dst_ip, ''))
          AND dst_port IS NOT NULL
          AND NOT has({allowlist_executables:Array(String)}, ifNull(process_executable, ''))
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.asset_id, '|tcp/', toString(e.port), '|', if(e.executable != '', e.executable, 'unknown'))
        AS group_key,
    e.asset_id AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('port', toString(e.port), 'executable', e.executable, 'process', any(e.process)) AS entities,
    toJSONString(CAST(tuple(
        toUInt32(e.port),
        arraySort(groupUniqArray(4)(e.address)),
        if(e.executable != '', e.executable, ''),
        any(e.process),
        arraySort(groupUniqArrayArray(8)(e.pids)),
        arraySort(groupUniqArrayArray(4)(e.users)),
        e.executable != ''
    ), concat('Tuple(port UInt32, bind_addresses Array(String), executable String, ',
              'process String, pids Array(UInt32), users Array(String), owner_known Bool)')))
        AS features,
    e.bucket AS bucket_start,
    if(e.executable != '', 'high', 'medium') AS confidence
FROM ev AS e
GROUP BY e.asset_id, e.port, e.executable, e.bucket
ORDER BY first_seen
