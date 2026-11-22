-- K8S-004 v1.0.0: secret enumeration by a non-system identity.
--
-- Input: kube-apiserver audit events (k8s.api.request, source k8s.audit) of the secrets
-- resource; the audit policy logs every secret request at Metadata level (never bodies).
-- Only successful requests (2xx) count: the identity actually received the secrets.
-- Two variants, one alert group per (cluster, identity, variant, bucket):
--   cluster_wide     list or watch of secrets with no namespace (kubectl get secrets -A):
--                    one request returns every secret of the cluster
--   namespace_sweep  list of secrets in >= {min_namespaces} distinct namespaces within
--                    {window_seconds} (sliding window): the same enumeration done
--                    namespace by namespace, which evades a cluster-wide-only check
--
-- Excluded by design: control-plane identities (the 'system:' prefix that Kubernetes
-- reserves for components and nodes, except service accounts), every service account of
-- the kube-system namespace (controllers such as the token and namespace controllers watch
-- all secrets), and exact identities in {allowed_identities} (reviewed operators). Service
-- accounts of other namespaces are NOT excluded: a workload token enumerating secrets is
-- the case this rule exists for.
--
-- Confidence: high. The audit record is authoritative for who listed which secrets with
-- which result; there is no second source that could disagree. Duplicate-safe via
-- LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(k8s_cluster, '') AS cluster,
            ifNull(k8s_namespace, '') AS namespace,
            assumeNotNull(k8s_user) AS user,
            ifNull(k8s_verb, '') AS verb,
            assumeNotNull(k8s_response_code) AS code,
            k8s_user_groups AS groups,
            k8s_source_ips AS source_ips,
            substring(JSONExtractString(payload, 'kubernetes', 'user_agent'), 1, 160) AS user_agent,
            JSONExtractString(attributes, 'impersonated_user') AS impersonated_user
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource = 'secrets'
          AND k8s_verb IN ('list', 'watch')
          AND k8s_response_code >= 200 AND k8s_response_code < 300
          AND ifNull(k8s_user, '') != ''
          AND NOT (startsWith(assumeNotNull(k8s_user), 'system:')
                   AND NOT startsWith(assumeNotNull(k8s_user), 'system:serviceaccount:'))
          AND NOT startsWith(assumeNotNull(k8s_user), 'system:serviceaccount:kube-system:')
          AND NOT has({allowed_identities:Array(String)}, assumeNotNull(k8s_user))
        LIMIT 1 BY event_id
    ),
    namespaced AS (
        SELECT * FROM ev WHERE namespace != '' AND verb = 'list'
    ),
    sweep_scored AS (
        SELECT
            cluster,
            user,
            event_time,
            uniqExact(namespace) OVER w AS namespaces_in_window
        FROM namespaced
        WINDOW w AS (
            PARTITION BY cluster, user
            ORDER BY toUnixTimestamp64Milli(event_time)
            RANGE BETWEEN {window_seconds:UInt32} * 1000 PRECEDING AND CURRENT ROW
        )
    ),
    sweep_crossings AS (
        SELECT
            cluster,
            user,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket_start,
            min(event_time) AS first_crossing,
            max(event_time) AS last_crossing,
            max(namespaces_in_window) AS peak_namespaces
        FROM sweep_scored
        WHERE namespaces_in_window >= {min_namespaces:UInt32}
        GROUP BY cluster, user, bucket_start
    ),
    matched AS (
        SELECT
            'cluster_wide' AS variant,
            e.*,
            toDateTime64(toStartOfInterval(e.event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket_start
        FROM ev AS e
        WHERE e.namespace = ''
        UNION ALL
        SELECT
            'namespace_sweep' AS variant,
            n.*,
            c.bucket_start AS bucket_start
        FROM sweep_crossings AS c
        INNER JOIN namespaced AS n ON n.cluster = c.cluster AND n.user = c.user
        WHERE n.event_time >= c.first_crossing - toIntervalMillisecond({window_seconds:UInt32} * 1000)
          AND n.event_time <= c.last_crossing
    )
SELECT
    concat(m.cluster, '|', m.user, '|', m.variant) AS group_key,
    any(m.asset_id) AS asset_id,
    any(m.asset_type) AS asset_type,
    min(m.event_time) AS first_seen,
    max(m.event_time) AS last_seen,
    uniqExact(m.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(m.event_time, m.event_id))) AS evidence_event_ids,
    map('cluster', m.cluster, 'user', m.user, 'variant', m.variant) AS entities,
    toJSONString(CAST(tuple(
        m.variant,
        toUInt32(uniqExact(m.event_id)),
        arraySort(groupUniqArray(2)(m.verb)),
        toUInt32(uniqExactIf(m.namespace, m.namespace != '')),
        arraySort(groupUniqArrayIf(16)(m.namespace, m.namespace != '')),
        startsWith(m.user, 'system:serviceaccount:'),
        arraySort(groupUniqArrayIf(4)(m.impersonated_user, m.impersonated_user != '')),
        arraySort(groupUniqArrayArray(16)(m.groups)),
        arraySort(groupUniqArrayArray(8)(m.source_ips)),
        arraySort(groupUniqArrayIf(4)(m.user_agent, m.user_agent != '')),
        toUInt32({min_namespaces:UInt32}),
        toUInt32({window_seconds:UInt32})
    ), concat('Tuple(variant String, requests UInt32, verbs Array(String), namespaces_count UInt32, ',
              'namespaces Array(String), service_account Bool, impersonated_users Array(String), ',
              'user_groups Array(String), source_ips Array(String), user_agents Array(String), ',
              'min_namespaces UInt32, window_seconds UInt32)'))) AS features,
    m.bucket_start AS bucket_start,
    'high' AS confidence
FROM matched AS m
GROUP BY m.cluster, m.user, m.variant, m.bucket_start
ORDER BY first_seen
