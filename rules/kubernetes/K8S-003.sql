-- K8S-003 v1.0.0: interactive exec/attach into a pod by a human identity.
--
-- Input: kube-apiserver audit events (k8s.api.request, source k8s.audit) of the pods/exec
-- and pods/attach subresources ({subresources}). kubectl >= 1.30 opens the session with a
-- WebSocket upgrade (verb get), older clients with SPDY (verb create); both count. Only
-- sessions the API server accepted are evaluated (response 101 Switching Protocols or 2xx);
-- denied attempts (403) are visible in the audit log but are not this rule.
--
-- Human identity: the authenticated user does not use the reserved 'system:' prefix,
-- which Kubernetes reserves for control-plane components, nodes and every service account
-- (system:serviceaccount:<ns>:<name>). Exact identities in {excluded_users} (reviewed
-- automation that authenticates with a non-system user) are ignored. When the request was
-- impersonated, the authenticated user decides and the impersonated identity is reported.
--
-- One row per (cluster, user, namespace, pod, bucket): repeated sessions of one person in
-- one pod merge into one alert (the engine extends continuous episodes).
-- Confidence (evidence completeness): high when the target pod is named and the session
-- was established (101/2xx); medium otherwise. Duplicate-safe via LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(k8s_cluster, '') AS cluster,
            ifNull(k8s_namespace, '') AS namespace,
            ifNull(k8s_object_name, '') AS pod,
            assumeNotNull(k8s_user) AS user,
            ifNull(k8s_verb, '') AS verb,
            ifNull(k8s_subresource, '') AS subresource,
            assumeNotNull(k8s_response_code) AS code,
            ifNull(k8s_audit_id, '') AS audit_id,
            k8s_user_groups AS groups,
            k8s_source_ips AS source_ips,
            substring(JSONExtractString(payload, 'kubernetes', 'user_agent'), 1, 160) AS user_agent,
            JSONExtractString(attributes, 'impersonated_user') AS impersonated_user,
            -- Request options the audit normaliser reads from the request URI (redacted).
            substring(JSONExtractString(attributes, 'exec_command'), 1, 256) AS command,
            JSONExtractBool(attributes, 'exec_tty') AS tty,
            ifNull(k8s_container, '') AS container,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource = 'pods'
          AND has({subresources:Array(String)}, ifNull(k8s_subresource, ''))
          AND k8s_verb IN ('get', 'create')
          AND k8s_response_code >= 100 AND k8s_response_code < 400
          AND ifNull(k8s_user, '') != ''
          AND NOT startsWith(assumeNotNull(k8s_user), 'system:')
          AND NOT has({excluded_users:Array(String)}, assumeNotNull(k8s_user))
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.cluster, '|', e.user, '|', e.namespace, '|', e.pod) AS group_key,
    any(e.asset_id) AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('cluster', e.cluster, 'user', e.user, 'namespace', e.namespace, 'pod', e.pod) AS entities,
    toJSONString(CAST(tuple(
        toUInt32(uniqExact(e.event_id)),
        arraySort(groupUniqArray(4)(e.subresource)),
        arraySort(groupUniqArray(4)(e.verb)),
        arraySort(groupUniqArray(4)(toString(e.code))),
        arraySort(groupUniqArrayIf(4)(e.impersonated_user, e.impersonated_user != '')),
        arraySort(groupUniqArrayArray(16)(e.groups)),
        arraySort(groupUniqArrayArray(8)(e.source_ips)),
        arraySort(groupUniqArrayIf(4)(e.user_agent, e.user_agent != '')),
        arraySort(groupUniqArrayIf(10)(e.command, e.command != '')),
        arraySort(groupUniqArrayIf(8)(e.container, e.container != '')),
        toBool(max(e.tty)),
        arraySort(groupUniqArrayIf(10)(e.audit_id, e.audit_id != ''))
    ), concat('Tuple(sessions UInt32, subresources Array(String), verbs Array(String), ',
              'response_codes Array(String), impersonated_users Array(String), ',
              'user_groups Array(String), source_ips Array(String), user_agents Array(String), ',
              'commands Array(String), containers Array(String), tty Bool, ',
              'audit_ids Array(String))')))
        AS features,
    e.bucket AS bucket_start,
    if(e.pod != '' AND countIf(e.code = 101 OR (e.code >= 200 AND e.code < 300)) > 0,
       'high', 'medium') AS confidence
FROM ev AS e
GROUP BY e.cluster, e.user, e.namespace, e.pod, e.bucket
ORDER BY first_seen
