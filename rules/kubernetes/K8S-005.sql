-- K8S-005 v1.0.0: privileged, host-namespace or hostPath pod ADMITTED by the API server.
--
-- Input (required): kube-apiserver audit events (k8s.api.request, source k8s.audit) of a pod
-- create (no subresource) or of an ephemeral-container patch/update, answered 2xx and not a
-- server-side dry run. The audit policy logs pod writes with their request body; the OTLP
-- normaliser turns it into risk_flags. A row needs at least one flag from
-- {privileged_flags}; run_as_root or harmless added capabilities alone do not count.
-- K8S-001 covers the same requests when Pod Security admission DENIES them.
--
-- Platform exemption (narrow, both conditions): the namespace is one of
-- {platform_namespaces} AND the creator is a kubelet (mirror pods of static manifests,
-- 'system:node:' identities) or a kube-system controller service account (DaemonSet,
-- ReplicaSet, Job controllers create the pods of platform workloads). A person or any other
-- identity creating a privileged pod in a platform namespace is still alerted.
--
-- Corroboration (optional source k8s.api_inventory): the inventory's view of the same named
-- pod (k8s.resource.created/updated, resource_type pods, same cluster/namespace/name) with
-- at least one flag from {privileged_flags}. Pods created by controllers carry no name in
-- the audit record (generateName), so they can only be corroborated by name when the
-- creator chose the name.
--
-- One row per (cluster, namespace, creator, flag signature, bucket): a controller creating
-- several privileged replicas, or one person creating several pods, is one alert per hour.
-- Confidence: high when audit and inventory agree on at least one named pod; medium for the
-- audit record alone. Duplicate-safe via LIMIT 1 BY event_id; the join only feeds
-- conditional aggregates.
WITH
    audit AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            if(startsWith(asset_id, 'k8s:'), splitByChar('/', substring(asset_id, 5))[1], asset_id)
                AS cluster,
            ifNull(k8s_namespace, '') AS namespace,
            ifNull(k8s_object_name, '') AS pod,
            assumeNotNull(k8s_user) AS user,
            ifNull(k8s_verb, '') AS verb,
            ifNull(k8s_subresource, '') AS subresource,
            arraySort(arrayFilter(f -> has({privileged_flags:Array(String)}, f),
                                  JSONExtract(attributes, 'risk_flags', 'Array(String)'))) AS flags,
            JSONExtract(attributes, 'risk_flags', 'Array(String)') AS all_flags,
            JSONExtractString(attributes, 'pod_security_enforce_policy') AS enforce_policy,
            substring(JSONExtractString(attributes, 'pod_security_audit_violations'), 1, 400)
                AS audit_violations,
            JSONExtractString(attributes, 'request_summary') AS summary,
            toDateTime64(toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32})), 3, 'UTC')
                AS bucket
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource = 'pods'
          AND ((k8s_verb = 'create' AND ifNull(k8s_subresource, '') = '')
               OR (k8s_verb IN ('patch', 'update') AND k8s_subresource = 'ephemeralcontainers'))
          AND k8s_response_code >= 200 AND k8s_response_code < 300
          AND ifNull(k8s_user, '') != ''
          AND NOT JSONExtractBool(attributes, 'dry_run')
        LIMIT 1 BY event_id
    ),
    admitted AS (
        SELECT *
        FROM audit
        WHERE length(flags) > 0
          AND NOT (has({platform_namespaces:Array(String)}, namespace)
                   AND (startsWith(user, 'system:node:')
                        OR startsWith(user, 'system:serviceaccount:kube-system:')))
    ),
    state AS (
        SELECT
            event_id,
            event_time,
            if(startsWith(asset_id, 'k8s:'), splitByChar('/', substring(asset_id, 5))[1], asset_id)
                AS cluster,
            ifNull(resource_namespace, '') AS namespace,
            assumeNotNull(resource_name) AS name
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.api_inventory'
          AND event_type IN ('k8s.resource.created', 'k8s.resource.updated')
          AND replaceAll(lower(ifNull(resource_type, '')), ' ', '') IN ('pod', 'pods')
          AND ifNull(resource_name, '') != ''
          AND NOT JSONExtractBool(attributes, 'baseline')
          AND hasAny(JSONExtract(attributes, 'risk_flags', 'Array(String)'),
                     {privileged_flags:Array(String)})
        LIMIT 1 BY event_id
    ),
    joined AS (
        SELECT
            a.*,
            s.event_id AS state_id,
            s.event_id != '' AS corroborated
        FROM admitted AS a
        LEFT JOIN state AS s
            ON s.cluster = a.cluster AND s.namespace = a.namespace AND s.name = a.pod
    )
SELECT
    concat(j.cluster, '|', j.namespace, '|', j.user, '|', arrayStringConcat(j.flags, ','))
        AS group_key,
    any(j.asset_id) AS asset_id,
    any(j.asset_type) AS asset_type,
    min(j.event_time) AS first_seen,
    max(j.event_time) AS last_seen,
    toUInt64(uniqExact(j.event_id) + uniqExactIf(j.state_id, j.corroborated)) AS event_count,
    -- arrayDistinct: one admission can join several inventory rows (created, then updated).
    arrayConcat(arrayDistinct(arrayMap(x -> x.2, groupArraySorted(400)(tuple(j.event_time, j.event_id)))),
                arraySort(groupUniqArrayIf(100)(j.state_id, j.corroborated))) AS evidence_event_ids,
    arraySort(groupUniqArrayIf(100)(j.state_id, j.corroborated)) AS supporting_event_ids,
    map('cluster', j.cluster, 'namespace', j.namespace, 'user', j.user) AS entities,
    toJSONString(CAST(tuple(
        j.flags,
        arraySort(groupUniqArrayArray(16)(j.all_flags)),
        toUInt32(uniqExact(j.event_id)),
        arraySort(groupUniqArrayIf(16)(j.pod, j.pod != '')),
        toUInt32(countIf(j.pod = '')),
        arraySort(groupUniqArray(4)(concat(j.verb, if(j.subresource = '', '', concat('/', j.subresource))))),
        arraySort(groupUniqArrayIf(4)(j.enforce_policy, j.enforce_policy != '')),
        anyIf(j.audit_violations, j.audit_violations != ''),
        startsWith(j.user, 'system:'),
        has({platform_namespaces:Array(String)}, j.namespace),
        toBool(countIf(j.corroborated) > 0)
    ), concat('Tuple(privileged_flags Array(String), risk_flags Array(String), admissions UInt32, ',
              'pods Array(String), unnamed_pods UInt32, requests Array(String), ',
              'enforce_policies Array(String), pod_security_audit_violation String, ',
              'system_identity Bool, platform_namespace Bool, state_corroborated Bool)')))
        AS features,
    j.bucket AS bucket_start,
    if(countIf(j.corroborated) > 0, 'high', 'medium') AS confidence
FROM joined AS j
GROUP BY j.cluster, j.namespace, j.user, j.flags, j.bucket
ORDER BY first_seen
