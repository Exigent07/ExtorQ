-- K8S-002 v1.0.0: risky RBAC grant observed in the audit log and/or the object state.
--
-- Two independent sources share one risk vocabulary (otlp_k8s.risk_flags_for_summary is
-- used by both the audit normaliser and the inventory collector):
--   audit: successful (2xx) create/update/patch of roles, clusterroles, rolebindings or
--          clusterrolebindings; flags computed from the post-change object. Changes by
--          system controllers listed in {excluded_users} (role aggregation, API server
--          bootstrap reconciliation) are ignored.
--   state: k8s.resource.created/updated inventory diffs of the same kinds carrying risk
--          flags; baseline snapshots and bootstrap objects named 'system:*' are ignored.
-- Only flags in {risky_flags} count. Identity (PLAN 5.3): cluster, kind/namespace/name and
-- the risk signature (sorted risky flags). Confidence is high when audit and state agree.
-- Duplicate-safe: LIMIT 1 BY event_id per source before grouping.
WITH
    audit AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            lower(ifNull(k8s_resource, '')) AS raw_kind,
            ifNull(k8s_namespace, '') AS namespace,
            ifNull(k8s_object_name, '') AS name,
            ifNull(k8s_user, '') AS user,
            ifNull(k8s_verb, '') AS verb,
            JSONExtract(attributes, 'risk_flags', 'Array(String)') AS all_flags,
            JSONExtractString(attributes, 'request_summary') AS summary,
            'audit' AS origin,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource IN ('roles', 'clusterroles', 'rolebindings', 'clusterrolebindings')
          AND k8s_verb IN ('create', 'update', 'patch')
          AND k8s_response_code >= 200 AND k8s_response_code < 300
          AND k8s_object_name IS NOT NULL
          AND NOT has({excluded_users:Array(String)}, ifNull(k8s_user, ''))
        LIMIT 1 BY event_id
    ),
    state AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            replaceAll(lower(ifNull(resource_type, '')), ' ', '') AS raw_kind,
            ifNull(resource_namespace, '') AS namespace,
            ifNull(resource_name, '') AS name,
            '' AS user,
            if(event_type = 'k8s.resource.created', 'state_created', 'state_updated') AS verb,
            JSONExtract(attributes, 'risk_flags', 'Array(String)') AS all_flags,
            '' AS summary,
            'state' AS origin,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.api_inventory'
          AND event_type IN ('k8s.resource.created', 'k8s.resource.updated')
          AND resource_name IS NOT NULL
          AND NOT startsWith(resource_name, 'system:')
          AND NOT JSONExtractBool(attributes, 'baseline')
        LIMIT 1 BY event_id
    ),
    ev AS (
        SELECT
            *,
            multiIf(raw_kind IN ('clusterrolebinding', 'clusterrolebindings'), 'clusterrolebindings',
                    raw_kind IN ('rolebinding', 'rolebindings'), 'rolebindings',
                    raw_kind IN ('clusterrole', 'clusterroles'), 'clusterroles',
                    raw_kind IN ('role', 'roles'), 'roles', '') AS kind,
            arraySort(arrayFilter(f -> has({risky_flags:Array(String)}, f), all_flags)) AS flags,
            if(startsWith(asset_id, 'k8s:'), splitByChar('/', substring(asset_id, 5))[1], asset_id)
                AS cluster
        FROM (SELECT * FROM audit UNION ALL SELECT * FROM state)
    )
SELECT
    concat(e.cluster, '|', e.kind, '|', e.namespace, '|', e.name) AS group_key,
    argMin(e.asset_id, length(e.asset_id)) AS asset_id,
    argMin(e.asset_type, length(e.asset_id)) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('cluster', e.cluster, 'kind', e.kind, 'namespace', e.namespace, 'name', e.name,
        'actor', arrayStringConcat(arraySort(groupUniqArrayIf(4)(e.user, e.user != '')), ','))
        AS entities,
    toJSONString(CAST(tuple(
        e.flags,
        arraySort(groupUniqArray(2)(e.origin)),
        arraySort(groupUniqArrayIf(8)(e.user, e.user != '')),
        arraySort(groupUniqArray(8)(e.verb)),
        anyIf(JSONExtractString(e.summary, 'role_ref'), e.summary != ''),
        arraySort(arraySlice(arrayDistinct(arrayFlatten(groupArrayIf(
            JSONExtract(e.summary, 'subjects', 'Array(String)'), e.summary != ''))), 1, 16))
    ), concat('Tuple(risk_flags Array(String), sources Array(String), actors Array(String), ',
              'verbs Array(String), role_ref String, subjects Array(String))'))) AS features,
    arrayStringConcat(e.flags, ',') AS signature,
    if(uniqExact(e.origin) = 2, 'high', 'medium') AS confidence,
    groupUniqArray(16)(e.simulation_run_id) AS simulation_run_ids
FROM ev AS e
WHERE e.kind != '' AND e.name != '' AND length(e.flags) > 0
GROUP BY e.cluster, e.kind, e.namespace, e.name, e.flags
ORDER BY first_seen
LIMIT 1000
