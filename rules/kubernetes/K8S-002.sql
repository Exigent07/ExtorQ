-- K8S-002 v1.1.0: risky RBAC grant observed in the audit log and/or the object state.
--
-- Two independent sources share one risk vocabulary (otlp_k8s.risk_flags_for_summary is
-- used by both the audit normaliser and the inventory collector):
--   audit: successful (2xx) create/update/patch of roles, clusterroles, rolebindings or
--          clusterrolebindings; flags computed from the post-change object. Ignored: changes
--          by system controllers in {excluded_users} (role aggregation, API server bootstrap
--          reconciliation) and metadata-only writes whose changed metadata fields are all in
--          {ignorable_metadata_fields} (annotations never change what an object grants;
--          labels stay in scope because they drive ClusterRole aggregation).
--   state: k8s.resource.created/updated inventory diffs of the same kinds carrying risk
--          flags; baseline snapshots and bootstrap objects named 'system:*' are ignored.
--
-- Documented platform-bootstrap exception (kubeadm init, v1.1.0). An audit row is not
-- alerted only when ALL of these hold:
--   * verb create by a bootstrap identity in {bootstrap_users}
--   * the object signature kind|namespace|name|roleRef|sorted subjects equals one of the
--     documented kubeadm objects {bootstrap_objects} (same name AND same grant)
--   * the request lies in [birth - {bootstrap_lead_seconds} s, birth +
--     {bootstrap_window_seconds} s] of the cluster's birth: the API server's own successful
--     creation of the kube-system namespace (user system:apiserver, response 201), which
--     happens once per etcd lifetime. No observed birth (ExtorQ attached later, audit gap):
--     no exception (fails closed).
-- A state row is excepted only as the inventory view of such an excepted create (same
-- object, same documented content, inside the same bootstrap window). Everything else
-- alerts, including later writes to the same objects and look-alike names ('kubeadm:x').
--
-- Only flags in {risky_flags} count. Identity (PLAN 5.3): cluster, kind/namespace/name and
-- the risk signature (sorted risky flags). Confidence is high when audit and state agree.
-- Duplicate-safe: LIMIT 1 BY event_id per source before grouping.
WITH
    births AS (
        SELECT
            if(startsWith(asset_id, 'k8s:'), splitByChar('/', substring(asset_id, 5))[1], asset_id)
                AS cluster,
            groupUniqArray(16)(event_time) AS born_at
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
                            - toIntervalSecond({bootstrap_window_seconds:UInt32})
          AND event_time < {window_end:DateTime64(3, 'UTC')}
                           + toIntervalSecond({bootstrap_lead_seconds:UInt32})
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource = 'namespaces'
          AND k8s_verb = 'create'
          AND k8s_object_name = 'kube-system'
          AND k8s_user = 'system:apiserver'
          AND k8s_response_code = 201
        GROUP BY cluster
    ),
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
          AND NOT (JSONExtractBool(attributes, 'metadata_only_change')
                   AND notEmpty(JSONExtract(attributes, 'metadata_fields_changed', 'Array(String)'))
                   AND arrayAll(f -> has({ignorable_metadata_fields:Array(String)}, f),
                                JSONExtract(attributes, 'metadata_fields_changed', 'Array(String)')))
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
            JSONExtractString(attributes, 'object_summary') AS summary,
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
    unified AS (
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
    ),
    classified AS (
        SELECT
            u.event_id AS event_id,
            u.event_time AS event_time,
            u.asset_id AS asset_id,
            u.asset_type AS asset_type,
            u.namespace AS namespace,
            u.name AS name,
            u.user AS user,
            u.verb AS verb,
            u.summary AS summary,
            u.origin AS origin,
            u.simulation_run_id AS simulation_run_id,
            u.kind AS kind,
            u.flags AS flags,
            u.cluster AS cluster,
            concat(u.kind, '|', u.namespace, '|', u.name, '|',
                   JSONExtractString(u.summary, 'role_ref'), '|',
                   arrayStringConcat(arraySort(JSONExtract(u.summary, 'subjects', 'Array(String)')),
                                     ',')) AS object_signature,
            arrayExists(s -> startsWith(s, concat(u.kind, '|', u.namespace, '|', u.name, '|')),
                        {bootstrap_objects:Array(String)}) AS documented_name,
            arrayExists(t -> u.event_time >= t - toIntervalSecond({bootstrap_lead_seconds:UInt32})
                             AND u.event_time <= t + toIntervalSecond({bootstrap_window_seconds:UInt32}),
                        b.born_at) AS in_bootstrap_window
        FROM unified AS u
        LEFT JOIN births AS b ON b.cluster = u.cluster
    ),
    bootstrap_creates AS (
        SELECT cluster, kind, namespace, name
        FROM classified
        WHERE origin = 'audit'
          AND verb = 'create'
          AND has({bootstrap_users:Array(String)}, user)
          AND has({bootstrap_objects:Array(String)}, object_signature)
          AND in_bootstrap_window
    ),
    ev AS (
        SELECT *
        FROM classified
        WHERE NOT (in_bootstrap_window
                   AND has({bootstrap_objects:Array(String)}, object_signature)
                   AND ((origin = 'audit' AND verb = 'create'
                         AND has({bootstrap_users:Array(String)}, user))
                        OR (origin = 'state'
                            AND (cluster, kind, namespace, name) IN
                                (SELECT cluster, kind, namespace, name FROM bootstrap_creates))))
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
            JSONExtract(e.summary, 'subjects', 'Array(String)'), e.summary != ''))), 1, 16)),
        if(e.namespace = '', concat(e.name, ' (cluster-scoped)'), concat(e.namespace, '/', e.name)),
        if(e.namespace = '', 'cluster-scoped', 'namespaced'),
        toBool(max(e.documented_name))
    ), concat('Tuple(risk_flags Array(String), sources Array(String), actors Array(String), ',
              'verbs Array(String), role_ref String, subjects Array(String), object_ref String, ',
              'scope String, documented_bootstrap_object Bool)'))) AS features,
    arrayStringConcat(e.flags, ',') AS signature,
    if(uniqExact(e.origin) = 2, 'high', 'medium') AS confidence,
    groupUniqArray(16)(e.simulation_run_id) AS simulation_run_ids
FROM ev AS e
WHERE e.kind != '' AND e.name != '' AND length(e.flags) > 0
GROUP BY e.cluster, e.kind, e.namespace, e.name, e.flags
ORDER BY first_seen
LIMIT 1000
