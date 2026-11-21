-- K8S-001 v1.0.0: privileged / host-namespace pod denied by Pod Security admission.
--
-- Input: kube-apiserver audit events (k8s.api.request, source k8s.audit) normalised by
-- B2's otlp_k8s: pod create (or ephemeral-container patch/update) answered 403 where the
-- normaliser recorded a Pod Security violation (attributes.pod_security_violation is
-- only set for 403 + "violates PodSecurity") AND the violation concerns privileged mode,
-- host namespaces, hostPath or dangerous capabilities (risk_flags from the request
-- summary, or the violation text). A 403 without a PSA violation (e.g. a mirror pod
-- refused by another admission plugin during bootstrap) never matches.
--
-- Identity: one alert per audit id (PLAN 5.3). Duplicate-safe via LIMIT 1 BY event_id
-- and grouping by audit id (several stages of one request collapse).
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(k8s_cluster, '') AS cluster,
            ifNull(k8s_namespace, '') AS namespace,
            ifNull(k8s_object_name, '') AS object_name,
            ifNull(k8s_user, '') AS user,
            ifNull(k8s_verb, '') AS verb,
            ifNull(k8s_subresource, '') AS subresource,
            assumeNotNull(k8s_audit_id) AS audit_id,
            JSONExtractString(attributes, 'pod_security_violation') AS psa_violation,
            JSONExtractString(attributes, 'pod_security_enforce_policy') AS enforce_policy,
            JSONExtract(attributes, 'risk_flags', 'Array(String)') AS risk_flags,
            JSONExtractBool(attributes, 'dry_run') AS dry_run,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'k8s.audit'
          AND event_type = 'k8s.api.request'
          AND k8s_resource = 'pods'
          AND k8s_response_code = 403
          AND k8s_audit_id IS NOT NULL
          AND ((k8s_verb = 'create' AND ifNull(k8s_subresource, '') = '')
               OR (k8s_verb IN ('patch', 'update') AND k8s_subresource = 'ephemeralcontainers'))
        LIMIT 1 BY event_id
    ),
    matched AS (
        SELECT
            *,
            arrayFilter(f -> has({privileged_flags:Array(String)}, f), risk_flags) AS matched_flags,
            match(psa_violation, {violation_pattern:String}) AS text_match
        FROM ev
        WHERE psa_violation != ''
    )
SELECT
    concat(any(m.cluster), '|', any(m.namespace), '|', any(m.user)) AS group_key,
    any(m.asset_id) AS asset_id,
    any(m.asset_type) AS asset_type,
    min(m.event_time) AS first_seen,
    max(m.event_time) AS last_seen,
    uniqExact(m.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(m.event_time, m.event_id))) AS evidence_event_ids,
    map('cluster', any(m.cluster), 'namespace', any(m.namespace), 'pod', any(m.object_name),
        'user', any(m.user), 'audit_id', m.audit_id) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArrayArray(16)(m.matched_flags)),
        any(m.enforce_policy),
        any(m.verb),
        any(m.subresource),
        toBool(max(m.dry_run)),
        substring(any(m.psa_violation), 1, 400)
    ), concat('Tuple(privileged_flags Array(String), enforce_policy String, verb String, ',
              'subresource String, dry_run Bool, violation String)'))) AS features,
    m.audit_id AS signature,
    if(length(groupUniqArrayArray(16)(m.matched_flags)) > 0 AND max(m.text_match), 'high', 'medium')
        AS confidence,
    groupUniqArray(16)(m.simulation_run_id) AS simulation_run_ids
FROM matched AS m
WHERE length(m.matched_flags) > 0 OR m.text_match
GROUP BY m.audit_id
ORDER BY first_seen
LIMIT 1000
