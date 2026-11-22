-- GH-001 v1.1.0: GitHub Actions workflow change that escalates privileges.
--
-- Input: github.workflow.modified events from the GitHub collector, whose workflow
-- analyser compares the workflow before/after a commit (attributes write_all_added,
-- added_write_scopes, triggers_added, dangerous_triggers_added, untrusted_checkout_added,
-- effective_permissions_unknown, parse_error_before/after, analysis).
-- Fires when the change adds `permissions: write-all`, adds a sensitive write scope,
-- adds a privileged trigger (pull_request_target, workflow_run, ...) or adds a checkout
-- of untrusted code in a privileged trigger.
-- analysis = 'lexical_fallback' (analyser >= 1.1.0): a version exists but could not be
-- parsed as YAML, so both versions were compared with the bounded lexical scan (fail
-- closed); the same escalation attributes are set from the lexical indicators and
-- effective permissions are unknown.
-- Identity (PLAN 5.3): repository, commit and workflow path. Confidence: medium for a
-- lexical-fallback comparison (indicators found in raw text, job scoping and effective
-- permissions unknown); otherwise high when both versions parsed and effective
-- permissions are known, medium when the repository default permissions are unknown, low
-- when a version did not parse and no lexical comparison was made (analyser 1.0.0).
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(gh_repository, '') AS repository,
            coalesce(gh_workflow_path, resource_path, '') AS workflow_path,
            assumeNotNull(gh_commit_sha) AS commit_sha,
            coalesce(gh_actor_login, actor_name, '') AS actor,
            ifNull(gh_ref, '') AS ref,
            JSONExtractBool(attributes, 'write_all_added') AS write_all_added,
            JSONExtract(attributes, 'added_write_scopes', 'Array(String)') AS added_scopes,
            JSONExtract(attributes, 'triggers_added', 'Array(String)') AS triggers_added,
            JSONExtract(attributes, 'dangerous_triggers_added', 'Array(String)') AS dangerous_added,
            JSONExtractBool(attributes, 'untrusted_checkout_added') AS untrusted_checkout,
            JSONExtractBool(attributes, 'effective_permissions_unknown') AS permissions_unknown,
            JSONExtractString(attributes, 'parse_error_before') AS parse_error_before,
            JSONExtractString(attributes, 'parse_error_after') AS parse_error_after,
            JSONExtractString(attributes, 'permissions_before') AS permissions_before,
            JSONExtractString(attributes, 'permissions_after') AS permissions_after,
            JSONExtractString(attributes, 'change_type') AS change_type,
            JSONExtractString(attributes, 'analysis') AS analysis,
            JSONExtractBool(attributes, 'lexical_truncated') AS lexical_truncated,
            simulation_run_id
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'github.api'
          AND event_type = 'github.workflow.modified'
          AND gh_commit_sha IS NOT NULL
        LIMIT 1 BY event_id
    ),
    scored AS (
        SELECT
            *,
            arrayFilter(s -> has({sensitive_scopes:Array(String)}, s), added_scopes) AS sensitive_added,
            arraySort(arrayDistinct(arrayConcat(
                arrayFilter(t -> has({dangerous_triggers:Array(String)}, t), triggers_added),
                dangerous_added))) AS risky_triggers
        FROM ev
    )
SELECT
    concat(m.repository, '|', m.workflow_path) AS group_key,
    any(m.asset_id) AS asset_id,
    any(m.asset_type) AS asset_type,
    min(m.event_time) AS first_seen,
    max(m.event_time) AS last_seen,
    uniqExact(m.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(m.event_time, m.event_id))) AS evidence_event_ids,
    map('repository', m.repository, 'workflow_path', m.workflow_path, 'commit_sha', m.commit_sha,
        'actor', any(m.actor), 'ref', any(m.ref)) AS entities,
    toJSONString(CAST(tuple(
        toBool(max(m.write_all_added)),
        arraySort(groupUniqArrayArray(16)(m.sensitive_added)),
        arraySort(groupUniqArrayArray(16)(m.added_scopes)),
        arraySort(groupUniqArrayArray(16)(m.risky_triggers)),
        toBool(max(m.untrusted_checkout)),
        any(m.permissions_before),
        any(m.permissions_after),
        any(m.change_type),
        toBool(max(m.permissions_unknown)),
        arraySort(groupUniqArray(4)(if(m.analysis = '', 'unspecified', m.analysis))),
        toBool(max(m.lexical_truncated))
    ), concat('Tuple(write_all_added Bool, sensitive_scopes_added Array(String), ',
              'added_write_scopes Array(String), risky_triggers_added Array(String), ',
              'untrusted_checkout_added Bool, permissions_before String, permissions_after String, ',
              'change_type String, effective_permissions_unknown Bool, ',
              'analysis_methods Array(String), lexical_scan_truncated Bool)'))) AS features,
    m.commit_sha AS signature,
    multiIf(max(m.analysis = 'lexical_fallback'), 'medium',
            max(m.parse_error_before != '' OR m.parse_error_after != ''), 'low',
            max(m.permissions_unknown), 'medium',
            'high') AS confidence,
    groupUniqArray(16)(m.simulation_run_id) AS simulation_run_ids
FROM scored AS m
WHERE m.write_all_added OR length(m.sensitive_added) > 0 OR length(m.risky_triggers) > 0
      OR m.untrusted_checkout
GROUP BY m.repository, m.workflow_path, m.commit_sha
ORDER BY first_seen
LIMIT 1000
