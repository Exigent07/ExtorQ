-- GH-001 v2.0.0: GitHub Actions workflow change that escalates GITHUB_TOKEN permissions.
--
-- Input: github.workflow.modified events from the GitHub collector, whose workflow analyser
-- compares the workflow before/after a commit (attributes write_all_added,
-- added_write_scopes, permissions_before/after, effective_permissions_unknown,
-- parse_error_before/after, analysis).
-- Fires when the change adds `permissions: write-all` or adds a write scope from
-- {sensitive_scopes} to the effective token permissions. Privileged triggers with
-- untrusted checkout (GH-002), unpinned actions (GH-003) and script injection (GH-004) are
-- separate rules (v2.0.0: this rule is permission escalation only).
-- analysis = 'lexical_fallback' (analyser >= 1.1.0): a version exists but could not be
-- parsed as YAML, so both versions were compared with the bounded lexical scan (fail
-- closed); the escalation attributes are then set from lexical indicators.
--
-- Identity (PLAN 5.3): repository, commit and workflow path. Confidence (evidence
-- completeness): high when both versions parsed and the effective permissions are known;
-- medium for a lexical-fallback comparison (job scoping unknown) or when the repository's
-- default token permissions are unknown; low when a version did not parse and no lexical
-- comparison was made (analyser 1.0.0). Duplicate-safe via LIMIT 1 BY event_id.
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
            JSONExtractBool(attributes, 'effective_permissions_unknown') AS permissions_unknown,
            JSONExtractString(attributes, 'parse_error_before') AS parse_error_before,
            JSONExtractString(attributes, 'parse_error_after') AS parse_error_after,
            JSONExtractString(attributes, 'permissions_before') AS permissions_before,
            JSONExtractString(attributes, 'permissions_after') AS permissions_after,
            JSONExtractString(attributes, 'change_type') AS change_type,
            JSONExtractString(attributes, 'analysis') AS analysis,
            JSONExtractBool(attributes, 'lexical_truncated') AS lexical_truncated
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
            arrayFilter(s -> has({sensitive_scopes:Array(String)}, s), added_scopes) AS sensitive_added
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
        any(m.permissions_before),
        any(m.permissions_after),
        any(m.change_type),
        toBool(max(m.permissions_unknown)),
        arraySort(groupUniqArray(4)(if(m.analysis = '', 'unspecified', m.analysis))),
        toBool(max(m.lexical_truncated))
    ), concat('Tuple(write_all_added Bool, sensitive_scopes_added Array(String), ',
              'added_write_scopes Array(String), permissions_before String, ',
              'permissions_after String, change_type String, effective_permissions_unknown Bool, ',
              'analysis_methods Array(String), lexical_scan_truncated Bool)'))) AS features,
    m.commit_sha AS signature,
    multiIf(max(m.analysis = 'lexical_fallback'), 'medium',
            max(m.parse_error_before != '' OR m.parse_error_after != ''), 'low',
            max(m.permissions_unknown), 'medium',
            'high') AS confidence
FROM scored AS m
WHERE m.write_all_added OR length(m.sensitive_added) > 0
GROUP BY m.repository, m.workflow_path, m.commit_sha
ORDER BY first_seen
