-- GH-002 v1.0.0: privileged workflow trigger that checks out untrusted pull-request code.
--
-- Input: github.workflow.modified events (github.api). The collector's workflow analyser
-- sets attributes.untrusted_checkout_added when the NEW version of the workflow has a
-- privileged trigger (pull_request_target, workflow_run, issue_comment: runs with the base
-- repository's secrets and a write-capable token) AND checks out code controlled by the
-- pull-request author or another run (actions/checkout of the PR head ref/sha/repository,
-- the actions/checkout allow-unsafe-pr-checkout opt-in, gh pr checkout, git fetch of
-- refs/pull/...), and the old version did not. This is the "pwn request" pattern: the
-- untrusted code runs with the privileged context.
-- A privileged trigger WITHOUT a checkout of untrusted code (labelling bots) is the
-- documented safe use of pull_request_target and is not alerted.
--
-- Identity: repository, commit and workflow path. Confidence (evidence completeness): high
-- when both versions parsed (structured analysis); medium for a lexical-fallback comparison
-- (an unparseable version; the indicators were found in raw text without job scoping); low
-- when a version did not parse and no lexical comparison was made. Duplicate-safe via
-- LIMIT 1 BY event_id.
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
            JSONExtractBool(attributes, 'untrusted_checkout_added') AS untrusted_checkout_added,
            JSONExtract(attributes, 'dangerous_triggers_added', 'Array(String)') AS triggers_added,
            JSONExtract(attributes, 'triggers_after', 'Array(String)') AS triggers_after,
            JSONExtract(attributes, 'lexical_evidence', 'Array(String)') AS lexical_evidence,
            JSONExtractString(attributes, 'permissions_after') AS permissions_after,
            JSONExtract(attributes, 'write_scopes_after', 'Array(String)') AS write_scopes_after,
            JSONExtractString(attributes, 'parse_error_before') AS parse_error_before,
            JSONExtractString(attributes, 'parse_error_after') AS parse_error_after,
            JSONExtractString(attributes, 'change_type') AS change_type,
            JSONExtractString(attributes, 'analysis') AS analysis
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'github.api'
          AND event_type = 'github.workflow.modified'
          AND gh_commit_sha IS NOT NULL
          AND JSONExtractBool(attributes, 'untrusted_checkout_added')
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.repository, '|', e.workflow_path) AS group_key,
    any(e.asset_id) AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('repository', e.repository, 'workflow_path', e.workflow_path, 'commit_sha', e.commit_sha,
        'actor', any(e.actor), 'ref', any(e.ref)) AS entities,
    toJSONString(CAST(tuple(
        arraySort(arrayFilter(t -> has({privileged_triggers:Array(String)}, t),
                              groupUniqArrayArray(16)(e.triggers_after))),
        arraySort(groupUniqArrayArray(16)(e.triggers_added)),
        arraySort(groupUniqArrayArray(10)(e.lexical_evidence)),
        any(e.permissions_after),
        arraySort(groupUniqArrayArray(16)(e.write_scopes_after)),
        any(e.change_type),
        arraySort(groupUniqArray(4)(if(e.analysis = '', 'unspecified', e.analysis)))
    ), concat('Tuple(privileged_triggers Array(String), privileged_triggers_added Array(String), ',
              'lexical_evidence Array(String), permissions_after String, ',
              'write_scopes_after Array(String), change_type String, ',
              'analysis_methods Array(String))'))) AS features,
    e.commit_sha AS signature,
    multiIf(max(e.analysis = 'lexical_fallback'), 'medium',
            max(e.parse_error_before != '' OR e.parse_error_after != ''), 'low',
            'high') AS confidence
FROM ev AS e
GROUP BY e.repository, e.workflow_path, e.commit_sha
ORDER BY first_seen
