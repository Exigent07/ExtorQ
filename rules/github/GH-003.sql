-- GH-003 v1.0.0: third-party GitHub Action referenced by a mutable tag or branch.
--
-- Input: github.workflow.modified events (github.api). The collector's workflow analyser
-- lists in attributes.unpinned_actions_added the third-party `uses:` references of the new
-- workflow version that are not pinned to a full 40-hex commit SHA (docker:// images
-- without a sha256 digest included) and were not already unpinned before. Actions owned by
-- GitHub (actions/*, github/*) are not third-party. A tag such as @v3 can be moved by
-- whoever controls the action's repository, so the workflow runs whatever the tag points
-- to next (supply-chain compromise of the action).
-- attributes.unpinned_actions_added is null when the version could not be analysed
-- structurally (lexical fallback): that case is a blind spot, not an alert.
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
            arraySlice(JSONExtract(attributes, 'unpinned_actions_added', 'Array(String)'), 1, 32)
                AS unpinned_added,
            JSONExtract(attributes, 'unpinned_actions_after', 'Array(String)') AS unpinned_after,
            JSONExtractString(attributes, 'change_type') AS change_type,
            JSONExtractString(attributes, 'permissions_after') AS permissions_after
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'github.api'
          AND event_type = 'github.workflow.modified'
          AND gh_commit_sha IS NOT NULL
          AND notEmpty(JSONExtract(attributes, 'unpinned_actions_added', 'Array(String)'))
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
        arraySort(groupUniqArrayArray(32)(e.unpinned_added)),
        toUInt32(length(groupUniqArrayArray(64)(e.unpinned_after))),
        any(e.change_type),
        any(e.permissions_after)
    ), concat('Tuple(unpinned_actions_added Array(String), unpinned_actions_in_workflow UInt32, ',
              'change_type String, permissions_after String)'))) AS features,
    e.commit_sha AS signature,
    'high' AS confidence
FROM ev AS e
GROUP BY e.repository, e.workflow_path, e.commit_sha
ORDER BY first_seen
