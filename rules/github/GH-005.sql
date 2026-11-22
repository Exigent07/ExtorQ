-- GH-005 v1.0.0: credential-shaped strings committed to a repository.
--
-- Input: github.secret.exposed events (github.api). The GitHub collector scans the lines a
-- commit ADDS with the credential patterns of extorq.common.redaction and emits one event
-- per (commit, path, line, pattern) with only the pattern name, the location and a
-- redacted match: the value itself is never stored, here or anywhere else.
-- Every event alerts: a credential that reached the repository history is exposed even if
-- a later commit removes it (it must be revoked, not just deleted). One alert per file and
-- commit lists every matched pattern and line (an access key id and its secret in one file
-- are one finding, not two).
--
-- Confidence (what the evidence establishes):
--   high    at least one provider-specific credential format ({specific_patterns}: fixed
--           prefix, length and alphabet, e.g. AKIA..., ghp_..., PEM private keys)
--   medium  only generic assignments (password=..., token: ..., Authorization headers, CLI
--           flags): a value was assigned to a credential-named key, but whether that value
--           is a live credential (and not a placeholder) is not established
-- No path or file-name allowlist: paths are chosen by the committer, and test fixtures are a
-- common hiding place. Identity: repository, path and commit. Duplicate-safe via
-- LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            ifNull(gh_repository, '') AS repository,
            assumeNotNull(gh_commit_sha) AS commit_sha,
            ifNull(resource_path, '') AS path,
            coalesce(gh_actor_login, actor_name, '') AS actor,
            ifNull(gh_ref, '') AS ref,
            JSONExtractString(attributes, 'pattern') AS pattern,
            JSONExtract(attributes, 'line', 'Nullable(UInt32)') AS line,
            substring(JSONExtractString(attributes, 'redacted_match'), 1, 200) AS redacted_match
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'github.api'
          AND event_type = 'github.secret.exposed'
          AND gh_commit_sha IS NOT NULL
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.repository, '|', e.path) AS group_key,
    any(e.asset_id) AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('repository', e.repository, 'path', e.path, 'commit_sha', e.commit_sha,
        'actor', any(e.actor)) AS entities,
    toJSONString(CAST(tuple(
        arraySort(groupUniqArray(16)(e.pattern)),
        arraySort(arrayFilter(p -> has({specific_patterns:Array(String)}, p),
                              groupUniqArray(16)(e.pattern))),
        toBool(countIf(has({specific_patterns:Array(String)}, e.pattern)) > 0),
        arraySort(groupUniqArrayIf(32)(ifNull(e.line, 0), e.line IS NOT NULL)),
        arraySort(groupUniqArray(8)(e.redacted_match)),
        toUInt32(uniqExact(e.event_id)),
        any(e.ref)
    ), concat('Tuple(patterns Array(String), provider_specific_patterns Array(String), ',
              'provider_specific_format Bool, lines Array(UInt32), ',
              'redacted_matches Array(String), matches UInt32, ref String)'))) AS features,
    e.commit_sha AS signature,
    if(countIf(has({specific_patterns:Array(String)}, e.pattern)) > 0, 'high', 'medium') AS confidence
FROM ev AS e
GROUP BY e.repository, e.path, e.commit_sha
ORDER BY first_seen
