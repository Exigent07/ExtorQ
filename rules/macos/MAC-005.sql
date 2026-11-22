-- MAC-005 v1.0.0: unsigned or ad-hoc signed application bundle installed on a macOS host.
--
-- Input: software.installed events (macos.inventory): an application bundle appeared in an
-- inventoried application directory (/Applications, ~/Applications, one level of
-- sub-folders) between two scans. The collector verifies the code signature of NEW bundles
-- (codesign --verify --strict) and reports attributes.signed: true, false (unsigned, or the
-- signature does not verify, e.g. the bundle was modified after signing) or "unknown" (the
-- check could not run or timed out). attributes.signature_type adds what kind of signature
-- it is; "adhoc" means signed without any identity (codesign -s -), which is how unsigned
-- arm64 code is made runnable and carries no more trust than no signature.
-- Alerts on signed = false (explicit; "unknown" never counts: unknown stays unknown) or
-- signature_type = 'adhoc' (when the collector reports the type).
--
-- No allowlist: an unsigned bundle has no verifiable identity (its bundle id, name and path
-- are whatever its author wrote), so there is nothing robust to key an exception on.
-- Identity: asset + bundle path + bundle version (a reinstall of the same version extends
-- the alert; a new version is a new alert). Confidence (evidence completeness): high when the
-- bundle identity (bundle id) was read together with the signature verdict; medium when the
-- bundle carries no readable Info.plist identity. Duplicate-safe via LIMIT 1 BY event_id.
WITH
    ev AS (
        SELECT
            event_id,
            event_time,
            asset_id,
            asset_type,
            assumeNotNull(resource_path) AS path,
            ifNull(resource_name, '') AS name,
            JSONExtractString(attributes, 'bundle_id') AS bundle_id,
            JSONExtractString(attributes, 'version') AS version,
            JSONExtractRaw(attributes, 'signed') = 'true' AS signed,
            JSONExtractString(attributes, 'signature_type') AS signature_type,
            JSONExtractString(attributes, 'signature_team_id') AS team_id,
            substring(JSONExtractString(attributes, 'signature_error'), 1, 200) AS signature_error,
            JSONExtractString(attributes, 'scope') AS scope
        FROM events
        WHERE event_time >= {window_start:DateTime64(3, 'UTC')}
          AND event_time < {window_end:DateTime64(3, 'UTC')}
          AND source_type = 'macos.inventory'
          AND event_type = 'software.installed'
          AND resource_path IS NOT NULL
          -- JSONExtractRaw distinguishes an explicit false from "unknown", null or a missing key.
          AND (JSONExtractRaw(attributes, 'signed') = 'false'
               OR JSONExtractString(attributes, 'signature_type') = 'adhoc')
        LIMIT 1 BY event_id
    )
SELECT
    concat(e.asset_id, '|', e.path) AS group_key,
    e.asset_id AS asset_id,
    any(e.asset_type) AS asset_type,
    min(e.event_time) AS first_seen,
    max(e.event_time) AS last_seen,
    uniqExact(e.event_id) AS event_count,
    arrayMap(x -> x.2, groupArraySorted(500)(tuple(e.event_time, e.event_id))) AS evidence_event_ids,
    map('path', e.path, 'name', any(e.name), 'bundle_id', any(e.bundle_id)) AS entities,
    toJSONString(CAST(tuple(
        any(e.name),
        any(e.bundle_id),
        e.version,
        toBool(max(e.signed)),
        any(e.signature_type),
        any(e.team_id),
        any(e.signature_error),
        any(e.scope)
    ), concat('Tuple(name String, bundle_id String, version String, signed Bool, ',
              'signature_type String, signature_team_id String, signature_error String, ',
              'scope String)'))) AS features,
    concat(if(e.version != '', e.version, 'version-unknown'), ':', e.path) AS signature,
    if(any(e.bundle_id) != '', 'high', 'medium') AS confidence
FROM ev AS e
GROUP BY e.asset_id, e.path, e.version
ORDER BY first_seen
