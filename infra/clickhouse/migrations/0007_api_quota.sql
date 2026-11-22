-- ExtorQ migration 0007 (API-DATA for D1/A): raise the per-minute query quota of the
-- analyst API's read identity extorq_api_ro from 1200 to 6000 queries.
--
-- Why: every console page costs the API 10-20 ClickHouse queries and one quota is shared
-- by every API process using extorq_api_ro (compose api, dev APIs, live tests). It was
-- exhausted several times while consoles rendered pages in parallel (observed 1276/1200,
-- 1374/1200 and 1434/1200 queries per minute; F-29, C2-IC-9, D1-IC-7), after which every
-- API user got errors until the minute ended. The API also caches its aggregate
-- endpoints for a few seconds now (EXTORQ_API_CACHE_TTL_SECONDS), so 6000 is headroom for
-- several parallel consoles, not a licence for unpaced loops.
--
-- Only the query count changes. The other limits of the interval are restated with the
-- values of 0002 because ALTER QUOTA ... FOR INTERVAL replaces every limit of that
-- interval: a limit left out would become unlimited (verified on ClickHouse 26.8). The
-- settings profile extorq_api_readonly (readonly=2, max_execution_time 30 s, max 60 s,
-- max_result_rows, memory and thread caps) is untouched. KEYED BY user_name and the TO
-- list (extorq_api_ro) are kept by ALTER QUOTA.
--
-- Idempotent: running it again leaves the same limits; IF EXISTS makes it a no-op when
-- the quota does not exist.
ALTER QUOTA IF EXISTS extorq_api_quota
    FOR INTERVAL 1 minute MAX queries = 6000, errors = 300, result_rows = 50000000,
                              read_rows = 5000000000, execution_time = 600;
