-- Evidence references outlive event retention. Record the source event time for
-- new references so the analyst API can distinguish out-of-retention evidence.
-- Historical references keep NULL unless a trusted event is resolved at write time.
ALTER TABLE extorq.alert_evidence
    ADD COLUMN IF NOT EXISTS event_time Nullable(DateTime64(3, 'UTC')) AFTER added_at;
