-- Exact completion of certificate-dependent events, including zero-row effects.
-- No legacy backfill: a watermark or current row cannot prove an old execution.
CREATE TABLE certificate_metadata_receipts (
    tenant_id uuid NOT NULL,
    event_sequence bigint NOT NULL CHECK(event_sequence>0),
    event_id text NOT NULL CHECK(event_id<>''),
    event_digest text NOT NULL CHECK(event_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(tenant_id,event_sequence),
    UNIQUE(tenant_id,event_id)
);
ALTER TABLE certificate_metadata_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_metadata_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_metadata_receipts_isolation ON certificate_metadata_receipts
    USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
    WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON certificate_metadata_receipts TO trstctl_app;

CREATE OR REPLACE FUNCTION certificate_metadata_statement_order() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scoped_tenant uuid := current_setting('trstctl.tenant_id',true)::uuid;
    event_order bigint := coalesce(nullif(current_setting('trstctl.certificate_projection_sequence',true),''),'0')::bigint;
    event_tenant uuid := nullif(current_setting('trstctl.certificate_projection_tenant',true),'')::uuid;
BEGIN
    PERFORM lock_certificate_metadata_order(scoped_tenant);
    IF TG_OP='INSERT' AND current_user=(SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid=TG_RELID)
        AND coalesce(current_setting('trstctl.certificate_snapshot_restore',true),'')='true'
        AND EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation'
            AND relation=TG_RELID AND mode='AccessExclusiveLock' AND granted) THEN
        RETURN NULL;
    END IF;
    IF event_order<0 OR (event_order>0 AND event_tenant IS DISTINCT FROM scoped_tenant) THEN
        RAISE EXCEPTION 'certificate statement sequence has wrong tenant or invalid order';
    END IF;
    -- A stale predicate may now match zero rows, so reject before the statement,
    -- not from a row trigger. Exact completed repeats are skipped by the
    -- projector under this same tenant lock before any of their effects run.
    IF event_order>0 AND EXISTS (SELECT 1 FROM certificate_metadata_watermarks
        WHERE tenant_id=scoped_tenant AND (unknown_write OR latest_sequence>event_order)) THEN
        RAISE EXCEPTION 'certificate metadata event requires complete ordered rebuild'
            USING ERRCODE='TC001';
    END IF;
    INSERT INTO certificate_metadata_watermarks(tenant_id,latest_sequence,unknown_write)
        VALUES(scoped_tenant,event_order,event_order=0)
        ON CONFLICT(tenant_id) DO UPDATE SET
            latest_sequence=greatest(certificate_metadata_watermarks.latest_sequence,excluded.latest_sequence),
            unknown_write=certificate_metadata_watermarks.unknown_write OR excluded.unknown_write;
    RETURN NULL;
END;
$$;
