-- Statement-level tenant ordering also covers UPDATE/DELETE that match zero
-- rows. The watermark is event-derived; it is rebuilt/snapshotted with the
-- certificate projection. Unknown utility writes remain unknown until rebuild.
CREATE TABLE certificate_metadata_watermarks (
    tenant_id uuid PRIMARY KEY,
    latest_sequence bigint NOT NULL CHECK (latest_sequence >= 0),
    unknown_write boolean NOT NULL
);
ALTER TABLE certificate_metadata_watermarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_metadata_watermarks FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_metadata_watermarks_isolation ON certificate_metadata_watermarks
    USING (tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON certificate_metadata_watermarks TO trstctl_app;

CREATE FUNCTION lock_certificate_metadata_order(scoped_tenant uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF scoped_tenant IS NULL OR current_setting('trstctl.tenant_id',true)::uuid IS DISTINCT FROM scoped_tenant THEN
        RAISE EXCEPTION 'certificate metadata tenant scope differs';
    END IF;
    -- Keep relation locks before the transaction advisory lock, including when
    -- a statement affects no rows. Full rebuild already owns this whole table.
    LOCK TABLE certificates IN ROW EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
        AND locktype='relation' AND relation='certificates'::regclass
        AND mode='AccessExclusiveLock' AND granted) THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('certificate-metadata-order'||chr(31)||scoped_tenant::text,0));
    END IF;
END;
$$;

CREATE FUNCTION certificate_metadata_statement_order() RETURNS trigger LANGUAGE plpgsql AS $$
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
    INSERT INTO certificate_metadata_watermarks(tenant_id,latest_sequence,unknown_write)
        VALUES(scoped_tenant,event_order,event_order=0)
        ON CONFLICT(tenant_id) DO UPDATE SET
            latest_sequence=greatest(certificate_metadata_watermarks.latest_sequence,excluded.latest_sequence),
            unknown_write=certificate_metadata_watermarks.unknown_write OR excluded.unknown_write;
    RETURN NULL;
END;
$$;

-- Certificate-only ordering provenance for every existing SQL metadata writer.
-- This does not backfill legacy rows from wall time, owner, source, or a guessed
-- event. Zero remains unknown until the existing complete ordered rebuild.
ALTER TABLE certificates
    ADD COLUMN metadata_sequence bigint NOT NULL DEFAULT 0 CHECK (metadata_sequence >= 0);

CREATE FUNCTION certificate_metadata_order() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    event_order bigint;
    trusted_snapshot_restore boolean;
BEGIN
    -- Same owner-role pattern as the existing state-restore trigger, additionally
    -- confined to INSERT while this transaction owns the certificate table.
    trusted_snapshot_restore := TG_OP = 'INSERT'
        AND current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid=TG_RELID)
        AND coalesce(current_setting('trstctl.certificate_snapshot_restore',true),'')='true'
        AND EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
            AND locktype='relation' AND relation=TG_RELID AND mode='AccessExclusiveLock' AND granted);
    IF trusted_snapshot_restore THEN
        RETURN NEW;
    END IF;
    event_order := coalesce(nullif(current_setting('trstctl.certificate_projection_sequence',true),''),'0')::bigint;
    IF event_order < 0 THEN RAISE EXCEPTION 'negative certificate projection sequence'; END IF;
    IF TG_OP='INSERT' THEN
        NEW.metadata_sequence := event_order;
    ELSIF event_order=0 OR OLD.metadata_sequence=0 THEN
        -- Unsequenced legacy utility writes cannot manufacture ordered history.
        NEW.metadata_sequence := 0;
    ELSE
        NEW.metadata_sequence := greatest(OLD.metadata_sequence,event_order);
    END IF;
    RETURN NEW;
END;
$$;

-- UPDATE OF records a writer's intent even if its value happens to be unchanged.
-- Exclusions are only the three recording cursor/origin columns, this fence, and
-- alerted_at (the existing transactional outbox annotation, never overwritten by
-- a recording). Native schema-census tests make future columns require review.
CREATE TRIGGER certificate_metadata_order
BEFORE INSERT OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at
ON certificates FOR EACH ROW EXECUTE FUNCTION certificate_metadata_order();

CREATE TRIGGER certificate_metadata_statement_order
BEFORE INSERT OR DELETE OR UPDATE OF id,tenant_id,owner_id,subject,sans,issuer,serial,
    fingerprint,key_algorithm,not_before,not_after,deployment_location,source,
    created_at,status,replaces_id,revoked_at,revocation_reason,renewed_at,
    issuance_idempotency_key,certificate_der,certificate_pem,issuance_response,
    issuance_request_binding,broker_issuance,key_origin,key_storage,key_exportable,
    key_generated_by,observed_by,observed_kind,last_seen_at
ON certificates FOR EACH STATEMENT EXECUTE FUNCTION certificate_metadata_statement_order();
