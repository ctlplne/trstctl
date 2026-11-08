-- A tenant's certificate recording recovery state. Before a recording
-- appends, it verifies the certificate-metadata history against exact
-- completion receipts and recovers any event a failed SQL transaction left in
-- the log. It used to re-read the tenant's whole history every time (from the
-- recorded leaf's own head, which is the registration for a new leaf), so an
-- import grew quadratically with the inventory. The state bounds that work
-- without dropping the guarantee:
--   recovered_through  every metadata event of the tenant at or below it had
--                      an exact receipt when an earlier scan, under the
--                      metadata fence, last verified it; each scan reads past it.
--   reverify_cursor    each scan also re-verifies one page of the history at
--                      or below the checkpoint, from here, wrapping round, so
--                      the whole history is re-checked continuously.
--   recheck_from       the lowest sequence whose receipt changed since the last
--                      scan (set by the trigger below); the next scan
--                      re-verifies from there, so a changed receipt anywhere is
--                      found at the next append.
-- The state lives on the watermark row: a rebuild, snapshot restore or tenant
-- erase resets it with that row, and a rolled-back recording rolls it back.
ALTER TABLE certificate_metadata_watermarks
    ADD COLUMN recovered_through bigint NOT NULL DEFAULT 0;
ALTER TABLE certificate_metadata_watermarks
    ADD COLUMN reverify_cursor bigint NOT NULL DEFAULT 0;
ALTER TABLE certificate_metadata_watermarks
    ADD COLUMN recheck_from bigint;

CREATE FUNCTION certificate_metadata_receipt_recheck() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    changed bigint := OLD.event_sequence;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        changed := least(OLD.event_sequence, NEW.event_sequence);
    END IF;
    UPDATE certificate_metadata_watermarks
        SET recheck_from = least(coalesce(recheck_from, changed), changed)
        WHERE tenant_id = OLD.tenant_id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER certificate_metadata_receipt_recheck
    AFTER UPDATE OF event_sequence, event_id, event_digest OR DELETE ON certificate_metadata_receipts
    FOR EACH ROW EXECUTE FUNCTION certificate_metadata_receipt_recheck();
