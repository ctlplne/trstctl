-- 0192_application_secret_owner.sql — answer who owns a native application
-- secret without placing values or human-readable owner data in the secret row.
--
-- owner_id is tenant-local and nullable for backward compatibility: old event
-- history did not name an owner and must rebuild honestly as unassigned. New
-- create events may bind an existing owners row.

ALTER TABLE secret_store
    ADD COLUMN owner_id uuid;

-- secret_store and its mutation receipts are recovery authority, intentionally
-- preserved while ordinary read models such as owners are atomically rebuilt.
-- A conventional FK would make TRUNCATE owners CASCADE erase sealed secrets.
-- Enforce the same tenant-local relationship at write time without creating that
-- destructive truncate dependency. The projector and API both use tenant-scoped
-- transactions, and this trigger is the final storage-layer AN-1 guard.
CREATE FUNCTION secret_store_owner_tenant_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM owners
         WHERE tenant_id = NEW.tenant_id
           AND id = NEW.owner_id
    ) THEN
        RAISE EXCEPTION 'secret_store owner does not exist in the secret tenant'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;

-- online-safe: installing a metadata-only trigger takes a short catalog lock and
-- does not scan or rewrite existing sealed secret rows.
CREATE TRIGGER secret_store_owner_tenant_guard_trigger
    BEFORE INSERT OR UPDATE OF tenant_id, owner_id ON secret_store
    FOR EACH ROW
    EXECUTE FUNCTION secret_store_owner_tenant_guard();

-- Crash-gap reconciliation must return the same metadata as the original
-- mutation. Existing receipts remain ownerless; new receipts retain only the
-- non-secret UUID, never owner names, emails, or secret values.
ALTER TABLE application_secret_mutation_receipts
    ADD COLUMN result_owner_id uuid;
