-- CR-045: a wrapper change must not change the identity of an already
-- projected secret mutation. V1 remains exact, including its sealed bytes;
-- v2 is a separately domain-separated digest of stable payload ciphertext.
-- Existing receipts start null and require authenticated backfill before a
-- tenant's first rewrap. A later part of this migration adds the durable
-- admission and recovery coordination tables for that operation.
ALTER TABLE application_secret_mutation_receipts
    ADD COLUMN semantic_sha256_v2 CHAR(64);

ALTER TABLE application_secret_mutation_receipts
    ADD CONSTRAINT application_secret_mutation_receipts_semantic_v2_check
    CHECK (semantic_sha256_v2 IS NULL OR semantic_sha256_v2 ~ '^[0-9a-f]{64}$');

COMMENT ON COLUMN application_secret_mutation_receipts.semantic_sha256_v2 IS
    'Version 2 mutation identity over stable payload nonce and ciphertext; only authenticated copy pairs may use this digest after a wrapper change.';

-- Independent, tenant-scoped admission state. The epoch prevents a completed
-- gate from being reused for a later registration of the same tenant UUID.
CREATE TABLE application_secret_rewrap_gates (
    tenant_id UUID PRIMARY KEY,
    tenant_epoch UUID NOT NULL,
    operation_id UUID NOT NULL,
    operation_kind TEXT NOT NULL DEFAULT 'migrate' CHECK (operation_kind IN ('migrate', 'rotate', 'deployment')),
    rewrap_in_progress BOOLEAN NOT NULL DEFAULT FALSE,
    v2_required BOOLEAN NOT NULL DEFAULT FALSE,
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    CHECK (NOT rewrap_in_progress OR v2_required)
);

ALTER TABLE application_secret_rewrap_gates ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_rewrap_gates FORCE ROW LEVEL SECURITY;
CREATE POLICY application_secret_rewrap_gates_isolation
    ON application_secret_rewrap_gates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT ON application_secret_rewrap_gates TO trstctl_app;

-- All three writers use the same transaction lock. An old receipt or fence
-- writer either commits before activation and is included in the check, or
-- reaches this trigger after activation and is refused.
CREATE FUNCTION application_secret_rewrap_gate_lock(p_tenant UUID)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('application-secret-rewrap-gate:' || p_tenant::text, 0));
END;
$$;

CREATE FUNCTION application_secret_rewrap_gate_change()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    live_epoch UUID;
BEGIN
    PERFORM application_secret_rewrap_gate_lock(NEW.tenant_id);
    SELECT epoch_id INTO live_epoch FROM application_secret_tenant_epochs
     WHERE tenant_id = NEW.tenant_id;
    IF live_epoch IS DISTINCT FROM NEW.tenant_epoch THEN
        RAISE EXCEPTION 'application-secret rewrap gate has the wrong tenant epoch';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.tenant_epoch <> NEW.tenant_epoch OR OLD.v2_required AND NOT NEW.v2_required THEN
            RAISE EXCEPTION 'application-secret rewrap gate cannot change its epoch or lower v2 requirement';
        END IF;
        IF OLD.rewrap_in_progress AND NOT NEW.rewrap_in_progress THEN
            NEW.generation := OLD.generation + 1;
        ELSIF NEW.generation <> OLD.generation THEN
            RAISE EXCEPTION 'application-secret rewrap generation is coordinator-owned';
        END IF;
    END IF;
    IF NEW.rewrap_in_progress OR NEW.v2_required THEN
        IF EXISTS (SELECT 1 FROM application_secret_mutation_receipts
                    WHERE tenant_id = NEW.tenant_id AND semantic_sha256_v2 IS NULL) THEN
            RAISE EXCEPTION 'application-secret v1 receipts require authenticated backfill before rewrap';
        END IF;
    END IF;
    IF NEW.rewrap_in_progress AND EXISTS (
        SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'application-secret pending commands must settle before rewrap';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER application_secret_rewrap_gate_change_trg
    BEFORE INSERT OR UPDATE ON application_secret_rewrap_gates
    FOR EACH ROW EXECUTE FUNCTION application_secret_rewrap_gate_change();

CREATE FUNCTION application_secret_rewrap_receipt_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    gate application_secret_rewrap_gates%ROWTYPE;
BEGIN
    PERFORM application_secret_rewrap_gate_lock(NEW.tenant_id);
    SELECT * INTO gate FROM application_secret_rewrap_gates WHERE tenant_id = NEW.tenant_id;
    IF FOUND THEN
        IF gate.rewrap_in_progress THEN
            RAISE EXCEPTION 'application-secret receipt write waits for rewrap completion' USING ERRCODE = 'TR001';
        END IF;
        IF gate.v2_required AND NEW.semantic_sha256_v2 IS NULL THEN
            RAISE EXCEPTION 'application-secret v2 receipt is required after rewrap';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER application_secret_rewrap_receipt_write_trg
    BEFORE INSERT OR UPDATE ON application_secret_mutation_receipts
    FOR EACH ROW EXECUTE FUNCTION application_secret_rewrap_receipt_write();

CREATE FUNCTION application_secret_rewrap_fence_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    armed BOOLEAN;
BEGIN
    PERFORM application_secret_rewrap_gate_lock(NEW.tenant_id);
    SELECT rewrap_in_progress INTO armed FROM application_secret_rewrap_gates
     WHERE tenant_id = NEW.tenant_id;
    IF COALESCE(armed, FALSE) THEN
        RAISE EXCEPTION 'application-secret command waits for rewrap completion' USING ERRCODE = 'TR001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER application_secret_rewrap_fence_write_trg
    BEFORE INSERT OR UPDATE ON application_secret_mutation_fences
    FOR EACH ROW EXECUTE FUNCTION application_secret_rewrap_fence_write();

-- A deployment rewrap freezes its tenant inventory. A registration either
-- commits before activation and is included, or reaches this trigger after
-- activation and must retry when the operation finishes.
CREATE FUNCTION application_secret_deployment_rewrap_lock()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('application-secret-deployment-inventory', 0));
END;
$$;

CREATE FUNCTION application_secret_rewrap_registration_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM application_secret_deployment_rewrap_lock();
    IF EXISTS (SELECT 1 FROM application_secret_rewrap_gates
               WHERE operation_kind = 'deployment' AND rewrap_in_progress) THEN
        RAISE EXCEPTION 'tenant registration waits for deployment key rewrap' USING ERRCODE = 'TR001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER application_secret_rewrap_registration_write_trg
    BEFORE INSERT ON tenants
    FOR EACH ROW EXECUTE FUNCTION application_secret_rewrap_registration_write();

-- These are target-local recovery coordination rows. A restored deployment
-- derives them from its authenticated history, never imports the source
-- deployment's proof rows. Every row is tenant-scoped even for a system-run
-- rebuild; the operation UUID prevents a crashed pass from being reused.
CREATE SCHEMA IF NOT EXISTS trstctl_recovery;
GRANT USAGE ON SCHEMA trstctl_recovery TO trstctl_app;

CREATE TABLE trstctl_recovery.tenant_key_domain_snapshots (
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    event_id TEXT NOT NULL CHECK (event_id <> ''),
    record_kind TEXT NOT NULL DEFAULT 'key_domain'
        CHECK (record_kind IN ('key_domain', 'tenant_registered', 'tenant_offboarded')),
    source_sequence BIGINT NOT NULL CHECK (source_sequence > 0),
    snapshot_sha256 CHAR(64) NOT NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation_id, event_id)
);
ALTER TABLE trstctl_recovery.tenant_key_domain_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.tenant_key_domain_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_key_domain_recovery_isolation
    ON trstctl_recovery.tenant_key_domain_snapshots
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT ON trstctl_recovery.tenant_key_domain_snapshots TO trstctl_app;

CREATE TABLE trstctl_recovery.recovery_pair_proofs (
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    event_id TEXT NOT NULL CHECK (event_id <> ''),
    pair_kind TEXT NOT NULL CHECK (pair_kind <> ''),
    row_id TEXT NOT NULL CHECK (row_id <> ''),
    event_sha256 CHAR(64) NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    row_sha256 CHAR(64) NOT NULL CHECK (row_sha256 ~ '^[0-9a-f]{64}$'),
    key_state_sha256 CHAR(64) NOT NULL CHECK (key_state_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation_id, event_id, pair_kind, row_id)
);
ALTER TABLE trstctl_recovery.recovery_pair_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.recovery_pair_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_pair_proofs_isolation
    ON trstctl_recovery.recovery_pair_proofs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT ON trstctl_recovery.recovery_pair_proofs TO trstctl_app;

-- A full restore records only hashes of event-derived and artifact-retained
-- secret-sync copies before replacing the first-pass outbox. The target-local
-- marker keeps the destination fenced until these pairs authenticate after
-- PostgreSQL key state is imported.
CREATE TABLE trstctl_recovery.restore_outbox_pairs (
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    job_id TEXT NOT NULL CHECK (job_id <> ''),
    event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
    outbox_id BIGINT NOT NULL CHECK (outbox_id > 0),
    event_payload_sha256 CHAR(64) NOT NULL CHECK (event_payload_sha256 ~ '^[0-9a-f]{64}$'),
    row_payload_sha256 CHAR(64) NOT NULL CHECK (row_payload_sha256 ~ '^[0-9a-f]{64}$'),
    event_sealed_sha256 CHAR(64) NOT NULL CHECK (event_sealed_sha256 ~ '^[0-9a-f]{64}$'),
    row_sealed_sha256 CHAR(64) NOT NULL CHECK (row_sealed_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation_id, job_id),
    UNIQUE (tenant_id, operation_id, outbox_id)
);
ALTER TABLE trstctl_recovery.restore_outbox_pairs ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.restore_outbox_pairs FORCE ROW LEVEL SECURITY;
CREATE POLICY restore_outbox_pairs_isolation
    ON trstctl_recovery.restore_outbox_pairs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT ON trstctl_recovery.restore_outbox_pairs TO trstctl_app;
