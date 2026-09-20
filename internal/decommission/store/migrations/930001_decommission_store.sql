-- SPDX-License-Identifier: BUSL-1.1

-- VDEC decommission store (internal/decommission/store) — proprietary
-- Enterprise/Provider. Version 930001 is in the reserved extension high band
-- (>= 900000) and does not collide with PCAS (900xxx), AGID (910xxx), or XREC
-- (920xxx). Every table carries tenant_id and FORCE row-level security keyed on
-- trstctl.tenant_id so cross-tenant reads and writes are denied (AN-1).
--
-- Forward-only by policy: the core migration runner records applied versions and
-- has no down-migration path. Recovery from a bad migration is restore from
-- backup. Every statement here is additive.

CREATE TABLE decommission_key_states (
    tenant_id       uuid   NOT NULL,
    key_id          text   NOT NULL,
    ledger_position bigint NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id)
);

CREATE INDEX decommission_key_states_position
    ON decommission_key_states (tenant_id, ledger_position);

ALTER TABLE decommission_key_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_key_states FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_key_states_isolation ON decommission_key_states
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_key_states TO trstctl_app;

CREATE TABLE decommission_dependents (
    tenant_id             uuid   NOT NULL,
    key_id                text   NOT NULL,
    dependent_class       text   NOT NULL,
    dependent_id          text   NOT NULL,
    registered_ordinal    bigint NOT NULL,
    accounted_ordinal     bigint,
    released_ordinal      bigint,
    erasure_ordinal       bigint,
    ledger_position       bigint NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id, dependent_class, dependent_id),
    CONSTRAINT decommission_dependents_key_state_fk
        FOREIGN KEY (tenant_id, key_id)
        REFERENCES decommission_key_states (tenant_id, key_id)
        ON DELETE CASCADE
);

CREATE INDEX decommission_dependents_accounted
    ON decommission_dependents (tenant_id, key_id, accounted_ordinal, dependent_class, dependent_id);
CREATE INDEX decommission_dependents_registered
    ON decommission_dependents (tenant_id, key_id, registered_ordinal);
CREATE INDEX decommission_dependents_class
    ON decommission_dependents (tenant_id, dependent_class, dependent_id);

ALTER TABLE decommission_dependents ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_dependents FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_dependents_isolation ON decommission_dependents
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_dependents TO trstctl_app;

CREATE TABLE decommission_completion_events (
    tenant_id        uuid   NOT NULL,
    key_id           text   NOT NULL,
    dependent_class  text   NOT NULL,
    dependent_id     text   NOT NULL,
    completion_kind  text   NOT NULL,
    job_id           text   NOT NULL,
    successor_key_id text   NOT NULL DEFAULT '',
    destination      text   NOT NULL DEFAULT '',
    ledger_position  bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id, dependent_class, dependent_id, completion_kind, destination, job_id),
    CONSTRAINT decommission_completion_kind_known
        CHECK (completion_kind IN ('reprotection', 'revocation'))
);

CREATE INDEX decommission_completion_events_dependent
    ON decommission_completion_events (tenant_id, key_id, dependent_class, dependent_id, completion_kind);
CREATE INDEX decommission_completion_events_position
    ON decommission_completion_events (tenant_id, key_id, ledger_position);

ALTER TABLE decommission_completion_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_completion_events FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_completion_events_isolation ON decommission_completion_events
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_completion_events TO trstctl_app;

CREATE TABLE decommission_revocations (
    tenant_id                  uuid   NOT NULL,
    key_id                     text   NOT NULL,
    dependent_class            text   NOT NULL,
    dependent_id               text   NOT NULL,
    destination                text   NOT NULL,
    intent_id                  text   NOT NULL DEFAULT '',
    intent_ledger_position     bigint,
    completion_job_id          text   NOT NULL DEFAULT '',
    completion_ledger_position bigint,
    completed                  boolean NOT NULL DEFAULT false,
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id, dependent_class, dependent_id, destination)
);

CREATE INDEX decommission_revocations_destination
    ON decommission_revocations (tenant_id, key_id, destination, completed);
CREATE INDEX decommission_revocations_dependent
    ON decommission_revocations (tenant_id, key_id, dependent_class, dependent_id, completed);

ALTER TABLE decommission_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE decommission_revocations FORCE ROW LEVEL SECURITY;

CREATE POLICY decommission_revocations_isolation ON decommission_revocations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON decommission_revocations TO trstctl_app;
