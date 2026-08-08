-- Constrained edge sub-CA delegations (epic B6).
--
-- B6 is the one deliberate exception to "signing lives only in the isolated
-- signer" (AN-3/AN-4): a host with no path to the brain runs a tightly bounded
-- delegated issuing CA locally. These tables are the brain's record of that
-- exception — which segments opted in and under what attestation policy, which
-- delegations were minted and where they stand, and every local issuance that
-- reconciled back. A delegation the brain has no row for does not exist; a
-- local issuance that never reconciles is exactly the shadow issuance this
-- schema exists to make visible. Per AN-1 every row carries tenant_id under
-- row-level security.

-- edge_segment_policies is the per-segment opt-in, OFF until a row says
-- otherwise. Enabling is one declaration: the TPM attestation roots that may
-- vouch for hosts in the segment, and the DNS identifiers the segment owns —
-- which become the name constraints of every delegation minted for it. The
-- mint path takes its constraints from here, never from the request, so a
-- host cannot ask for a wider scope than its segment declared.
CREATE TABLE edge_segment_policies (
    tenant_id             uuid        NOT NULL,
    segment_id            uuid        NOT NULL,
    enabled               boolean     NOT NULL,
    attestation_roots_pem text[]      NOT NULL,
    permitted_dns_domains text[]      NOT NULL,
    excluded_dns_domains  text[]      NOT NULL,
    updated_at            timestamptz NOT NULL,
    event_sequence        bigint      NOT NULL,
    PRIMARY KEY (tenant_id, segment_id)
);

ALTER TABLE edge_segment_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_segment_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY edge_segment_policies_isolation ON edge_segment_policies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON edge_segment_policies TO trstctl_app;

-- edge_delegations: one row per delegated CA the isolated signer minted. The
-- certificate carries the real bounds (name constraints, path length zero,
-- short validity); this row is the brain's handle for showing, expiring and
-- revoking it. Revocation also lands in ca_issued_certs under the parent CA,
-- so OCSP and the CRL answer for a revoked delegation with no new machinery.
CREATE TABLE edge_delegations (
    tenant_id             uuid        NOT NULL,
    id                    uuid        NOT NULL,
    segment_id            uuid        NOT NULL,
    ca_id                 uuid        NOT NULL,
    host                  text        NOT NULL,
    common_name           text        NOT NULL,
    serial                text        NOT NULL,
    certificate_pem       text        NOT NULL,
    permitted_dns_domains text[]      NOT NULL,
    excluded_dns_domains  text[]      NOT NULL,
    -- The attested key's SHA-256 and the attestation certificate's SHA-256,
    -- recorded so the delegation is traceable to the hardware that vouched.
    attested_key_sha256   text        NOT NULL,
    attestation_cert_sha256 text      NOT NULL,
    status                text        NOT NULL, -- 'active' | 'revoked'
    not_before            timestamptz NOT NULL,
    not_after             timestamptz NOT NULL,
    revoked_at            timestamptz,
    revoke_reason         text        NOT NULL,
    created_at            timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL,
    event_sequence        bigint      NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, ca_id, serial)
);

ALTER TABLE edge_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_delegations FORCE ROW LEVEL SECURITY;

CREATE POLICY edge_delegations_isolation ON edge_delegations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The console's first question is "what is live in this segment".
CREATE INDEX edge_delegations_segment_idx
    ON edge_delegations (tenant_id, segment_id, status, not_after);

GRANT SELECT, INSERT, UPDATE, DELETE ON edge_delegations TO trstctl_app;

-- edge_issuances: the reconciled ledger of what a delegated CA issued while
-- the host was unreachable. One row per (delegation, serial), written only by
-- the reconcile projector after the brain re-verified the reported leaf:
-- signature chains to the delegated CA and the names sit inside the
-- delegation's constraints. within_constraints records the verdict — a leaf
-- outside them is recorded AND flagged, never silently dropped, because a
-- refused report would leave the shadow issuance invisible, which is the
-- outcome this table exists to prevent.
CREATE TABLE edge_issuances (
    tenant_id          uuid        NOT NULL,
    delegation_id      uuid        NOT NULL,
    serial             text        NOT NULL,
    subject            text        NOT NULL,
    dns_names          text[]      NOT NULL,
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    issued_at          timestamptz NOT NULL,
    reconciled_at      timestamptz NOT NULL,
    within_constraints boolean     NOT NULL,
    violation          text        NOT NULL,
    event_sequence     bigint      NOT NULL,
    PRIMARY KEY (tenant_id, delegation_id, serial)
);

ALTER TABLE edge_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_issuances FORCE ROW LEVEL SECURITY;

CREATE POLICY edge_issuances_isolation ON edge_issuances
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The panel lists a delegation's reconciled issuances newest-first, and the
-- violations view scans the flag.
CREATE INDEX edge_issuances_delegation_idx
    ON edge_issuances (tenant_id, delegation_id, reconciled_at DESC);
CREATE INDEX edge_issuances_violation_idx
    ON edge_issuances (tenant_id, within_constraints);

GRANT SELECT, INSERT, UPDATE, DELETE ON edge_issuances TO trstctl_app;
