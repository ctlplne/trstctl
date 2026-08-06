-- L1: durable per-customer scoped delegation for provider operators.
--
-- The delegation RULE existed as a library with no store and nothing calling
-- it, so every served provider route still authorised any authenticated
-- operator against any customer. This table is the rule's enforcement data.
--
-- Deliberately NOT under tenant row-level security, and deliberately NOT named
-- tenant_id.
--
-- RLS scopes rows to the tenant making a request. A delegation is read when NO
-- tenant context exists yet: the provider plane is deciding whether this
-- operator may touch that customer AT ALL, which is the question asked before a
-- tenant is selected. Under tenant RLS the row would be invisible at exactly
-- the moment it is needed, and the fail-closed check would refuse every
-- operator — a guard that always fires is a guard nobody keeps.
--
-- The column is customer_tenant_id rather than tenant_id so the RLS inventory
-- (internal/store/rls_inventory.go, doctor ISO-1) does not classify this as a
-- tenant table it must fence. That is a naming choice made to state a fact, not
-- to dodge the guard: this row is not the customer's data, it is the provider's
-- record of who may act on that customer. A tenant has no route to read or
-- write it — access is through the system pool from the provider plane only.

CREATE TABLE IF NOT EXISTS provider_operator_delegations (
    operator_id        text        NOT NULL,
    -- The customer this grant is over. There is deliberately no wildcard row
    -- and no NULL-means-all: a wildcard delegation is indistinguishable from
    -- the unscoped access this mechanism replaces, and it would be reached for
    -- on the first busy day.
    customer_tenant_id text        NOT NULL,
    -- One row per operation. Separate rows rather than an array because the
    -- operations carry different blast radii — provision creates, suspend
    -- interrupts a live service, offboard DESTROYS — and revoking one must not
    -- require rewriting the others.
    operation          text        NOT NULL,
    granted_by         text        NOT NULL DEFAULT '',
    granted_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operator_id, customer_tenant_id, operation)
);

CREATE INDEX IF NOT EXISTS provider_operator_delegations_by_operator
    ON provider_operator_delegations (operator_id);

-- No tenant role reaches this table; the provider plane uses the system pool.
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_operator_delegations TO trstctl_app;

COMMENT ON TABLE provider_operator_delegations IS
    'Provider-plane grants: which operator may perform which operation on which customer. Read outside tenant context, so not under tenant RLS.';
