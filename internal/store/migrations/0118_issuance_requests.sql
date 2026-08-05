-- I3: an issuance request as a first-class object with a real lifecycle.
--
-- Today a request is identity metadata plus a row in issuance_approval_requests.
-- That table is a dual-control GATE — keyed on (tenant, resource, action), it
-- answers "have enough people approved this yet". It cannot answer the
-- questions a requester actually has: was my request denied, or is nobody
-- looking? Did it expire? Can I withdraw it?
--
-- Those states are not decoration. A request with no denial state forces a
-- reviewer to either approve or leave it silently rotting, and a queue where
-- rotting and pending look identical is a queue people stop reading. A request
-- with no expiry accumulates forever, so the queue's size stops meaning
-- anything. A request with no cancel forces the requester to ask someone else
-- to clean up after them.

CREATE TABLE IF NOT EXISTS issuance_requests (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL,
    -- What is being asked for.
    subject      text NOT NULL,
    profile      text NOT NULL DEFAULT '',
    -- The CSR, when the requester generated their own key. Empty means the
    -- request does not carry one; it is never a private key, and this column
    -- must never hold key material.
    csr_pem      text NOT NULL DEFAULT '',
    -- Who asked, and why. Justification is NOT optional-in-practice: a reviewer
    -- deciding on a request with no stated reason is rubber-stamping.
    requester    text NOT NULL,
    justification text NOT NULL DEFAULT '',
    -- Where the request came from: 'console', 'api', 'ticket', 'ci'. An
    -- unrecorded origin is distinguishable from a recorded one, as with owner
    -- provenance (I2) — empty means unknown, never 'api'.
    origin       text NOT NULL DEFAULT '',
    -- The external ticket that opened it, when origin is 'ticket'. Lets an
    -- auditor walk from a certificate back to the change record that authorized
    -- it, which is the whole point of ticket intake.
    ticket_ref   text NOT NULL DEFAULT '',
    -- requested | approved | denied | expired | cancelled | issued
    --
    -- 'issued' is separate from 'approved' deliberately: approval is a decision,
    -- issuance is an outcome, and collapsing them would make a request whose
    -- issuance later FAILED look successfully fulfilled.
    status       text NOT NULL DEFAULT 'requested',
    -- Who closed it and why. decided_by is empty for 'expired' — nobody decided,
    -- which is exactly what expiry means and must not be attributed to a person.
    decided_by   text NOT NULL DEFAULT '',
    decision_reason text NOT NULL DEFAULT '',
    decided_at   timestamptz,
    -- The identity minted on success, so the request and the credential are
    -- linked in both directions.
    identity_id  uuid,
    -- When an unattended request stops waiting. NOT NULL: a request that never
    -- expires is a queue entry nobody will ever be forced to look at.
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- AN-1: every table carries tenant_id and every query filters on it.
ALTER TABLE issuance_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_requests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS issuance_requests_tenant_isolation ON issuance_requests;
CREATE POLICY issuance_requests_tenant_isolation ON issuance_requests
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The open queue is what people work from, so that is the indexed path rather
-- than the whole table.
CREATE INDEX IF NOT EXISTS issuance_requests_open_idx
    ON issuance_requests (tenant_id, created_at DESC)
    WHERE status = 'requested';

-- The expiry sweep asks only for requests that are still waiting and past due.
CREATE INDEX IF NOT EXISTS issuance_requests_due_idx
    ON issuance_requests (expires_at)
    WHERE status = 'requested';

GRANT SELECT, INSERT, UPDATE, DELETE ON issuance_requests TO trstctl_app;
