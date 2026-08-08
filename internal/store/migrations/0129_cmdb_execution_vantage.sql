-- I2: which vantage executes the CMDB sync.
--
-- The reconcile ran only in the control plane, so a ServiceNow instance
-- reachable only from a private segment needed a private-egress grant into it.
-- The epic's model is the relay's: the domain-joined relay already sits inside
-- the segment, and reading the CMDB from there needs no hole through the
-- firewall at all.
--
-- NULLABLE, nothing backfilled, per 0121's rule: NULL is the honest value for
-- every existing schedule — nobody chose a vantage, and the behaviour they
-- have (control-plane execution) continues. Writing 'control_plane' into
-- existing rows would fabricate a recorded choice.
ALTER TABLE cmdb_reconcile_schedules
    ADD COLUMN IF NOT EXISTS execution text;

COMMENT ON COLUMN cmdb_reconcile_schedules.execution IS
    'control_plane | relay, or NULL meaning the control plane runs the sync, as before (epic I2). relay dispatches a cmdb.sync job claimed by a network relay inside the segment; the token_ref must then be a secret:// reference the redemption path can resolve.';
