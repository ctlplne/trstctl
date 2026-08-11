-- 0162_secret_sync_recovery_authority.sql -- durable event-only restore fence.
--
-- Secret-sync events rebuild command intent, but they cannot reconstruct whether
-- a worker generation had already crossed the external receiver boundary. A
-- logical event-only restore therefore records one deployment-local red light.
-- Only the full-restore coordinator may turn it green after importing and
-- validating the paired PostgreSQL receiver rows.

CREATE TABLE secret_sync_recovery_authority (
    singleton                    boolean     PRIMARY KEY DEFAULT true,
    receiver_io_authorized       boolean     NOT NULL,
    reason                       text        NOT NULL,
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secret_sync_recovery_authority_singleton_chk CHECK (singleton),
    CONSTRAINT secret_sync_recovery_authority_shape_chk CHECK (
        (receiver_io_authorized AND reason = '')
        OR (NOT receiver_io_authorized AND reason <> '')
    )
);

INSERT INTO secret_sync_recovery_authority
       (singleton, receiver_io_authorized, reason)
VALUES (true, true, '');

-- Receiver workers enter through the owner-role projection transaction. The
-- application role must never be able to clear a restore fence by SQL.
REVOKE ALL ON secret_sync_recovery_authority FROM trstctl_app;
