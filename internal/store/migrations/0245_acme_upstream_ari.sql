-- RFC 9773 observations are per exact external-CA certificate, not per DNS
-- name or authority. The immutable observation event is the source of truth;
-- this tenant-RLS row is its rebuildable scheduling and operator projection.
CREATE TABLE acme_upstream_ari (
    tenant_id           uuid NOT NULL,
    certificate_id      uuid NOT NULL,
    authority_id        text NOT NULL,
    certificate_id_ari  text NOT NULL,
    fingerprint         text NOT NULL,
    status              text NOT NULL CHECK (status IN ('queued', 'ready', 'error', 'unavailable')),
    window_start        timestamptz,
    window_end          timestamptz,
    updated_at          timestamptz NOT NULL,
    fetched_at          timestamptz,
    next_poll_at        timestamptz NOT NULL,
    failure_count       integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    error_class         text NOT NULL DEFAULT '',
    event_sequence      bigint NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, certificate_id),
    CHECK ((window_start IS NULL) = (window_end IS NULL)),
    CHECK (window_start IS NULL OR window_end > window_start),
    CHECK (status <> 'ready' OR window_start IS NOT NULL)
);

CREATE INDEX acme_upstream_ari_due_idx
    ON acme_upstream_ari (tenant_id, next_poll_at, certificate_id);

ALTER TABLE acme_upstream_ari ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_upstream_ari FORCE ROW LEVEL SECURITY;
CREATE POLICY acme_upstream_ari_isolation ON acme_upstream_ari
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON acme_upstream_ari TO trstctl_app;
