-- P5-L2: a syslog audit feed presents a client certificate to a receiver that
-- requires RFC 5425 mutual TLS. client_cert_ref is the operator-approved
-- reference to that certificate and its key, projected from
-- audit.feed.destination.configured; the key itself never enters this read
-- model. A column with a constant default rewrites no rows.
ALTER TABLE audit_feed_destinations
    ADD COLUMN IF NOT EXISTS client_cert_ref text NOT NULL DEFAULT '';
