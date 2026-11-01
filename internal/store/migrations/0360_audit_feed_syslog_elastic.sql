-- P5: syslog over TLS and Elasticsearch join the audit feed collectors. A
-- syslog destination may leave token_ref empty: its receiver is then verified
-- through the system roots, and a token_ref, when given, names the receiver's
-- CA certificate rather than a bearer token. Existing destinations and
-- deliveries keep their providers.
ALTER TABLE audit_feed_destinations DROP CONSTRAINT IF EXISTS audit_feed_destination_provider_chk;
ALTER TABLE audit_feed_destinations
    ADD CONSTRAINT audit_feed_destination_provider_chk
    CHECK (provider IN ('splunk-hec', 'sentinel', 'syslog', 'elastic'));
ALTER TABLE audit_feed_destinations DROP CONSTRAINT IF EXISTS audit_feed_destination_required_chk;
ALTER TABLE audit_feed_destinations
    ADD CONSTRAINT audit_feed_destination_required_chk
    CHECK (name <> '' AND endpoint_url <> '' AND (token_ref <> '' OR provider = 'syslog'));
ALTER TABLE audit_feed_deliveries DROP CONSTRAINT IF EXISTS audit_feed_delivery_provider_chk;
ALTER TABLE audit_feed_deliveries
    ADD CONSTRAINT audit_feed_delivery_provider_chk
    CHECK (provider IN ('splunk-hec', 'sentinel', 'syslog', 'elastic'));
