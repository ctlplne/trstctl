-- P5-L4: an Elasticsearch audit feed presents its credential as an API key
-- (the default, empty), with basic auth or as a bearer token. The scheme is a
-- projection of audit.feed.destination.configured, which checks it against the
-- closed set; the credential itself stays behind token_ref and never enters
-- this read model. A column with a constant default rewrites no rows.
ALTER TABLE audit_feed_destinations
    ADD COLUMN IF NOT EXISTS auth_scheme text NOT NULL DEFAULT '';
