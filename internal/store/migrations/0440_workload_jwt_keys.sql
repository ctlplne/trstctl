-- SPDX-License-Identifier: BUSL-1.1
-- N5-L3: rotations of the workload JWT signing key (the key that signs
-- JWT-SVIDs and the tokens the OpenID issuer publishes). Generation 1 is the
-- key provisioned with the SPIFFE protocol; each row is a later generation:
-- published at its rotation, signing from activates_at, and the generation
-- before it published until previous_retires_at. Projected from
-- workload.jwt_key.rotated.
CREATE TABLE workload_jwt_keys (
 tenant_id uuid NOT NULL,
 generation integer NOT NULL CHECK (generation >= 2),
 key_id text NOT NULL CHECK (key_id <> ''),
 published_at timestamptz NOT NULL,
 activates_at timestamptz NOT NULL,
 previous_retires_at timestamptz NOT NULL,
 event_sequence bigint NOT NULL CHECK (event_sequence > 0),
 PRIMARY KEY (tenant_id, generation),
 CHECK (published_at <= activates_at AND activates_at < previous_retires_at)
);
ALTER TABLE workload_jwt_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_jwt_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY workload_jwt_keys_isolation ON workload_jwt_keys
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON workload_jwt_keys TO trstctl_app;
