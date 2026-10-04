-- Audit history can contain pre-UUID administrative scopes. New checkpoints
-- retain their original scope while RLS uses a deterministic UUID key. Existing
-- UUID checkpoints use tenant_id::text as their implicit scope; adding only a
-- nullable column avoids a table rewrite or long exclusive migration lock.
ALTER TABLE audit_checkpoints ADD COLUMN scope_id text;
