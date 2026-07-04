-- CORRECT-003: lifecycle read-model identity is tenant-scoped. The original
-- owners/issuers/identities schema had both a global PRIMARY KEY (id) and a
-- tenant-composite UNIQUE (tenant_id, id). Projection replay targets the
-- tenant-composite key, so a duplicate can still surface as owners_pkey before
-- the served lifecycle gate reaches issuance. Replace only the old single-column
-- primary keys with composite primary keys; existing composite foreign keys keep
-- their tenant consistency.

DO $$
DECLARE
    id_attnum smallint;
BEGIN
    SELECT attnum INTO id_attnum
      FROM pg_attribute
     WHERE attrelid = 'owners'::regclass AND attname = 'id';

    IF EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'owners'::regclass
           AND conname = 'owners_pkey'
           AND contype = 'p'
           AND conkey = ARRAY[id_attnum]
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE owners DROP CONSTRAINT owners_pkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'owners'::regclass AND contype = 'p'
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE owners ADD CONSTRAINT owners_pkey PRIMARY KEY (tenant_id, id);
    END IF;
END $$;

DO $$
DECLARE
    id_attnum smallint;
BEGIN
    SELECT attnum INTO id_attnum
      FROM pg_attribute
     WHERE attrelid = 'issuers'::regclass AND attname = 'id';

    IF EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'issuers'::regclass
           AND conname = 'issuers_pkey'
           AND contype = 'p'
           AND conkey = ARRAY[id_attnum]
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'issuers'::regclass AND contype = 'p'
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE issuers ADD CONSTRAINT issuers_pkey PRIMARY KEY (tenant_id, id);
    END IF;
END $$;

DO $$
DECLARE
    id_attnum smallint;
BEGIN
    SELECT attnum INTO id_attnum
      FROM pg_attribute
     WHERE attrelid = 'identities'::regclass AND attname = 'id';

    IF EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'identities'::regclass
           AND conname = 'identities_pkey'
           AND contype = 'p'
           AND conkey = ARRAY[id_attnum]
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE identities DROP CONSTRAINT identities_pkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'identities'::regclass AND contype = 'p'
    ) THEN
        -- online-safe: constraint-only lifecycle catalog PK swap, SCHEMA-007 harness proves rows/FKs/RLS before and after.
        ALTER TABLE identities ADD CONSTRAINT identities_pkey PRIMARY KEY (tenant_id, id);
    END IF;
END $$;
