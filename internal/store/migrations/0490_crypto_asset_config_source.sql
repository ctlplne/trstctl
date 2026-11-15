-- X2-L7: a host-config fact a product reaches only through its built-in
-- default (nothing in the file states it) records config_source 'default'
-- and product_version, the installed package whose default it is, as the
-- host's package database names it. Projected from cbom.asset.observed. Rows
-- recorded before this are stated facts ('' and ''), as every host-config
-- fact was. Columns with constant defaults rewrite no rows.
ALTER TABLE crypto_assets
    ADD COLUMN IF NOT EXISTS config_source text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS product_version text NOT NULL DEFAULT '';
