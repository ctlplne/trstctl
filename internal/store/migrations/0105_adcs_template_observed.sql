-- Keep the template as observed, so drift can be computed (epic F2).
--
-- 0104 stored the VERDICT — worst severity, findings, publishing CAs — which is
-- what the console renders. It did not store the source attributes the verdict
-- was derived from, because nothing needed them.
--
-- Semantic drift does. Comparing two sweeps means comparing what the directory
-- actually said each time: was enrollee-supplies-subject on before, was manager
-- approval there. Without those, a second sweep reconstructs every template with
-- its flags cleared and reports the entire estate as having just turned
-- dangerous — a false-positive storm that would destroy trust in the alert on
-- the first day it ran, and do it loudly.
--
-- So the observed template is kept verbatim. jsonb rather than a column per
-- flag: the attribute set this analysis reads will grow as it learns new
-- dangerous combinations, and a migration per flag would make adding a check
-- expensive enough that people stop adding them.
--
-- online-safe: ADD COLUMN with a constant default is catalog-only in
-- PostgreSQL 11+, and this table is small — one row per certificate template.
ALTER TABLE adcs_template_posture
    ADD COLUMN IF NOT EXISTS observed_template jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN adcs_template_posture.observed_template IS
    'The certificate template exactly as the directory reported it (epic F2), so the next sweep can compute a semantic diff rather than guessing. Attributes only — never a credential.';
