-- Q6-O2: a decoy can be a Kubernetes service account token: a service account
-- bound to nothing whose token Secret sits where a thief looks. The cluster's
-- API server sends its audit events to trstctl; a read of the Secret, or any
-- request made with the token, is a use of the bait. The decoy names the
-- cluster (as the operator registered it), the namespace, the service account
-- and the Secret. Existing decoys keep their kind and content, and none of them
-- is a Kubernetes decoy.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_kind_check;
ALTER TABLE honey_tokens
    ADD CONSTRAINT honey_tokens_kind_check CHECK (kind IN ('native', 'aws', 'secret', 'database', 'file', 'kubernetes'));

ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS k8s_cluster text,
    ADD COLUMN IF NOT EXISTS k8s_namespace text,
    ADD COLUMN IF NOT EXISTS k8s_service_account text,
    ADD COLUMN IF NOT EXISTS k8s_secret text;

ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_aws_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_aws_complete CHECK (
    (kind IN ('native', 'secret', 'database', 'file', 'kubernetes') AND aws_account_config_id IS NULL AND aws_account_id IS NULL
     AND aws_access_key_id IS NULL AND aws_lease_id IS NULL AND aws_regions IS NULL
     AND aws_poll_interval_seconds IS NULL)
    OR
    (kind = 'aws' AND aws_account_config_id IS NOT NULL AND aws_account_id ~ '^[0-9]{12}$'
     AND aws_access_key_id IS NOT NULL AND aws_lease_id IS NOT NULL
     AND cardinality(aws_regions) BETWEEN 1 AND 32
     AND aws_poll_interval_seconds BETWEEN 60 AND 3600)
);

-- A Kubernetes decoy names its cluster, namespace, service account and token
-- Secret, in Kubernetes' own name forms; no other kind names any of them.
ALTER TABLE honey_tokens DROP CONSTRAINT IF EXISTS honey_tokens_kubernetes_complete;
ALTER TABLE honey_tokens ADD CONSTRAINT honey_tokens_kubernetes_complete CHECK (
    CASE WHEN kind = 'kubernetes'
         THEN k8s_cluster IS NOT NULL AND k8s_cluster ~ '^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$'
              AND k8s_namespace IS NOT NULL AND k8s_namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
              AND k8s_service_account IS NOT NULL AND k8s_service_account ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
              AND k8s_secret IS NOT NULL AND k8s_secret ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
         ELSE k8s_cluster IS NULL AND k8s_namespace IS NULL AND k8s_service_account IS NULL AND k8s_secret IS NULL
    END
);
