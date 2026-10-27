-- The deployment KEK's generations (A198).
--
-- Generation 0 is the deployment's local key file (secrets.kek_file). A served
-- rotation moves the deployment KEK to a new generation: a key created and held
-- under an operator wrapper (a local wrapper file, or an HSM key the isolated
-- signer holds), of which only the wrapped form is stored here. While a
-- rotation runs, the next generation is recorded beside the current one and new
-- data is wrapped under it; when every data key has been re-wrapped, the next
-- generation becomes current and the previous one is retired.
--
-- One deployment-wide row, not tenant data: it carries no tenant_id and is read
-- inside every tenant's key-domain fence, so a tenant transaction sees the
-- generation that is current when it seals. It is projected from the
-- deployment.kek.* events the operator tenant records (a monotonic event
-- sequence guards it), is not part of the per-tenant read model, and is never
-- removed by a tenant's offboarding.
CREATE TABLE IF NOT EXISTS deployment_kek_domain (
    singleton                boolean     PRIMARY KEY DEFAULT true,
    domain_id                uuid        NOT NULL,
    generation               bigint      NOT NULL,
    wrapper_kind             text        NOT NULL DEFAULT '',
    wrapper_id               text        NOT NULL DEFAULT '',
    wrapped_kek              bytea,
    next_generation          bigint      NOT NULL DEFAULT 0,
    next_wrapper_kind        text        NOT NULL DEFAULT '',
    next_wrapper_id          text        NOT NULL DEFAULT '',
    next_wrapped_kek         bytea,
    operation_id             text        NOT NULL DEFAULT '',
    operation_status         text        NOT NULL DEFAULT '',
    stage                    text        NOT NULL DEFAULT '',
    progress_cursor          text        NOT NULL DEFAULT '',
    tenants_total            bigint      NOT NULL DEFAULT 0,
    tenants_done             bigint      NOT NULL DEFAULT 0,
    containers_rewrapped     bigint      NOT NULL DEFAULT 0,
    history_events_rewrapped bigint      NOT NULL DEFAULT 0,
    files_rewrapped          bigint      NOT NULL DEFAULT 0,
    containers_verified      bigint      NOT NULL DEFAULT 0,
    verify_passes            bigint      NOT NULL DEFAULT 0,
    verify_stragglers        bigint      NOT NULL DEFAULT 0,
    previous_generation      bigint      NOT NULL DEFAULT 0,
    started_at               timestamptz,
    verified_at              timestamptz,
    rotated_at               timestamptz,
    last_error_code          text        NOT NULL DEFAULT '',
    last_error               text        NOT NULL DEFAULT '',
    operator_tenant_id       text        NOT NULL DEFAULT '',
    last_transition_event_id text        NOT NULL DEFAULT '',
    last_transition_type     text        NOT NULL DEFAULT '',
    last_transition_actor    text        NOT NULL DEFAULT '',
    last_transition_at       timestamptz,
    last_transition_sequence bigint      NOT NULL DEFAULT 0,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deployment_kek_domain_singleton_chk CHECK (singleton),
    CONSTRAINT deployment_kek_domain_generation_chk CHECK (generation >= 0 AND next_generation >= 0),
    -- A generation after 0 is always a wrapped key under a named wrapper.
    CONSTRAINT deployment_kek_domain_current_chk CHECK (
        (generation = 0 AND wrapper_kind = '' AND wrapped_kek IS NULL)
        OR (generation > 0 AND wrapper_kind <> '' AND wrapper_id <> '' AND octet_length(wrapped_kek) > 0)
    ),
    CONSTRAINT deployment_kek_domain_next_chk CHECK (
        (next_generation = 0 AND next_wrapper_kind = '' AND next_wrapped_kek IS NULL)
        OR (next_generation = generation + 1 AND next_wrapper_kind <> '' AND next_wrapper_id <> ''
            AND octet_length(next_wrapped_kek) > 0)
    )
);

-- The application role reads it inside tenant transactions and writes it only
-- through the inline projection of a deployment.kek.* event; it never deletes it.
GRANT SELECT, INSERT, UPDATE ON deployment_kek_domain TO trstctl_app;
