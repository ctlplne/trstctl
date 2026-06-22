# Privacy Data Catalog

This catalog is the human-readable copy of `internal/privacy.Catalog()`. It lists
direct personal-data locations, why the field exists, and what the
`privacy.subject.erased` and `privacy.retention.enforced` projections do to
tenant read surfaces.

| ID | Location | Erasure behavior |
| --- | --- | --- |
| `events.actor.subject` | `events.Actor.Subject` | Tenant audit reads replace erased subjects with subject-ref placeholders. |
| `events.data.subject-values` | `events.Event.Data` | Audit reads redact exact erased subject values from old immutable event payloads. |
| `owners.email` | `owners.email` | Blank inactive unreferenced owner email and pseudonymize owner name. |
| `tenant_members.subject` | `tenant_members.subject/display_name/email` | Replace offboarded subjects with erased placeholders and clear display/contact fields. |
| `api_tokens.subject` | `api_tokens.subject` | Revoke direct erasure matches and pseudonymize expired/revoked token subjects. |
| `identities.name-attributes` | `identities.name/attributes` | Pseudonymize terminal identity names and clear attributes. |
| `certificates.subject-sans` | `certificates.subject/sans` | Pseudonymize terminal certificate subjects and clear SANs. |
| `certificates.location-source` | `certificates.deployment_location/source` | Clear terminal deployment location and source values. |
| `ssh_keys.comment-location` | `ssh_keys.comment/location` | Clear orphaned stale SSH key comment and location fields. |
| `attestations.evidence` | `attestations.evidence` | Clear stale evidence JSON. |
| `approvals.actors` | `issuance_approval_requests.requester / issuance_approvals.approver` | Pseudonymize stale requester and approver subjects while preserving resource/action evidence. |
| `profiles.created-by` | `certificate_profiles.created_by` | Pseudonymize stale profile author values. |
| `agents.name` | `agents.name` | Pseudonymize stale agent names while preserving agent id/status/version. |

Default non-audit retention runs every `24h`. It uses these class windows:
owners `17520h`, identities/certificates/approvals/profiles/attestations `9528h`,
SSH keys/agents `4320h`, and access subjects `2160h`. Operators can override
them with the `TRSTCTL_PRIVACY_RETENTION_*` settings in `docs/configuration.md`.

## Data-subject access and portability (PRIVACY-004)

Beyond erasure and retention, an operator answering a data-subject **access /
portability** request can export every record tied to a subject across this catalog
in one tenant-scoped call:

```
POST /api/v1/privacy/subject-exports
{ "subject": "alice@corp.example.com" }
```

The response collects the subject's **owners, identities, certificates** (matched on
subject CN or SAN), **SSH keys, attestations, tenant members, API tokens** (the token
hash is never included — only the principal subject, scopes, and lifecycle
timestamps), and **dual-control approvals** (both requester and approver ties), plus
a per-category `counts` map for completeness. It is a **read** — it changes no state,
so it carries no `Idempotency-Key` — and it reads under PostgreSQL row-level security
for the caller's tenant only (**AN-1**): a subject in another tenant with the same
name is never returned. It requires the `privacy:read` permission.

This is the inverse of the existing subject **erasure**
(`POST /api/v1/privacy/subject-erasures`): export discloses the subject's data,
erasure removes it. Erasure and retention are event-sourced (`privacy.subject.erased`
/ `privacy.retention.enforced`); export is a pure read and emits no event.
