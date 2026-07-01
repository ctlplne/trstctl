# Privacy Data Catalog

This catalog is the human-readable copy of the platform's machine-readable privacy
catalog. It lists direct personal-data locations, why the field exists, and what
the `privacy.subject.erased` and `privacy.retention.enforced` projections do to
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
| `pam_sessions.subjects` | `pam_sessions.subject/requested_by/reason/audit` | Subject export includes matching rows; subject erasure pseudonymizes matching subject/requester fields and clears free-form reason/audit metadata; retention covers terminal PAM session metadata after the access window. |
| `discovery_findings.triage` | `discovery_findings.triage_actor/triage_reason` | Subject export includes matching rows; subject erasure pseudonymizes matching triage actors and clears free-form triage reasons; retention covers stale triage metadata after discovery evidence ages out. |
| `notification_threshold_deliveries.subject` | `notification_threshold_deliveries.subject/channel` | Subject export includes matching rows; subject erasure pseudonymizes matching threshold-delivery subjects/channels; retention covers stale threshold-delivery metadata after notification evidence ages out. |
| `incident_executions.operator-evidence` | `incident_executions.created_by/reason/evidence_bundle/failed_targets/rollback_refs` | Subject export includes matching rows; subject erasure pseudonymizes matching operators and clears free-form incident evidence while preserving non-PII status and identity IDs; retention covers stale incident evidence. |
| `nhi_access_reviews.actors` | `nhi_access_review_campaigns.reviewer_subject/requested_by; nhi_access_review_items.decision_by/decision_reason` | Subject export includes matching rows; subject erasure pseudonymizes matching access-review actors and clears free-form decision metadata; retention covers stale access-review metadata after governance evidence ages out. |
| `access_change_requests.actors` | `access_change_requests.requester_subject/reason; access_change_request_decisions.approver_subject/reason` | Subject export includes matching rows; subject erasure pseudonymizes matching requester/approver subjects and clears free-form reasons/evidence refs; retention covers stale access-change metadata after governance evidence ages out. |
| `discovery_runs.requester` | `discovery_runs.requested_by` | Subject export includes matching rows; subject erasure pseudonymizes matching discovery run requesters; retention covers stale requester subjects after discovery evidence ages out. |
| `notification_routing_policies.owner-contact` | `notification_routing_policies.owner_ref/owner_email` | Subject export includes matching rows; subject erasure pseudonymizes matching routing owners and clears matching contact metadata; retention covers stale routing owner/contact metadata after routing evidence ages out. |
| `remediation_playbook_runs.operator-evidence` | `remediation_playbook_runs.created_by/reason/evidence_refs/rollback_refs` | Subject export includes matching rows; subject erasure pseudonymizes matching remediation operators and clears free-form evidence while preserving non-PII run state; retention covers stale remediation evidence. |
| `compliance_report_schedules.recipient` | `compliance_report_schedules.recipient_ref` | Subject export includes matching rows; subject erasure pseudonymizes matching compliance report recipient references; retention covers stale recipient references after schedule evidence ages out. |
| `incident_fleet_reissuance_runs.operator-evidence` | `incident_fleet_reissuance_runs.created_by/reason/evidence_bundle/failed_targets/rollback_refs` | Subject export includes matching rows; subject erasure pseudonymizes matching fleet-reissuance operators and clears free-form incident evidence while preserving non-PII run state; retention covers stale fleet-reissuance evidence. |
| `oidc_prelogin.client-metadata` | `oidcPreLoginEntry.ClientIP/UserAgent` | Delete the in-memory pre-login entry on consume or TTL expiry; no durable read model or event stores the client IP/user-agent metadata. |

Default non-audit retention runs every `24h`. It uses these class windows:
owners `17520h`, identities/certificates/approvals/profiles/attestations `9528h`,
SSH keys/agents `4320h`, and access subjects/PAM subjects `2160h`. Governance,
discovery, notification, remediation, compliance-schedule, and incident free-form
evidence follows the 397-day operational evidence window unless an operator
configures a shorter policy. OIDC pre-login metadata is ephemeral and expires after
`10m`. Operators can override supported retention classes with the
`TRSTCTL_PRIVACY_RETENTION_*` settings in
`docs/configuration.md`.

## In the console (`/privacy`)

The web console exposes this stack as a **Privacy & data governance** screen at the
served `/privacy` route (see **[The web console](web-console.md)**). From there an
operator can:

- **File a subject erasure** — submit a data subject and optional reason; the console
  calls `POST /api/v1/privacy/subject-erasures` and shows the count of records erased
  for that subject, drawn from the `privacy.subject.erased` projection.
- **Enforce retention on demand** — trigger `POST /api/v1/privacy/retention-runs` and
  review recent runs (run id, cutoffs, records affected, who requested it), on top of
  the scheduled `24h` default run.
- **Browse the personal-data catalog** — the same catalog rows above, read from
  `GET /api/v1/privacy/catalog`, so the data map and the controls that act on it live
  on one screen.

The console surfaces erasure, retention, and the catalog; **data-subject export**
(below) remains a deliberate API call rather than a one-click console action, because it
discloses a subject's data and is better issued from an audited, scripted context.

## Data-subject access and portability

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
for the caller's tenant only: a subject in another tenant with the same name is
never returned. It requires the `privacy:read` permission.

This is the inverse of the existing subject **erasure**
(`POST /api/v1/privacy/subject-erasures`): export discloses the subject's data,
erasure removes it. Erasure and retention are event-sourced (`privacy.subject.erased`
/ `privacy.retention.enforced`); export is a pure read and emits no event.
