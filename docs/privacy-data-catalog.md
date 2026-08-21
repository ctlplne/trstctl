# Privacy Data Catalog

This catalog is the human-readable copy of the platform's machine-readable
privacy catalog: direct personal-data locations, why each field exists,
and what the `privacy.subject.erased` and `privacy.retention.enforced`
projections do to tenant read surfaces. Unless noted, a subject-access
export (below) returns every matching row for that location.

| ID | Location | Erasure behavior |
| --- | --- | --- |
| `events.actor.subject` | `events.Actor.Subject` | Tenant audit reads replace erased subjects with subject-ref placeholders. |
| `events.data.subject-values` | `events.Event.Data` | Audit reads redact exact erased subject values from old immutable event payloads. |
| `owners.email` | `owners.name/email/application_id/service/business_unit/escalation_chain/ownership_verified_by` | Export includes every matching ownership-accountability field. Erasure pseudonymizes the owner and verification actor and clears contact, application-model, and escalation values. Retention applies the same cleanup to inactive, unreferenced owners. `environment` stays opaque because it is a deployment classification, not a person. |
| `ownership_readiness_exceptions.actor-reason` | `ownership_readiness_exceptions.granted_by/reason/revoked_by/revocation_reason` | Export includes attributed grant/revoke evidence. Erasure pseudonymizes matching actors and clears free text; retention does the same after expiry. Identity, event, grant/expiry, and revocation timestamps remain immutable authority. |
| `tenant_members.subject` | `tenant_members.subject/display_name/email` | Replaces offboarded subjects with erased placeholders. Clears display/contact fields. |
| `api_tokens.subject` | `api_tokens.subject` | Revokes direct erasure matches. Pseudonymizes expired/revoked token subjects. |
| `identities.name-attributes` | `identities.name/attributes` | Pseudonymizes terminal identity names. Clears attributes. |
| `certificates.subject-sans` | `certificates.subject/sans` | Pseudonymizes terminal certificate subjects. Clears SANs. |
| `certificates.location-source` | `certificates.deployment_location/source` | Clears terminal deployment location and source values. |
| `ssh_keys.comment-location` | `ssh_keys.comment/location` | Clears orphaned, stale SSH key comment and location fields. |
| `attestations.evidence` | `attestations.evidence` | Clears stale evidence JSON. |
| `approvals.actors` | `issuance_approval_requests.requester / issuance_approvals.approver` | Pseudonymizes stale requester and approver subjects. Preserves resource/action evidence. |
| `application_secret_mutation_fences.requester` | `application_secret_mutation_fences.requester_sealed/requester_ref` | `privacy.subject.erased` deletes every matching pre-finalization fence. If exact approval authority is already bound, its requester is atomically pseudonymized and pending/approved authority is superseded first. Approval binding/finalization clears both requester fields; target projection deletes a finalized fence. |
| `application_secret_mutation_fences.actor` | `application_secret_mutation_fences.actor/actor_subject_ref` | The fence keeps the exact authenticated subject and role set needed to reproduce a crash-interrupted event. Erasure deletes matching commands before finalization. After finalization, the history-operation barrier atomically rewrites `actor.subject` and the exact approval requester to the tenant-bound placeholder, preserves roles, clears the selector, and lets target projection delete the fence. |
| `read_model_snapshots.payload` | `read_model_snapshots.payload` | This disposable JSON cache can copy every personal-data field in the tenant read model. Durable erasure preparation deletes the target tenant row in the same SQL transaction as its crash marker and records the exact zero-or-one deletion count. An active marker blocks every replacement writer. |
| `profiles.created-by` | `certificate_profiles.created_by` | Pseudonymizes stale profile author values. |
| `agents.name` | `agents.name` | Pseudonymizes stale agent names. Preserves agent id/status/version. |
| `agents.offboarding-evidence` | `agents.offboarded_by/offboard_reason` | Erasure pseudonymizes matching offboard actors and clears free-form reasons. Retention clears stale offboarding evidence, keeping agent id/status/version/offboarded_at. |
| `pam_sessions.subjects` | `pam_sessions.subject/requested_by/reason/audit` | Erasure pseudonymizes matching subject/requester fields and clears free-form reason/audit metadata. Retention covers terminal PAM session metadata after the access window. |
| `discovery_findings.triage` | `discovery_findings.triage_actor/triage_reason` | Erasure pseudonymizes matching triage actors and clears free-form triage reasons. Retention covers stale triage metadata once discovery evidence ages out. |
| `discovery_sources.config` | `discovery_sources.config` | Exported as matching JSON values, not rows. Erasure pseudonymizes exact matching JSON string values. Retention clears stale source-config PII paths once discovery evidence ages out. |
| `discovery_findings.metadata` | `discovery_findings.metadata` | Exported as matching JSON values, not rows. Erasure pseudonymizes exact matching JSON string values. Retention clears stale finding-metadata PII paths once discovery evidence ages out. |
| `notification_threshold_deliveries.subject` | `notification_threshold_deliveries.subject/channel` | Erasure pseudonymizes matching threshold-delivery subjects/channels. Retention covers stale threshold-delivery metadata once notification evidence ages out. |
| `incident_executions.operator-evidence` | `incident_executions.created_by/reason/evidence_bundle/failed_targets/rollback_refs` | Erasure pseudonymizes matching operators and clears free-form incident evidence, keeping non-PII status and identity IDs. Retention covers stale incident evidence. |
| `nhi_access_reviews.actors` | `nhi_access_review_campaigns.reviewer_subject/requested_by; nhi_access_review_items.decision_by/decision_reason` | Erasure pseudonymizes matching access-review actors and clears free-form decision metadata. Retention covers stale access-review metadata once governance evidence ages out. |
| `access_change_requests.actors` | `access_change_requests.requester_subject/reason; access_change_request_decisions.approver_subject/reason` | Erasure pseudonymizes matching requester/approver subjects and clears free-form reasons/evidence refs. Retention covers stale access-change metadata once governance evidence ages out. |
| `discovery_runs.requester` | `discovery_runs.requested_by` | Erasure pseudonymizes matching discovery-run requesters. Retention covers stale requester subjects once discovery evidence ages out. |
| `notification_routing_policies.owner-contact` | `notification_routing_policies.owner_ref/owner_email` | Erasure pseudonymizes matching routing owners and clears contact metadata. Retention covers stale routing owner/contact metadata once routing evidence ages out. |
| `remediation_playbook_runs.operator-evidence` | `remediation_playbook_runs.created_by/reason/evidence_refs/rollback_refs` | Erasure pseudonymizes matching remediation operators and clears free-form evidence, keeping non-PII run state. Retention covers stale remediation evidence. |
| `compliance_report_schedules.recipient` | `compliance_report_schedules.recipient_ref` | Erasure pseudonymizes matching compliance-report recipient references. Retention covers stale recipient references once schedule evidence ages out. |
| `incident_fleet_reissuance_runs.operator-evidence` | `incident_fleet_reissuance_runs.created_by/reason/evidence_bundle/failed_targets/rollback_refs` | Erasure pseudonymizes matching fleet-reissuance operators and clears free-form incident evidence, keeping non-PII run state. Retention covers stale fleet-reissuance evidence. |
| `oidc_prelogin.client-metadata` | `oidcPreLoginEntry.ClientIP/UserAgent` | Deletes the in-memory pre-login entry on consume or TTL expiry. No durable read model or event stores the client IP/user-agent metadata. |

Default non-audit retention runs every `24h`, using these class windows:
owners `17520h`; identities/certificates/approvals/profiles/attestations
`9528h`; SSH keys/agents/agent offboarding evidence `4320h`; and access
subjects/PAM subjects `2160h`. Governance, discovery, notification,
remediation, compliance-schedule, ownership-exception, and incident free-form evidence follows
the 397-day operational evidence window unless an operator configures a
shorter policy. OIDC pre-login metadata is ephemeral and expires after
`10m`. Operators can override these classes via the
`TRSTCTL_PRIVACY_RETENTION_*` settings (`docs/configuration.md`).

## Read-model snapshot cache

Read-model snapshots are accepted only as one complete capture generation. Every
tenant row carries the same projection head, capture ID, expected tenant count,
and digest of the exact sorted tenant IDs. A missing target row, mixed capture,
legacy format, or crash-partial capture is ignored before any read-model table is
truncated; a cold restore then starts from checkpoint zero and replays sanitized
event history. After erasure completion, the periodic writer may create a new
snapshot from the already-sanitized read model.

## In the console (`/privacy`)

The web console exposes this stack as **Evidence privacy** at `/privacy`
(see **[The web console](web-console.md)**). It answers the boundary first:
`privacy:read` can review tenant evidence, `privacy:write` is required to change
retention or erasure evidence, retention is named per catalog entry, and every
request stays inside the current tenant. Exact controls stay in four closed
sections and load only when an operator opens them:

- **Policy and data map** — browse the maintained rows from `GET
  /api/v1/privacy/catalog`, including location, owner, purpose, and retention
  class.
- **Subject rights** — submit a subject erasure and optional reason. The
  console calls `POST /api/v1/privacy/subject-erasures` and shows the count of
  records erased from the `privacy.subject.erased` projection. Export a
  subject's cataloged record counts through `POST
  /api/v1/privacy/subject-exports`. Secret values and token material are not
  rendered.
- **Archive removal evidence** — inspect or record tenant-scoped proof that a
  backup or signed audit archive was deleted, cryptographically shredded, or
  retained under legal hold through `GET` and `POST` on
  `/api/v1/privacy/archive-erasure-attestations`.
- **Retention jobs** — trigger `POST
  /api/v1/privacy/retention-runs` and review recent runs (id, cutoffs,
  records affected, requester), on top of the scheduled `24h` default.

Opening the page does not eagerly fetch these evidence sets. This keeps the
default view short and avoids moving tenant evidence into the browser before the
operator asks to review that section.

## Data-subject access and portability

Beyond erasure and retention, an operator answering a data-subject
**access / portability** request can export every record tied to a
subject in one tenant-scoped call:

```
POST /api/v1/privacy/subject-exports
{ "subject": "alice@corp.example.com" }
```

The response collects the subject's owners, identities, certificates
(matched on subject CN or SAN), SSH keys, attestations, tenant members,
and API tokens (the token hash is never included — only the principal
subject, scopes, and lifecycle timestamps), plus dual-control approvals
(requester and approver ties) and a per-category `counts` map. It is a
read — it changes no state, carries no `Idempotency-Key`, and reads under
PostgreSQL row-level security for the caller's tenant only: a subject in
another tenant with the same name is never returned. It requires the
`privacy:read` permission.

This is the inverse of subject **erasure**
(`POST /api/v1/privacy/subject-erasures`): export discloses the subject's
data, erasure removes it. Both are event-sourced
(`privacy.subject.erased` / `privacy.retention.enforced`); export is a
pure read and emits no event.
