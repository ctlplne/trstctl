# Privacy Data Catalog

This catalog is the human-readable copy of `internal/privacy.Catalog()`. It lists
direct personal-data locations, why the field exists, and what the
`privacy.subject.erased` projection does to tenant read surfaces.

| ID | Location | Erasure behavior |
| --- | --- | --- |
| `events.actor.subject` | `events.Actor.Subject` | Tenant audit reads replace erased subjects with subject-ref placeholders. |
| `events.data.subject-values` | `events.Event.Data` | Audit reads redact exact erased subject values from old immutable event payloads. |
| `owners.email` | `owners.email` | Blank email and pseudonymize owner name. |
| `tenant_members.subject` | `tenant_members.subject/display_name/email` | Replace subject with an erased placeholder and clear display/contact fields. |
| `api_tokens.subject` | `api_tokens.subject` | Revoke matching tokens and replace subject with an erased placeholder. |
| `identities.name-attributes` | `identities.name/attributes` | Pseudonymize selected identity names and clear attributes. |
| `certificates.subject-sans` | `certificates.subject/sans` | Pseudonymize selected certificate subjects and clear SANs. |
| `ssh_keys.comment-location` | `ssh_keys.comment/location` | Clear selected SSH key comment and location fields. |
| `attestations.evidence` | `attestations.evidence` | Clear selected evidence JSON. |
