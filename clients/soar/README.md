# trstctl response pack for SOAR tools

`pack.json` and `playbooks/` are response playbooks a SOAR (security orchestration,
automation and response) tool runs against trstctl's API (N7). Each playbook is a
list of HTTP calls — method, path, JSON body, `Idempotency-Key`, the answers it
expects, and what it reads back — so any tool that can make an authenticated HTTP
request can run them, step by step, without a trstctl-specific connector.

## Connecting

Create an API token holding exactly the scopes in `pack.json` (`api.scopes`), store it
in the SOAR's credential vault, and send it as `Authorization: Bearer <token>` with
`X-Tenant-ID: <tenant id>` on every call to `<trstctl_url>`.

## Running a playbook

Fill the playbook's `inputs`, then run its `steps` in order:

- Replace `{{name}}` in `path`, `body` and `idempotency_key` with an input, or with an
  earlier step's output as `{{steps.<step>.<output>}}`.
- Send the call; the answer's status must be one of `expect`.
- `assert` maps a JSON pointer in the answer to the value it must hold; stop if it
  does not.
- `until` repeats the call every `every_seconds` until its `assert` holds, for at
  most `max_seconds`.
- `outputs` reads JSON pointers from the answer for later steps.

Every mutating step sends an `Idempotency-Key` built from its inputs, so a SOAR that
retries a step, or runs the playbook again, gets trstctl's first answer instead of a
second effect.

## Playbooks

| Playbook | What it does |
| --- | --- |
| `revoke-compromised-certificate` | Revokes one certificate for key compromise and waits until trstctl reports it revoked. |
| `rotate-leaked-secret` | Writes a new value for a stored secret and resolves the leaked-secret finding as remediated, with the new version as evidence. |
| `retire-triggered-honeytoken` | Refuses a honeytoken that has not triggered; revokes one that has, keeping its trigger record. |

Every step's operation, method and path are checked against the served OpenAPI
document, and every playbook is run against the served API with a token holding only
the pack's scopes, in `TestServedSOARPlaybookPackN7`.
