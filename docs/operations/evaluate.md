# `trstctl evaluate` — run one certificate journey against your own endpoint

`trstctl evaluate` is the evaluation kit for a team trying trstctl on its own
infrastructure. It drives one complete certificate journey against an endpoint
you choose, through your running control plane's own API, and writes what
happened at each step into an evidence pack: what was checked, how it is known,
a pass/fail verdict, and what the run does not show. Signed, the pack verifies
on another machine with the audit keys you pinned.

It is a command in the shipping `trstctl` binary, beside
[`trstctl doctor`](doctor.md). It calls the same API routes an operator uses; it
has no side door into the datastore.

## Before you run it

1. A TLS endpoint you control, serving any certificate for the name clients use.
2. A host agent on the machine that serves it, enrolled with the host role.
3. A deployment target for that endpoint: its connector (for example `nginx`),
   its certificate and key paths, `"executor": "agent"` and the agent's
   `required_agent_id`, so the agent generates the key on the host, and
   `verify_address` and `verify_server_name`, which the evaluation uses as the
   endpoint and the name unless you pass `--endpoint` and `--name`.
4. An operator API token in `$TRSTCTL_TOKEN` (or a file named by `--token-file`).
   It is never accepted on the command line.

## Running it

```bash
export TRSTCTL_TOKEN=...   # an operator token for the tenant
trstctl evaluate --server https://trstctl.example.internal \
  --deployment-target 6f0c...e21 --out evaluation-pack.json --sign
```

| Flag | Default | What it does |
|---|---|---|
| `--server URL` | `$TRSTCTL_SERVER` | The control plane's base URL. |
| `--deployment-target ID` | none | The connector target for the endpoint. Required. |
| `--endpoint host:port` | the target's `verify_address` | The endpoint to evaluate. |
| `--name NAME` | the target's `verify_server_name` | The DNS name clients use; the certificate is issued for it. |
| `--owner NAME` | `design-partner-evaluation` | The owner of the issued identity, created when missing. |
| `--profile NAME` | none | A certificate profile to issue under. |
| `--timeout D` | `10m` | The longest wait for any one step. |
| `--out PATH` | `evaluation-pack.json` | Where the pack is written (mode `0600`). |
| `--ca-file PATH` | `$TRSTCTL_CA_FILE` | The CA bundle for the control plane's TLS. |
| `--sign` | off | Signs the pack through the isolated signer's `audit-export` handle. Requires the signer socket; the command never reads private-key bytes. |
| `--signer-socket PATH` | `$TRSTCTL_SIGNER_SOCKET` | Required by `--sign`. |
| `--journeys LIST` | `certificate` | The journeys to run: `certificate`, `secrets`, `ssh`, comma-separated. `--deployment-target` is needed only for `certificate`. |
| `--force-failure JOURNEY` | none | Makes one step of that journey expect what did not happen, to see a failure reported as one. |
| `--ssh-principal NAME` | `eval-user` | The SSH journey's login name; one `protocols.ssh_user_principals` lists (the eval profile allows `eval-user`). |

Exit codes: **0** every step passed · **1** a step failed · **2** the command
could not run (a missing flag, an unreadable target, an unreachable server).

## What each step does, and how its outcome is known

Each step is `pass`, `fail` or `skipped`. A step that depends on one that failed
is skipped, never passed, so a failed journey never reads as a passed one. A
passed step says whether its outcome was **observed** (read from outside the
product's own record of what it did) or **recorded** (the product's record).

| Step | What happens | Basis |
|---|---|---|
| `discovery` | The control plane completes a TLS handshake with the endpoint and records the certificate it served. | observed |
| `ownership` | The owner is found or created; the issued identity belongs to it. | recorded |
| `issuance` | The endpoint is bound to a new identity on the platform CA after the reviewed preview, and the certificate is issued. With an agent-executed target the key is generated on the host. | recorded |
| `deployment` | The connector's receipt for the issued certificate says delivered or verified. | recorded |
| `verification` | This command completes its own TLS handshake with the endpoint, from where it runs, and is served the issued certificate. | observed |
| `renewal` | Once the identity is deployed, it is renewed and redeployed, and this command is then served the renewed certificate. | observed |
| `revocation` | The superseded certificate is revoked, and an OCSP request returns a signed answer saying revoked. | observed |
| `audit_export` | The signed audit export of the journey's identity, from the moment the journey started, verifies with the published audit keys. It runs even after a failure, to record what was tried. A journey that stopped before it created an identity has no record of its own, so this step is skipped, saying so, rather than passed on other records the tenant made meanwhile. | recorded |

## Check a pack offline

```bash
trstctl-cli audit verification-keys > audit-jwks.json   # obtain and compare out of band
trstctl evaluate verify --pack evaluation-pack.json --audit-jwks audit-jwks.json
```

The verifier checks the pack's signature under the evaluation-pack artifact
domain with the key set you pinned, that the pack beside the signature is
exactly the signed pack, and that the audit export inside it verifies with the
same keys. It never trusts the key set the pack carries.

## More journeys

`--journeys certificate,secrets,ssh,workload,incident` runs the secrets, SSH,
workload identity and incident journeys beside the certificate one, into the same
pack (format `trstctl.evaluation-pack/v2`; a run of the certificate journey alone
still writes `v1`). Each journey keeps its own
steps, verdict and limits under `journeys`, and the same rule: a step after a
failure is skipped, never passed. The pack's verdict passes only when every
journey does.

| Journey | Steps | Needs |
|---|---|---|
| `secrets` | `secret_create` a synthetic value · `secret_read` it back (same version and digest) · `secret_rotate` and read the new version · `secret_run`: `trstctl run` puts it in a child process's environment and the child compares it, printing nothing · `secret_delete`, then a read answers 404 | `secrets:read`, `secrets:write`; a POSIX shell for the run step |
| `ssh` | `ssh_issue` a user certificate for a key the command generates · `ssh_verify` it offline against the served CA key (`/ssh/ca`) · `ssh_revoke` it · `ssh_krl`: the served KRL (`/ssh/krl`) lists its serial | `certs:issue`, `certs:write`; the SSH CA served, with the principal in `protocols.ssh_user_principals` |
| `workload` | `workload_x509`: fetch an X.509-SVID from the Workload API socket and check it as a workload does — it chains to the trust bundle the socket sends, carries exactly one SPIFFE ID, and the private key handed over is its own · `workload_jwt`: fetch a JWT-SVID for an audience unique to this run and verify it offline against the trust domain's JWT bundle (subject, audience, expiry) · `workload_validate`: the socket validates the token for that audience and refuses it for another | a Workload API socket on the machine that runs the command: `--workload-socket` or `$SPIFFE_ENDPOINT_SOCKET` (the control plane's own socket with `protocols.spiffe.serve_local_workloads`, or a host agent's) |
| `incident` | runs after the certificate journey and responds to a compromise of the key behind the certificate it left deployed: `incident_preview` the effect-free key-compromise preview (every certificate to revoke at its CA, the deployed one among them, and the exact host stop) · `incident_rehearse` a revoked-credential game day — a static preview and a mocked rehearsal, labeled as such · `incident_contain` the reviewed command that revokes the certificate at its CA and has the host agent stop the listener, read back until both report (`containment_stopped`) · `incident_verify`: the certificate's OCSP answer says revoked, and the endpoint no longer serves it to this machine | the certificate journey's target, an agent whose host profile grants that target a containment (its listener and one pinned, argument-free stop action), and a token with `identities:write`, `connectors:write`, `incidents:write` and `incidents:game-day` |

The pack keeps the synthetic secret's digest, never its value, and the journey
deletes it. `--force-failure secrets` makes the read expect a value that was never
written; `--force-failure ssh` makes the KRL check expect the revoked serial absent;
`--force-failure workload` makes the validation expect the token to pass for another
audience; `--force-failure incident` makes the last check expect the compromised
certificate still good over OCSP. The pack records the SVID's SPIFFE ID and the
token's digest, never the token or a key. A journey with a forced failure fails at
that step, its later steps are skipped, the other journeys run as before, and the
pack's verdict fails.

The incident journey changes the lab: it revokes the certificate the certificate
journey deployed and stops the listener serving it. Run it against a lab target,
and bring the listener back with the containment grant's recovery action before
evaluating that target again.

```bash
trstctl evaluate --server https://trstctl.example.internal \
  --journeys secrets,ssh,workload --workload-socket /run/trstctl/workload.sock \
  --out evaluation-pack.json --sign
```

## Unattended cycles

`--cycles 3 --interval 5m` runs the chosen journeys three times, five minutes
apart, with nobody watching. Each cycle is its own run, with its own idempotency
keys, certificates and audit window. The pack (format
`trstctl.evaluation-pack/v3`) keeps every cycle under `cycles`, with the last
cycle's steps, journeys and audit export at the top and a verdict and summary for
the whole run. An endpoint is enrolled once: after the first cycle, the
certificate journey issues the enrolled identity's next certificate through
renewal, then deploys, verifies, renews and revokes as before.

When the control plane cannot be reached (it is restarting, or what fronts it
answers 502, 503 or 504), the cycle it cut short is `interrupted`, not failed.
The command waits up to `--recovery-timeout` (10 minutes by default) for
`/readyz`, records when the outage was first seen and when the control plane
answered again, and runs the next cycle. The run passes only when every cycle
passed, except an interrupted cycle that the very next cycle passed after. A
failure with the control plane up, an outage in the last cycle and an outage that
outlasts the timeout each fail it. The incident journey stops the endpoint it
contains, so it runs once and is refused with `--cycles`.

```bash
trstctl evaluate --server https://trstctl.example.internal --deployment-target "$TARGET_ID" \
  --journeys certificate,secrets,ssh --cycles 12 --interval 30m --out evaluation-pack.json --sign
```

## What it does not show

- **Discovery is a handshake, not a sweep.** The control plane connects to the
  endpoint you named. Finding endpoints nobody listed is what a network relay's
  scan does, and it is not part of this journey.
- **One vantage.** Verification and the renewal check are this command's own
  handshakes: they show what this machine was served, not what every client is
  served.
- **OCSP, not CRL.** Revocation is checked over OCSP. CRL publication is
  asynchronous and is not checked.
- **Keys from the same server.** The run checks the audit export with the keys
  this server publishes. Check the pack again with a key set you obtained
  separately, as above.
- **Once.** The journey runs once against one endpoint. It is not a load,
  failover or long-running test.
- **It changes things.** The run creates an owner (when missing) and an identity,
  issues and deploys two certificates to the endpoint, and revokes the first.
  Run it against an endpoint you are evaluating, not one in production use.
- **The secrets journey covers the native store.** It writes, reads, rotates,
  injects and deletes one synthetic secret; syncs to external stores, dynamic
  secrets and sharing are not part of it.
- **The SSH journey stops at the KRL.** It issues and revokes one user
  certificate and reads the served KRL; it does not install the KRL on a host or
  log in with the certificate.
