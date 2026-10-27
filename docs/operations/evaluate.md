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
| `renewal` | The identity is renewed and redeployed, and this command is then served the renewed certificate. | observed |
| `revocation` | The superseded certificate is revoked, and an OCSP request returns a signed answer saying revoked. | observed |
| `audit_export` | The signed audit export of the journey verifies with the published audit keys. It runs even after a failure, to record what was tried. | recorded |

## Check a pack offline

```bash
trstctl-cli audit verification-keys > audit-jwks.json   # obtain and compare out of band
trstctl evaluate verify --pack evaluation-pack.json --audit-jwks audit-jwks.json
```

The verifier checks the pack's signature under the evaluation-pack artifact
domain with the key set you pinned, that the pack beside the signature is
exactly the signed pack, and that the audit export inside it verifies with the
same keys. It never trusts the key set the pack carries.

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
