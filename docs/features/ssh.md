# SSH — replace standing SSH keys with short-lived certificates

## What it is

Most SSH access works by copying a user's public key into a server's `authorized_keys`
file. That scales badly and ages dangerously: keys pile up, nobody remembers whose they
are, and removing access means hunting them down across every host. An
**[SSH certificate](../glossary.md)** replaces that model: you trust one SSH
[certificate authority](../glossary.md), which signs short-lived certificates saying
"this user may log in as `alice` until 5 p.m." No per-host key copying, automatic expiry,
central control.

This page covers trstctl's three SSH pieces: the CA that signs host and user certificates
(F43), the agent that safely configures hosts to trust it (F44), and attestation-gated
short-lived user certificates tying SSH access to verified identity (F45).

## Why it exists

Standing SSH keys are one of the most common audit findings and breach vectors: orphaned
keys grant access nobody tracks, and offboarding rarely removes every key. SSH
certificates fix the structural problem: access expires on its own, trust is centralized
in the CA, and you grant exactly the principals and time window each session needs. The
hard parts are changing host trust without locking yourself out, and ensuring only the
right identity can get a certificate — what F44 and F45 address.

## How it works

### The SSH certificate authority (F43)

trstctl's SSH CA signs two kinds of OpenSSH certificate: host certificates (so clients
verify a server without trust-on-first-use prompts) and user certificates (so servers
authorize logins without a stored key). Each certificate carries principals, a validity
window, and optional critical options and extensions.

All signing goes through the single crypto path — one `SignSSHCertificate` operation
taking an opaque signer handle — so the CA key lives in an [HSM](../glossary.md), held in
the isolated signing service, never in the API process or in the clear. An issuance
profile bounds the maximum TTL and allowed certificate types; serial numbers increment
under a lock; every issuance is recorded as an immutable `ssh.cert.issued` event in its
own bounded lane. The CA also maintains a key revocation list (KRL): revoke by serial or
key ID, then distribute a snapshot to hosts, pulling back a certificate before it
expires.

The operator workflow is served two ways: OpenSSH-compatible protocol endpoints
(`/ssh/ca`, `/ssh/issue/user`, `/ssh/issue/host`, `/ssh/krl`) and a guarded product API
used by the CLI and console. `POST /api/v1/ssh/certificates/preview` validates and
normalizes an exact host or user request without allocating a serial, writing an event,
changing the KRL, making a network call, or calling the signer. It shows the requested
and effective TTL (default 1 hour, hard maximum 24 hours), deduplicated principals,
public-key and authority fingerprints, applied options/extensions, the one future signer
call, and the revocation path. `POST /api/v1/ssh/certificates` revalidates the same
contract and issues exactly one certificate behind an `Idempotency-Key`; a stable retry
returns the first result instead of signing again.

The direct user-certificate path allowlists only `source-address` and `force-command`
critical options plus known OpenSSH session extensions. Host certificates reject all
critical options and extensions. Both paths accept one public key and never accept or
return its private key. Status and revocation remain available at
`GET /api/v1/ssh/status` and `POST /api/v1/ssh/certificates/revoke`; revocation appends
an immutable, tenant-scoped `ssh.cert.revoked` event before publishing the updated KRL
snapshot. On every control-plane start, trstctl rebuilds the KRL from those events before
serving SSH. A malformed matching event stops startup instead of publishing a partial or
empty revocation list.

### SSH deployment & trust configuration (F44)

For a host to accept the CA's certificates, it must trust the CA's public key, written
into `TrustedUserCAKeys` and referenced from `sshd_config`. Editing `sshd_config` on a
live fleet is exactly where people lock themselves out, so trstctl's agent follows a hard
rule: **additive-only, validated before it takes effect, and rolled back automatically on
any failure.**

The agent saves the current file contents in memory, adds a missing CA line once,
and writes changes atomically (write-temp-then-rename). It then validates
(`sshd -t`), reloads, and health-checks that `sshd` still accepts connections.
An apply failure restores the saved contents and reloads the prior config; reload
and health commands are operator-supplied, required, and run as validated argv lines with
shell metacharacters rejected (`--ssh-trust-reload-cmd`, `--ssh-trust-health-cmd`) —
reload success alone isn't proof of health. Removing trust is never implicit:
`RemoveCATrust` needs an explicit confirmation flag. A failed restoration leaves
an unclear host state that needs operator attention. The library emits
`ssh.trust.added`, `ssh.trust.removed`, `ssh.trust.rolled_back`, and
`ssh.trust.rollback_failed` when an audit sink is connected. The current one-shot
agent command does not connect that sink or deliver these events to the control
plane; record its observed result through the rollout handoff below. That record
is an operator assertion, not automatic proof of the host change.

When both files already contain the requested trust, rerunning the command
leaves their contents unchanged but repeats validation, reload, and the health
check. A previous process may have stopped after writing files and before
reloading SSH. A failed retry reports its failed stage and leaves the files
untouched; it cannot restore an earlier process's memory-only backup. Keep an
independent recovery session and backup until both existing and certificate-based
access have been verified. Durable crash rollback and automatic audit delivery
are not provided by this one-shot command.

The one-shot requires `--ssh-trust-ca-key` and `--ssh-trust-tenant`; enrollment
flags do not enroll this operation. Set `--ssh-trust-keys-file` to the first
global `TrustedUserCAKeys` path, including directives loaded through `Include`.
A conflicting path or a `Match` block before global CA trust is refused before
any file changes. See the [complete rollout example](../journeys/ssh-at-scale.md).

The control plane also has a served handoff for this high-blast-radius path:
`POST /api/v1/ssh/trust-rollouts` records the source, target hosts, CA fingerprint,
reload/health commands, rollback plan, status, and an explicit `confirmed=true`
acknowledgment; `POST /api/v1/ssh/hosts/retire` records retirement evidence once
migration completes. The browser and CLI record/request the workflow, but host file
edits happen only inside the operator-confirmed agent path.

### Attestation-gated short-lived user certificates (F45)

The most powerful pattern: issue an SSH user certificate only to a caller who proves
identity first. This issuer runs an [attestation](workload-identity.md) check (the same
chain used for workload identity), then derives principals from the verified attestation
and calls the SSH CA. It requires an approver distinct from the attested subject, rejects
unbound principals, supports OpenSSH `source-address` and `force-command` critical
options, fails closed on attestation failure, defaults to a 15-minute TTL (capped by the
profile), and binds the attestation via an immutable `ssh.attested_cert.issued` event:
access short-lived and provably tied to a specific CI job or cloud instance — no standing
keys.

Review the exact request first with
`POST /api/v1/ssh/attested-user-certs/preview` or
`trstctl ssh preview-attested-user`. The preview reads tenant trust, validates and
normalizes the public key, approver, principals, lifetime, source addresses, and
forced command, then returns proof and key fingerprints, the isolated-signer action,
and recovery instructions. It performs no proof verification, write, external call,
audit emission, or signer call; proof verification remains execution-only because a
proof may contain one-time evidence.

Execution is served at `POST /api/v1/ssh/attested-user-certs` and by `trstctl ssh
issue-attested-user`; the request carries an attestation method, base64 payload, SSH
public key, approver, optional key ID, principals, TTL, source-address allowlist, and
force-command policy. The response is the certificate plus serial, key ID, expiry,
constraints, and the attestation record — the private key never crosses the API or UI.
The console retains one request-scoped idempotency key after an uncertain response;
its **Retry unchanged request** action recovers the original result instead of signing
again. For CLI recovery, set `TRSTCTL_IDEMPOTENCY_KEY` to a stable value and reuse the
same command body. A changed request with that key is rejected with HTTP 409.

## Use it

Stand up the SSH CA, distribute its public key to hosts via the agent, then issue
short-lived user certificates. The CA's public key goes into a host's trust config like
this (what the agent writes, additively):

For a container deployment, bind the served SSH workflow and the shared
attestation mint to one tenant. This exposes the workflow; it does not invent a
trusted identity source:

```sh
TRSTCTL_PROTOCOLS_SSH_ENABLED=true
TRSTCTL_PROTOCOLS_SSH_TENANT_ID=11111111-1111-4111-8111-111111111111
TRSTCTL_ATTESTED_ISSUANCE_ENABLED=true
TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN=example.org
TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL=10m
TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL=1h
```

Add an enabled, tenant-scoped public trust source through
`/api/v1/workloads/attester-trust-sources`. The same source gates both workload
SVIDs and attested SSH user certificates. If no matching source exists, both
mints fail closed; the console does not show a fake list of available
attestors.

```text
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
```

```text
# /etc/ssh/trusted_user_ca_keys  (the CA public key in authorized_keys form)
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... trstctl-ssh-ca
```

A user certificate is then issued with an attestation-bound principal and a short TTL
(e.g. 15 minutes); the user connects normally and `sshd` validates the certificate
against the trusted CA without any stored key.

```sh
trstctl ssh status
trstctl ssh preview \
  --type host \
  --public-key "$(cat /etc/ssh/ssh_host_ed25519_key.pub)" \
  --key-id edge-1.internal \
  --principals edge-1.internal,edge-1 \
  --ttl-seconds 86400
trstctl ssh issue \
  --type host \
  --public-key "$(cat /etc/ssh/ssh_host_ed25519_key.pub)" \
  --key-id edge-1.internal \
  --principals edge-1.internal,edge-1 \
  --ttl-seconds 86400
trstctl ssh trust-rollout \
  --hosts edge-1.internal \
  --ca-fingerprint SHA256:... \
  --reload-cmd 'systemctl reload sshd' \
  --health-cmd 'ssh -o BatchMode=yes localhost true' \
  --rollback-plan 'restore backup, reload sshd' \
  --status health_passed \
  --confirm
cat > ssh-attested-user.json <<EOF
{
  "method": "k8s_sat",
  "payload_base64": "$K8S_SAT_B64",
  "public_key": "$(cat ~/.ssh/id_ed25519.pub)",
  "approver": "ssh-approver",
  "principals": ["web"],
  "source_addresses": ["10.0.0.0/24"],
  "force_command": "/usr/local/bin/deploy",
  "ttl_seconds": 900
}
EOF
trstctl ssh issue-attested-user -f ssh-attested-user.json
trstctl ssh revoke --serial 42 --reason 'revoked'
trstctl ssh retire-host --host edge-1.internal --reason 'replaced'
```

## Pitfalls & limits

- **Never hand-edit trust on a live host.** Use the agent so the
  validate-reload-health-check-rollback safety net applies — a bad manual `sshd_config`
  edit can lock you out, and trstctl won't remove existing trust without explicit
  confirmation.
- **Serving status:** the SSH CA is served by the running control plane
  (`protocols.ssh.enabled`, default off): cert issuance at `/ssh/...`, the OpenSSH binary
  KRL at `/ssh/krl` (`sshd`'s `RevokedKeys` consumes it), and workflow API/CLI coverage
  for effect-free direct issuance preview, idempotent host/user issuance, status, trust
  rollout evidence, attested user cert issue, KRL revocation, and host retirement. The CA
  key stays in the isolated signing service, never the API process,
  with every step recorded as an immutable event and tenant data isolated at the database
  layer. SSH host-key discovery is also served via `ssh` discovery sources on the outbox
  worker; privileged trust rewrites still need the explicit agent-safe rollout workflow —
  see [Current limitations](../limitations.md).
- **Short TTLs require renewal.** That's the security benefit, but plan the renewal path
  for long-running sessions.
- **KRL distribution is push-based.** Revoking a certificate means distributing the
  updated KRL to hosts — budget for that propagation.

## Reference

- **CA operations:** `IssueUserCert`, `IssueHostCert`, `AuthorityKey` (for
  `TrustedUserCAKeys` / `@cert-authority`), `KRL.RevokeSerial`, `KRL.Distribute`.
- **Served API/CLI:** `POST /api/v1/ssh/certificates/preview`,
  `POST /api/v1/ssh/certificates`, `GET /api/v1/ssh/status`,
  `POST /api/v1/ssh/trust-rollouts`,
  `POST /api/v1/ssh/attested-user-certs/preview`,
  `POST /api/v1/ssh/attested-user-certs`,
  `POST /api/v1/ssh/certificates/revoke`, `POST /api/v1/ssh/hosts/retire`;
  `trstctl ssh preview|issue|status|trust-rollout|preview-attested-user|issue-attested-user|revoke|retire-host`.
- **Agent config:** `SSHDConfigPath`, `TrustedUserCAKeysPath`,
  `AllowUnconfirmedRemoval` (default false).
- **Attested issuance:** `AttestedUserCertIssuer.Issue` (method+payload → cert).
- **Events:** `ssh.cert.issued`, `ssh.attested_cert.issued`, `ssh.trust.added`,
  `ssh.trust.removed`, `ssh.trust.rolled_back`, `ssh.trust.rollback_failed`.
- **Standard:** OpenSSH certificate format (`PROTOCOL.certkeys`).
- **Design deep-dive:** [SSH trust-rewrite design](../design/ssh-trust-rewrite.md).

## See also

[Workload identity](workload-identity.md) (attestation chain F45 reuses) ·
[Issuance & certificate authorities](issuance-and-cas.md) ·
[SSH trust-rewrite design](../design/ssh-trust-rewrite.md) ·
[Discovery & inventory](discovery-and-inventory.md) (finding SSH keys) ·
glossary: [SSH certificate](../glossary.md), [attestation](../glossary.md),
[HSM/KMS](../glossary.md)

**Covers:** F43, F44, F45
