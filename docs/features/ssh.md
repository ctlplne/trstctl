# SSH — replace standing SSH keys with short-lived certificates

## What it is

Most SSH access works by copying a user's public key into a server's `authorized_keys`
file. That scales badly and ages dangerously: keys pile up, nobody remembers whose they
are, and removing access means hunting them down across every host. An
**[SSH certificate](../glossary.md)** replaces that model. You trust *one* SSH
[certificate authority](../glossary.md), and it signs short-lived certificates that say
"this user may log in as `alice` until 5 p.m." No per-host key copying, automatic
expiry, central control.

This page covers trstctl's three SSH pieces: the SSH **CA** that signs host and user
certificates (F43), the **agent** that safely configures hosts to trust that CA (F44),
and **attestation-gated** short-lived user certificates that tie SSH access to verified
identity (F45).

## Why it exists

Standing SSH keys are one of the most common audit findings and breach vectors: orphaned
keys grant access nobody is tracking, and offboarding rarely removes every key. SSH
certificates fix the structural problem — access expires on its own, trust is centralized
in the CA, and you can grant exactly the principals and time window each session needs.
The hard parts are doing the host trust change *without locking yourself out*, and making
sure only the right identity can get a certificate — which is what F44 and F45 address.

## How it works

### The SSH certificate authority (F43)

trstctl's SSH CA signs two kinds of OpenSSH certificate: **host certificates** (so
clients can verify a server without trust-on-first-use prompts) and **user
certificates** (so servers can authorize a login without a stored key). Each certificate
carries principals (which usernames it's valid for), a validity window, and optional
critical options and extensions.

All signing goes through the single crypto path — one `SignSSHCertificate` operation that
takes an opaque signer handle — so the CA key can live in an [HSM](../glossary.md) and
never appears in the clear, held in the separate, isolated signing service rather than the
API process. An issuance profile bounds the maximum TTL and which certificate types are
allowed; serial numbers increment safely under a lock; every issuance is recorded as an
immutable `ssh.cert.issued` event and runs in its own bounded lane so it can't starve
other work. The CA also maintains a **key revocation list (KRL)** — it can revoke by
serial or key ID and produce a snapshot to distribute to hosts, which is how you pull back
a certificate before it expires.

### SSH deployment & trust configuration (F44)

For a host to accept the CA's certificates, it must trust the CA's public key — written
into `TrustedUserCAKeys` and referenced from `sshd_config`. Editing `sshd_config` on a
live fleet is exactly where people lock themselves out, so trstctl's agent does it with
extreme care, and this is a hard project rule: **trust is only ever added additively,
validated before it takes effect, and rolled back automatically on any failure.**

The agent (1) backs up both files; (2) is idempotent — if the CA line is already present
it does nothing; (3) writes changes atomically (write-temp-then-rename); (4) runs a
three-step gauntlet — validate the new config (`sshd -t`), reload, then health-check that
`sshd` still accepts connections; and (5) if *any* step fails, restores both files from
backup and reloads the known-good config. In the agent binary, the reload command and
the post-reload health command are both operator-supplied and required
(`--ssh-trust-reload-cmd`, `--ssh-trust-health-cmd`); reload success alone is not treated
as proof that SSH is healthy. Removing trust is never an implicit side
effect: `RemoveCATrust` refuses to run without an explicit confirmation flag. Every
action is audited (`ssh.trust.added`, `ssh.trust.removed`, `ssh.trust.rolled_back`).
If restoration or the restored-config reload fails, the agent audits
`ssh.trust.rollback_failed` instead; that means the host is in an unknown SSH-trust
state and needs operator intervention.

### Attestation-gated short-lived user certificates (F45)

The most powerful pattern: don't issue an SSH user certificate to anyone who asks —
issue it only to a caller who **proves** their identity first. This issuer runs an
[attestation](workload-identity.md) check (the same chain used for workload identity), and
only on success derives the certificate's principals from the verified attestation and
calls the SSH CA. It fails closed if attestation fails, defaults to a 15-minute TTL
(capped by the profile), and binds the attestation to the issued certificate in the audit
trail via an immutable `ssh.attested_cert.issued` event. The result: SSH access that is
short-lived *and* provably tied to, say, a specific CI job or a specific cloud instance —
no standing keys at all.

## Use it

Conceptually, the flow is: stand up the SSH CA, distribute its public key to hosts via
the agent, then issue short-lived user certificates. The CA's public key goes into a
host's trust config like this (what the agent writes for you, additively):

```text
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
```

```text
# /etc/ssh/trusted_user_ca_keys  (the CA public key in authorized_keys form)
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... trstctl-ssh-ca
```

A user certificate is then issued with explicit principals and a short TTL (e.g. 15
minutes for `alice`), and the user connects normally — `sshd` validates the certificate
against the trusted CA without any stored key.

## Pitfalls & limits

- **Never hand-edit trust on a live host.** Use the agent so the validate-reload-
  health-check-rollback safety net applies; a bad manual `sshd_config` edit can lock you
  out. trstctl will not remove existing trust without an explicit confirmation.
- **Serving status:** the **SSH CA is served** by the running control plane
  (`protocols.ssh.enabled`, default off): cert issuance at `/ssh/...`
  and the OpenSSH **binary KRL** at `/ssh/krl` (`sshd`'s `RevokedKeys` consumes it).
  The CA key lives in the isolated signing service under its own SSH-cert-constrained
  handle, never in the API process, and issuance keeps each tenant's data isolated at the
  database layer with every step recorded as an immutable event. The **trust agent** and
  the **attested issuer** are library-complete and tested but not yet wired into the agent
  binary — see [Current limitations](../limitations.md).
- **Short TTLs require renewal.** That's the security benefit, but plan the renewal path
  for long-running sessions.
- **KRL distribution is push-based.** Revoking a certificate means distributing the
  updated KRL to hosts; budget for that propagation.

## Reference

- **CA operations:** `IssueUserCert`, `IssueHostCert`, `AuthorityKey` (for
  `TrustedUserCAKeys` / `@cert-authority`), `KRL.RevokeSerial`, `KRL.Distribute`.
- **Agent config:** `SSHDConfigPath`, `TrustedUserCAKeysPath`,
  `AllowUnconfirmedRemoval` (default false).
- **Attested issuance:** `AttestedUserCertIssuer.Issue` (method + payload → attested cert).
- **Events:** `ssh.cert.issued`, `ssh.attested_cert.issued`, `ssh.trust.added`,
  `ssh.trust.removed`, `ssh.trust.rolled_back`, `ssh.trust.rollback_failed`.
- **Standard:** OpenSSH certificate format (`PROTOCOL.certkeys`).
- **Design deep-dive:** [SSH trust-rewrite design](../design/ssh-trust-rewrite.md).

## See also

[Workload identity](workload-identity.md) (the attestation chain F45 reuses) ·
[Issuance & certificate authorities](issuance-and-cas.md) ·
[SSH trust-rewrite design](../design/ssh-trust-rewrite.md) ·
[Discovery & inventory](discovery-and-inventory.md) (finding existing SSH keys) ·
glossary: [SSH certificate](../glossary.md), [attestation](../glossary.md),
[HSM/KMS](../glossary.md)

**Covers:** F43, F44, F45
