# Design: SSH trust rewrite (S13.2, F44)

**Status:** reviewed — design gate for S13.3 (build).
**Catastrophic-risk area.** A mistake in how the agent rewrites `sshd` / host
trust can lock operators out of production. This document is the contract the
S13.3 implementation must follow; S13.3 adds no behavior not specified here.

## 1. Goal and non-goals

Configure a host to trust the trustctl SSH CA — install a host certificate and
point `sshd` at the CA via `TrustedUserCAKeys` — **without any path that can lock
an operator out of their own machine.** The agent performs the change through the
supervised agent path (AN-4); it never edits trust out of band.

Non-goals: session brokering (trustctl manages SSH *credentials*, it is not a
bastion), and non-SSH trust.

## 2. Principles

- **Additive-first.** Trust is only ever *added*. Existing `authorized_keys`,
  existing host keys, and existing `TrustedUserCAKeys` entries are preserved. An
  operator's current key-based access keeps working across the change, so the
  change cannot itself remove the operator's way in.
- **Never remove existing trust without explicit confirmation.** Removing a CA
  line or pruning `authorized_keys` requires an explicit, separately-confirmed
  operation with its own rollback — it is never a side effect of installing trust.
- **Validate before reload.** Every change is validated with `sshd -t` (config
  test) *before* the running daemon is reloaded. An invalid config is never
  reloaded.
- **Validated reload with automatic rollback.** After reload, a health check
  confirms `sshd` is accepting connections. If validation or the health check
  fails, the previous configuration is restored from backup and `sshd` is
  reloaded again — automatically, without operator action.
- **Atomic writes.** Config and trust files are written write-temp-then-`rename`
  so a crash mid-write can never leave a truncated `sshd_config`.
- **Fail-safe, not fail-open and not fail-closed-to-lockout.** On any uncertainty
  the agent restores the last-known-good state rather than leaving a half-applied
  config.

## 3. Change procedure (what S13.3 implements)

1. **Snapshot / backup** the current `sshd_config` and `TrustedUserCAKeys` file
   (and record their absence if they do not exist).
2. **Install the host certificate** (additive — does not touch existing host keys).
3. **Add the CA trust line** to `TrustedUserCAKeys` *if not already present*
   (additive, idempotent). Ensure `sshd_config` references the file (additive
   directive; existing directives preserved).
4. **Validate** with `sshd -t`. On failure → **restore backups**, return an error,
   make no further change.
5. **Reload** `sshd`.
6. **Health-check** the daemon. On failure → **restore backups, reload again**
   (rollback), return an error.
7. On success, record the new last-known-good snapshot.

## 4. Lockout failure modes and mitigations

| # | Failure mode | Mitigation |
|---|---|---|
| L1 | New `sshd_config` is syntactically invalid | `sshd -t` validation **before** reload; invalid config never reloaded |
| L2 | Reload succeeds but `sshd` then refuses connections | Post-reload health check; automatic rollback to backup on failure |
| L3 | Agent crashes mid-write, truncating `sshd_config` | Atomic write-temp-then-`rename`; the live file is replaced only when fully written |
| L4 | Change removes the operator's existing access | Additive-first: existing `authorized_keys` and trust are preserved; removal requires explicit confirmation (§2) |
| L5 | CA key compromise forces emergency host access | Break-glass recovery (§5) issues an emergency host credential out-of-band (S12.4) |
| L6 | Backup itself is lost before rollback | Backups are written atomically and verified to exist before any mutation proceeds |
| L7 | Repeated apply double-adds trust / drifts config | Additive step is idempotent (CA line added only if absent) |
| L8 | Health check passes locally but control-plane connectivity is gone | Health check is local (does `sshd` accept a connection), independent of the control plane, so a control-plane outage cannot block rollback |

## 5. Break-glass recovery path (ties to S12.4)

If a host is locked out despite the above (e.g. L5), recovery does **not** depend
on the control plane. An operator quorum issues an emergency host credential via
the offline break-glass ceremony (S12.4); the host's console/recovery path
installs it, restoring access. The break-glass bundle reconciles into the audit
log on recovery (AN-2).

## 6. Interface contract

The S13.3 build implements the `Applier` over the `FileSystem` and `Reloader`
seams declared in `internal/agent/sshtrust` (`types.go`). Those seams exist so the
rollback and lockout-failure paths above are **tested with induced failures**
(invalid config, unhealthy reload) rather than only in production. No production
behavior is added outside this design.
