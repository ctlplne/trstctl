# Approved fleet SSH trust changes

This workflow adds one public user-certificate CA to opted-in enrolled hosts.
Use **SSH access → Trust rollout → Plan fleet change**, or the CLI below.
Retain independent access and a file backup before changing SSH trust.

## Prepare each host

1. Obtain the intended public CA through `trstctl-cli ssh status`, inspect its
   fingerprint with `ssh-keygen -lf`, and stage that public line locally.
2. Inspect `sshd -T -f /etc/ssh/sshd_config`. Choose the effective global
   `TrustedUserCAKeys` path, including the first applicable Include directive.
   The existing config must be a regular file; its directory and the trust
   file's directory must exist. Paths containing whitespace are refused.
3. Configure a validation command, reload command and a separate health command.
   Use a pinned real SSH login check and prove it succeeds before rollout.
   Commands are parsed as argv without a shell; shell interpreters and shell
   metacharacters are refused. Use absolute executable paths.
4. Add these options to the existing **enrolled host agent's** service command;
   keep its control-plane address, enrollment certificate/key, and host role:

   ```sh
   --ssh-trust-fleet --ssh-trust-confirm \
   --ssh-trust-ca-key /etc/trstctl/staged-user-ca.pub \
   --ssh-trust-sshd-config /etc/ssh/sshd_config \
   --ssh-trust-keys-file /etc/ssh/trusted_user_ca_keys \
   --ssh-trust-validate-cmd '/usr/sbin/sshd -t -f /etc/ssh/sshd_config' \
   --ssh-trust-reload-cmd '/usr/bin/systemctl reload sshd' \
   --ssh-trust-health-cmd '/usr/bin/ssh -F /etc/trstctl/rollout-health.conf rollout-probe@localhost true'
   ```

   The locally owned health configuration must pin host trust, select an
   authorized probe identity, and bound connection attempts/timeouts. Adjust
   these paths for the host OS; this example assumes a systemd Linux host.
   `--ssh-trust-tenant` may additionally pin the enrolled tenant. Do not combine
   fleet mode with the one-shot `--ssh-trust-add-ca` or `--ssh-krl-apply` modes.
   A KRL watcher can coexist and uses the same local mutation slot.

A heartbeat reports only readiness, the staged public CA fingerprint, and a
policy digest binding paths, command argv and executable hashes. No command,
local path or secret is accepted from the remote job. Readiness must be less
than five minutes old; replacing the local CA or action changes the digest.
The host re-reads the policy after claiming, so it refuses a changed policy
instead of applying an old approval.

## Preview, approve, start, observe

The control-plane operator must include `ssh.trust.apply` in the configured
`agent_claimable_job_kinds` allowlist. This does not enable any host locally.
Planning and dispatch require `agents:write`; reading requires `agents:read`.
Approval decisions require `certs:issue`, and the requester cannot self-approve.
The default quorum is two distinct reviewers (or the configured quorum).

Save a preview request with a name, reason, one plain `public_ca_key` line and
`agent_ids` from `trstctl-cli agents list`. The plan supports at most 100 hosts:

```sh
trstctl-cli ssh trust-fleet preview --file preview-input.json > reviewed.json
trstctl-cli ssh trust-fleet request-approval --file reviewed.json > approval.json
```

Inspect `plan.hosts`, `plan.ca_fingerprint`, `plan_digest` and `plan.expires_at`.
Preview is effect-free. Disabled, unconfirmed, stale, missing, non-host and
misconfigured entries remain in the roster as skipped; no job goes to them.
The plan's public key is canonical and base64 encoded by the JSON byte contract.
Preserve the returned plan rather than reconstructing it.

Reviewers use the shared **Approvals** inbox, or
`trstctl-cli approval-requests approve <approval_request_id> <intent_digest>`
with the exact `intent_digest` returned as `approval_intent_digest`. Check the
CLI's `--help` for its global authentication options. Once quorum is met:

```sh
trstctl-cli ssh trust-fleet start --file approval.json
trstctl-cli ssh trust-fleet list --limit 25
trstctl-cli ssh trust-fleet show <rollout-id>
```

The plan has a 15-minute execution deadline from preview. A changed ready-host
policy or expired review requires a new preview and approval. Each host gets
one durable, exact-agent job through the outbox. The dedicated host loop has one
worker, no prefetched queue, a 120-second claim and a 30-second work bound;
rollback cleanup has a separate bounded context. The API's pending response
means jobs were queued, not that SSH changed.

`verified` requires the signed receipt's exact plan/host/attempt binding, CA
readback, effective global trust path, file hashes, validation, reload and health.
Failed/refused receipts preserve a closed phase and reason code. A failure with
`rollback=verified` means exact prior file bytes were restored and validation,
reload and health succeeded; the rollout still needs attention. Missing receipts
remain pending, or `execution_window_expired` after the deadline. Immutable
source checks prevent a modified projection row from inventing completion.
Receipts describe their recorded check time, not continuous availability.

## Recover an interrupted report or change

Keep the agent's key-directory volume across upgrades. Fleet terminal reports
use their own encrypted `pending-reports-ssh-trust` directory beside the enrolled
key; a reconnect re-signs the same execution facts before claiming again, even
if fleet mode has since been turned off. The first accepted source proof remains
canonical. The effect index and its snapshots omit reviewer name/reason text
and store a tenant-bound requester reference; served metadata comes from the
matching privacy-cataloged source. Renewal pauses and joins the worker before replacing its signing key.
An unreadable report directory pauses claims and reports `report_state_paused`.

Restore the matching retained volume/binding first. If recovery is impossible,
stop the agent, preserve evidence, inspect the host independently, and use the
existing `--set-aside-pending-report` command
with that agent's identity options. It checks both report namespaces and moves
unrecoverable state aside by exact path. Setting aside loses automatic delivery
of that observation; it does not prove the host was unchanged or restore trust.

Rollback file copies live in memory. Process/power loss can leave a partial
change; retry validates, reloads and checks even if the CA line is already there,
but cannot recreate a prior process's backup. Keep independent access and backups;
do not have another administrator edit the same files during an attempt.
This workflow neither prunes trust/authorized_keys nor installs host certificates.
Use separately authorized procedures for those changes.
