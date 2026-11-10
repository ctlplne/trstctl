# Runbook: a host renewal refused as another job's

This runbook frees one target whose host-generated renewals all fail on its host
agent because an old job's pending record still holds the target's slot. It
changes one file on that agent's host and nothing on the control plane.

## Symptom

Every renewal for one target (`executor: agent`, the `endpoint.renew` job kind)
fails on its host agent with the detail:

```text
the encrypted pending host key belongs to another job or cannot be read
```

Other targets on the same agent renew normally.

## Cause

While a host-generated renewal is in flight, the host agent keeps one encrypted
pending record per target: the key it generated and, once the control plane signs
it, the certificate. A later job finds the slot taken and refuses rather than reuse
a key it cannot tie to itself. Records whose job has ended are released without an
operator:

- every renewal the control plane queues says through which job the target's
  renewals have ended, and the agent wipes an ended job's record whose key was
  never signed;
- the agent's rollback of a failed successor frees the successor's signed record.

A record from a successor that was signed and then rolled back by an agent that did
not yet free it is neither, so it keeps the slot until it is removed by hand. The
key inside it is encrypted for this agent and was never served: the rollback put the
predecessor back. Removing the record discards that key, and the certificate issued
for it then has no key anywhere; revoke it from the inventory if your policy
requires that for unused certificates.

## Prerequisites

- The target's ID and connector name (for example `nginx`), from
  `trstctl-cli connector target list` or the target's page in the console, and the
  agent's tenant ID.
- Shell access to the host agent's machine as the account that runs the agent.
- The agent's host rollback directory. The agent prints it when it starts
  (`trstctl-agent: encrypted host rollback state enabled at <directory>`): its
  `--host-rollback-dir`, or, when that flag is unset, `host-rollbacks` beside the
  file its `--key` flag names, resolved from the agent's working directory.

## Commands

Stop the agent, so no renewal reads the slot while you change it:

```sh
sudo systemctl stop trstctl-agent
```

```powershell
Stop-Service trstctl-agent
```

The record's file name is the SHA-256 of the tenant ID, the connector name and the
target ID, joined by NUL bytes, in lowercase hexadecimal, followed by `.renew`:

```sh
TENANT_ID=11111111-1111-1111-1111-111111111111
CONNECTOR=nginx
TARGET_ID=3f2a8d1c-5b7e-4c9a-8e21-6d4b0a9f7c13
HOST_ROLLBACK_DIR=/path/from/the/agent/start/line
NAME="$(printf '%s\0%s\0%s' "$TENANT_ID" "$CONNECTOR" "$TARGET_ID" | sha256sum | cut -d' ' -f1)"
ls -l "$HOST_ROLLBACK_DIR/$NAME.renew"
rm "$HOST_ROLLBACK_DIR/$NAME.renew"
```

On macOS use `shasum -a 256` in place of `sha256sum`. On Windows:

```powershell
$bytes = [Text.Encoding]::UTF8.GetBytes("$TenantId`0$Connector`0$TargetId")
$name = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLower()
Remove-Item (Join-Path $HostRollbackDir "$name.renew")
```

Remove only that one file. The directory also holds other targets' records and the
encrypted predecessor bundles that rollback depends on.

Start the agent again:

```sh
sudo systemctl start trstctl-agent
```

```powershell
Start-Service trstctl-agent
```

## Post-checks

- The target's next renewal generates a new key on the host, is signed, and reports
  delivered (and verified when the target names a `verify_address`).
- The agent's other targets keep renewing.

## Abort criteria

- `ls` finds no file with that name: the stuck record belongs to another tenant,
  connector or target ID; check the three values rather than removing other files.
- The renewal still fails with the same detail after the removal: stop, and keep the
  agent's log of that job for the issue report.
