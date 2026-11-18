# Runbook: chart upgrade and rollback

This runbook upgrades the Helm chart and rolls it back when readiness, signer
health, agent heartbeat, or inventory checks fail. It covers the control-plane
chart in `deploy/helm/trstctl` and the fleet surfaces that chart exposes.

## Prerequisites

- Save the current release revision: `helm history trstctl -n trstctl`.
- Export the current values:

```sh
helm get values trstctl -n trstctl -o yaml > trstctl-values.before.yaml
```

- Confirm `/readyz` is `200`.
- Confirm `trstctl_signer_up == 1`.
- Set `TRSTCTL_CA_FILE` to the trusted public CA bundle for the control-plane
  certificate; never disable TLS verification to get through an outage.
- Record `trstctl-cli agents list` and inventory counts before the upgrade.
- Run `trstctl --check-config` in the candidate environment and confirm the
  `agent_channel.*` lines match the planned fleet topology.

## Idempotency keys across this upgrade

An idempotency key is a retry label. It tells trstctl that two copies of the
same command must produce one effect. The upgraded API also binds that label to
the authenticated caller, method, path, canonical query, and request-body
digest. This prevents a changed command from silently receiving an earlier
command's cached response.

Bodyless, queryless commands keep their previous binding and replay normally.
An older successful mutation that had a body or query cannot be proved to match
after the upgrade because the older row did not record those input digests. Its
first retry therefore fails closed with `409 Conflict` and this detail:

```text
Idempotency-Key was already used for a different authenticated request
```

When this happens, confirm the intended effect in trstctl, then submit the
intended command once with a new unique idempotency key. Do not delete or edit
the old idempotency row: it is the durable proof that the earlier command ran.
Record the old and new key references in the change ticket. Never place the
request body or a credential value in either key.

## Agent registration binding across this upgrade

Agent certificates now identify the tenant's registration as well as its UUID.
Deleting a tenant and registering the same UUID must not give an old agent access
to the replacement tenant. The CA stamps the retained registration identifier;
authenticated agent operations and both renewal paths verify it.

Certificates issued before this binding was introduced require authorized
re-enrollment. A missing, duplicate or different binding is refused even when the
certificate is otherwise trusted and unexpired. Renewal cannot upgrade that old
identity: the operator must authorize a new bootstrap token for the intended
current tenant. The error includes `enroll again` guidance. Plan this interruption
before upgrading a fleet; existing cached credentials do not migrate automatically.

For each affected agent:

1. Stop that agent's service and retain its exact old certificate/key paths in
   protected storage for investigation. Do not copy private keys into a ticket.
2. Using the intended tenant's authenticated CLI context, run
   `trstctl-cli agents enroll-token` with the intended `allowed_identity` and
   role grants, as in the [fleet rollout runbook](fleet-rollout.md). Store each
   single-use token in a separate owner-readable file with mode `0600`.
3. Keep the agent's verified server address, name, CA bundle and execution
   settings. Supply `--bootstrap-token-file` and new, unused `--key` and `--cert`
   paths in a protected directory. Both paths must be unused: an existing cached
   identity takes precedence over a fresh bootstrap token. Update the service
   configuration to keep these new paths across restarts.
4. Start the agent and verify a successful heartbeat, expected inventory and job
   eligibility. Verify renewal and reconnection with the successor certificate.
   Preserve failed results; token creation or a TLS handshake alone is insufficient.

Do not disable tenant checks or edit the certificate SANs to recover service.
An ordinary restart or read-model rebuild retaining the same registration event
does not authorize a new tenant generation. Missing registration history requires
source recovery before enrollment can proceed.

## Dynamic-secret principal names across this upgrade

Each dynamic-secret lease names its principal (a database role or user, a
directory entry, a cloud user, a key) with the provider's prefix, the role and a
suffix that the control plane now derives under the deployment key from the
tenant, its registration epoch, the provider and the lease. Earlier releases
ended the name in ten hex digits that anyone holding the lease ID could compute.
Active leases keep their recorded names: the upgraded build revokes, expires and
rotates them as before.

Drain before upgrading, with every control-plane replica stopped. A lease or a
static rotation whose earlier attempt created its principal under the old name
and then stopped would, on its retry, create the new name and leave the old
principal behind, and a PostgreSQL static principal never expires on its own.

1. Pause every rotation schedule
   (`POST /api/v1/secrets/rotation-schedules/{id}/pause`); otherwise they keep
   queuing static rotations.
2. Stop the control plane and wait until its pods are gone:

```sh
kubectl -n trstctl scale deployment/trstctl --replicas=0
kubectl -n trstctl wait --for=delete pod \
  -l app.kubernetes.io/instance=trstctl,app.kubernetes.io/component=control-plane \
  --timeout=10m
```

3. As a PostgreSQL superuser or a role with `BYPASSRLS`, record what is still
   pending (the application role sees no rows without a tenant setting; per
   tenant, run `SET trstctl.tenant_id = '<tenant uuid>'` first):

```sql
SELECT tenant_id, id, provider, role FROM dynamic_secret_leases WHERE state = 'pending';
SELECT tenant_id, id, provider, secret_key, phase FROM secret_static_rotation_commands WHERE terminal_at IS NULL;
```

4. Upgrade (`helm upgrade` below restores the replica count), then resume the
   schedules (`POST /api/v1/secrets/rotation-schedules/{id}/resume`).

If an ID you recorded was still pending, its retry can leave a principal under
the old name: `<prefix>_<role>_` followed by the first ten hex digits of SHA-256
over the ID. It is shaped like the backend's other issued names: the prefix and
role are lower-cased with each run of other characters as one `_`, joined by the
backend's separator (`_` or `-`; Kubernetes uses `-` throughout), and cut so the
whole name fits the backend's length limit; HANA, Oracle and Snowflake store it
in upper case. Once the retry
has completed, remove that principal at the target by hand. trstctl does not
drop it on its own, because a name anyone can compute may belong to another
lease.

Stopping every replica first also keeps the old and new builds from running side
by side. The chart's default rolling update (`maxSurge: 1`) overlaps them while
leadership hands over; an older pod cannot revoke a lease the new build named,
and it keeps issuing the old names. Upgrade one release at a time.

Rolling back: the preflight's `redeploy_previous_binary` verdict covers database
migrations only. Once the upgraded build has issued leases, an older build cannot
revoke them, so do not roll back past this release. If you must:

1. Revoke every lease issued since the upgrade, and wait until each revocation
   has completed:

```sql
SELECT tenant_id, id FROM dynamic_secret_leases WHERE state = 'active' AND issued_at >= '<upgrade start>';
```

2. Record the static credentials minted since the upgrade, which an older build
   cannot retire (filtering on `updated_at` also catches a rotation queued before
   the upgrade and staged after it):

```sql
SELECT tenant_id, id, provider, new_ref FROM secret_static_rotation_commands WHERE updated_at >= '<upgrade start>';
```

   Only one-user rotations mint such a principal: its name ends in more than ten
   hex digits after its last separator, which the older build refuses to revoke.
   The name is `new_ref` for a database user, the part of `new_ref` before `/`
   for AWS IAM, and, for a key or service account, the name the provider shows
   for the ID in `new_ref`. After rolling back, the older build's next rotation
   of that key replaces its credential and then ends `retire_pending`, because it
   cannot retire the predecessor. Drop that principal at the target by hand only
   after the rotation has replaced it; never drop a key's current credential.
   Never drop a two-user rotation account or an account rotated in place (its
   `new_ref` is `<account>/<command id>`): the older build retires those itself,
   without dropping them. Static credentials have no expiry of their own, so the
   minted ones otherwise stay live.

## Commands: preflight

Render the chart with the exact values file and inspect the agent channel and
isolated-signer surfaces:

```sh
helm template trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml > rendered.before.yaml

grep -n 'agent-grpc\|TRSTCTL_AGENT_CHANNEL\|trstctl-signer' rendered.before.yaml
```

If the upgrade changes signer mode, verify the signer key store, KEK, signer auth
Secret, and mTLS Secret are present before applying. The signer must keep the same
key material unless a key ceremony explicitly says otherwise.

Run the new image's database preflight against the deployment's PostgreSQL. It
changes nothing, and it exits 1 when the upgrade is blocked:

```sh
docker run --rm \
  -e TRSTCTL_POSTGRES_MODE=external -e TRSTCTL_POSTGRES_DSN \
  -e TRSTCTL_BACKUP_DIRECTORY=/backups -v /backups:/backups:ro \
  <new image> --upgrade-preflight
```

Record its `rollback:` line in the change ticket. `redeploy_previous_binary`
means the rollback below is enough; `restore_backup` means a pending migration is
destructive, so take a full backup first (the preflight blocks until a verified
one from the last 26 hours is visible) and roll back by restoring it. See
[Database migrations & upgrades](../migrations.md#upgrade-runbook).
The verdict covers database migrations only; for dynamic-secret leases, also
follow [Dynamic-secret principal names across this upgrade](#dynamic-secret-principal-names-across-this-upgrade).

## Commands: upgrade

With any dynamic-secret provider configured, drain first as
[Dynamic-secret principal names across this upgrade](#dynamic-secret-principal-names-across-this-upgrade)
describes.

```sh
helm upgrade trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml \
  --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

If isolated signer mode is enabled:

```sh
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

## Expected metrics and logs

- `/readyz` returns `200` after each Deployment becomes Ready.
- `trstctl_signer_up` stays `1`, or returns to `1` before the control plane is
  marked ready.
- `sum(increase(trstctl_agent_enrollments_total{result="failed"}[15m]))` stays
  `0`; an upgrade should not break fresh agent bootstrap.
- `sum(increase(trstctl_agent_heartbeats_total{result="failed"}[10m])) /
  clamp_min(sum(increase(trstctl_agent_heartbeats_total[10m])), 1)` stays at or
  below `0.02`.
- `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1)` stays at or
  below `0.02`; stale means the control plane has not seen an agent for two
  heartbeat intervals.
- `sum(increase(trstctl_agent_bulkhead_rejections_total[5m]))` stays `0`.
- Agent logs return to `heartbeat ok`.
- `trstctl-cli agents list` keeps the same fleet count and shows expected versions.
- Inventory counts stay stable. Upgrade should not remove certificate, SSH, or
  agent inventory rows.
- Kubernetes events do not show repeated crash loops, failed mounts, or readiness
  probe failures.

## Abort criteria

Rollback immediately when:

- `/readyz` stays `503` for longer than two readiness probe periods.
- `trstctl_signer_up == 0` after signer rollout completes.
- `TrstctlAgentEnrollmentFailures`, `TrstctlAgentHeartbeatFailures`, or
  `TrstctlAgentFleetStale` fires; these alerts encode the 2 percent
  missed-heartbeat threshold.
- `TrstctlAgentBulkheadSaturated` fires continuously.
- `trstctl-cli agents list` loses hosts that were healthy before the upgrade.
- Inventory counts decrease without an explicit migration note.
- The rendered chart opens or closes the agent channel differently from the
  `trstctl --check-config` output.

## Rollback commands

```sh
helm history trstctl -n trstctl
helm rollback trstctl <last-good-revision> -n trstctl --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

`helm rollback` runs the previous binary against the database as the upgrade
left it. That is safe when the preflight's rollback method was
`redeploy_previous_binary`, including after a migration failed partway (see
[A failed upgrade](../migrations.md#a-failed-upgrade)). When it was
`restore_backup` and the destructive migration ran, restore the pre-upgrade
backup first ([Restoring](../disaster-recovery.md#restoring)).

An older build cannot revoke the dynamic-secret leases this release issued.
Before rolling back past it, follow
[Dynamic-secret principal names across this upgrade](#dynamic-secret-principal-names-across-this-upgrade).

If the rollback itself cannot reach readiness, stop fleet churn first, then use
the signer or DR runbook depending on the failing dependency:

```sh
kubectl -n trstctl rollout pause daemonset/trstctl-agent
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://cp.example.com/readyz
curl -fsS --cacert "$TRSTCTL_CA_FILE" https://cp.example.com/metrics | grep trstctl_signer_up
```

## Post-checks

1. `/readyz` is `200`.
2. `trstctl_signer_up == 1`.
3. `trstctl_agents_stale_total / clamp_min(trstctl_agents_total, 1) <= 0.02`.
4. `trstctl-cli agents list` has the expected host count.
5. Inventory counts match the pre-upgrade baseline.
6. Store `helm history`, rendered manifests, and the before/after counts in the
   change ticket.
