# Issue and trust SSH access at scale

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `ssh_ca`, `ssh_krl`, `ssh_trust_rollout`, `ssh_attested_issuance`, `ssh_retirement`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

Replace the pile of standing SSH keys in everyone's `authorized_keys` with
short-lived certificates from a single SSH certificate authority: hosts trust
one CA, user certificates expire on their own, and leftover keys end up in a
clean inventory for retirement. The running binary serves the CA, KRL,
attested-cert, rollout-evidence, revocation, and retirement handoff; host file
mutation stays in the operator-confirmed agent path.

## Before you start

- A running control plane and an API token from
  [Getting started](../getting-started.md) (`trstctl token create`).
- The `trstctl ssh` verbs in this journey read three environment variables —
  all required:

  ```sh
  export TRSTCTL_URL=https://localhost:8443
  export TRSTCTL_TOKEN=trst_...
  export TRSTCTL_TENANT=11111111-1111-1111-1111-111111111111
  ```
- An installed agent on the hosts you want to manage, enrolled as in
  [Getting started](../getting-started.md). For what the agent can see and change on a
  host, see [SSH](../features/ssh.md).

## Steps

1. Turn on the SSH certificate authority and bind it to your tenant. The CA's key lives
   in the separate signing service under a handle constrained to SSH-cert signing — it
   never enters the API process. See [SSH](../features/ssh.md).

   ```yaml
   protocols:
     ssh:
       enabled: true
       tenant_id: "11111111-1111-1111-1111-111111111111"
   ```

   -> the SSH CA is served at `/ssh/...`, and its binary key-revocation list at
   `/ssh/krl` (the artifact a host's `RevokedKeys` consumes). The toggle is off by
   default and startup fails closed if you enable it without a tenant.

2. Find the SSH access you already have, so you know what the certificates are
   replacing. A control-plane `ssh` discovery source records network host keys. To
   collect on-host grants, explicitly give the shipped agent the safe paths it may
   read; it records standing access and flags an `authorized_keys` grant whose owner is
   unknown as orphaned. Only fingerprints and metadata are reported, never key bytes. See
   [Discovery & inventory](../features/discovery-and-inventory.md).

   ```sh
   cat > ssh-source.json <<'JSON'
   {"kind":"ssh","name":"fleet","config":{"targets":["10.0.0.10:22"]}}
   JSON
   trstctl-cli discovery sources create -f ssh-source.json
   echo '{"source_id":"<source-id>"}' | trstctl-cli discovery runs start -f -
   trstctl-cli discovery findings list --run_id <run-id>
   trstctl-agent ... \
     --inventory-ssh-authorized-keys '/home/*/.ssh/authorized_keys' \
     --inventory-ssh-sshd-configs /etc/ssh/sshd_config
   trstctl ssh fleet
   ```

   -> you get a list of standing-access keys to retire as certificates take over. The
   SSH discovery control surface (source/schedule/run/findings) and its host-key scan
   execute through the served discovery outbox worker; on-host SSH/private-key
   inventory arrives through the agent's mTLS inventory report path. See
   [Discovery & inventory](../features/discovery-and-inventory.md).

3. Make your hosts trust the CA's public key. The CA's key goes into a host's
   `TrustedUserCAKeys` file, referenced from `sshd_config`. The agent does this
   *additively* and safely, and this trust-rewrite is a high-blast-radius change, so it
   is **off by default** and requires an explicit opt-in plus confirmation. See
   [SSH](../features/ssh.md).

   ```sh
   trstctl-agent --enroll-url https://localhost:8443 \
     --bootstrap-token-file ./trstctl-bootstrap-token \
     --server localhost:9443 \
     --name edge-agent-1 \
     --ca-bundle ./trstctl-ca.pem \
     --ssh-trust-add-ca \
     --ssh-trust-confirm \
     --ssh-trust-reload-cmd 'systemctl reload sshd' \
     --ssh-trust-health-cmd 'ssh -o BatchMode=yes localhost true'
   ```
   The reload and health commands are parsed as argv and executed without a
   shell; shell metacharacters and shell interpreters are rejected.

   What the agent writes for you, additively:

   ```text
   # /etc/ssh/sshd_config
   TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
   ```

   -> the agent backs up the files, validates the new config (`sshd -t`), reloads, runs
   your post-reload health command, and auto-rolls-back to the last-known-good on any
   failure — so a bad rewrite cannot lock you out. It never removes existing trust
   without an explicit confirmation. Record the served rollout evidence after the agent
   reports the result:

   ```sh
   trstctl ssh trust-rollout \
     --source <source-id> \
     --hosts edge-1.internal \
     --ca-fingerprint SHA256:... \
     --reload-cmd 'systemctl reload sshd' \
     --health-cmd 'ssh -o BatchMode=yes localhost true' \
     --rollback-plan 'restore trusted_user_ca_keys backup and reload sshd' \
     --status health_passed \
     --confirm
   ```

4. Review and issue a direct host certificate when provisioning a server. Preview is
   mandatory in the console and available separately in the CLI so automation can prove
   the exact lifetime, hostnames, public-key fingerprint, signer call, and revocation
   path before making a change. Preview allocates no serial and makes no signer call.

   ```sh
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
   ```

   -> the private host key never leaves the server; only its public `.pub` line enters
   trstctl. The CLI supplies an idempotency key, so retrying the same issuance cannot
   mint a second certificate. Use the direct user type only for an already-authorized
   provisioning workflow; use the attested path below for just-in-time access.

5. Issue a short-lived user certificate tied to a verified identity, not handed to
   anyone who asks. The attested issuer runs an attestation check first and only then
   derives the certificate's principals from the verified result, defaulting to a short
   TTL. Every issuance is an immutable `ssh.attested_cert.issued` event. See [SSH](../features/ssh.md).

   ```sh
   trstctl ssh issue-attested-user \
     --method k8s_sat \
     --payload-base64 "$K8S_SAT_B64" \
     --public-key "$(cat ~/.ssh/id_ed25519.pub)" \
     --key-id jit-deployer \
     --ttl-seconds 900
   ```

   -> the user connects normally and `sshd` validates the certificate against
   the trusted CA with no stored key. Access expires on its own, the
   certificate's principals come from the verified attestation (the caller
   cannot request extras), and the private key stays with the user — never in
   trstctl. The attestation-gated issuer is served through the SSH workflow
   API, CLI, and UI.

6. Pull a certificate back before it expires. Revoking it puts its serial on the SSH
   CA's key-revocation list, served in OpenSSH binary format at `/ssh/krl`, which a
   host's `sshd` consumes via its `RevokedKeys` directive. See [SSH](../features/ssh.md).

   ```sh
   trstctl ssh status
   trstctl ssh revoke --serial <serial> --reason 'operator requested revocation'
   curl -fsS "$TRSTCTL_URL/ssh/krl" -o trstctl.krl
   trstctl ssh retire-host --host edge-1.internal --source <source-id> --run <run-id> --reason 'standing SSH access replaced'
   ```

   -> a revoked certificate is reported as revoked by stock `ssh-keygen`; budget for
   pushing the updated KRL to hosts, since distribution is push-based.

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — do the same
  consolidation for X.509 certificates.
- [onboard-a-team.md](onboard-a-team.md) — isolate each team's access in its own
  tenant.

**Journey:** J8
**Steps through:** F43, F44, F45, F42
