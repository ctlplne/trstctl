# Issue and trust SSH access at scale

## Goal

You will replace the pile of standing SSH keys in everyone's `authorized_keys` with
short-lived SSH certificates from a single authority. The outcome is hosts that trust
*one* SSH certificate authority, users who get certificates that expire on their own
(say, valid until 5 p.m.), and a clean inventory of any leftover keys still granting
access. This is for an operator who wants central, time-bounded, auditable SSH access
instead of per-host key copying. The running binary serves the CA, KRL, attested-cert,
rollout-evidence, revocation, and retirement handoff; host file mutation remains in the
operator-confirmed agent path.

## Before you start

- A running control plane and an API token from
  [Getting started](../getting-started.md) (`trstctl token create`).
- The CLI/API pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
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
   replacing. Create an `ssh` discovery source and queue a run; trstctl records host
   keys and standing-access grants — and flags an `authorized_keys` grant whose owner is
   unknown as orphaned. Only fingerprints are stored, never private keys. See
   [Discovery & inventory](../features/discovery-and-inventory.md).

   ```sh
   cat > ssh-source.json <<'JSON'
   {"kind":"ssh","name":"fleet","config":{"targets":["10.0.0.10:22"]}}
   JSON
   trstctl-cli discovery sources create -f ssh-source.json
   echo '{"source_id":"<source-id>"}' | trstctl-cli discovery runs start -f -
   trstctl-cli discovery findings list --run_id <run-id>
   ```

   -> you get a list of standing-access keys to retire as certificates take over. The
   SSH discovery control surface (source/schedule/run/findings) is served; the host-key
   scan executes from the agent/library connector — see
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

4. Issue a short-lived user certificate tied to a verified identity, not handed to
   anyone who asks. The attested issuer runs an attestation check first and only then
   derives the certificate's principals from the verified result, defaulting to a short
   TTL. Every issuance is an immutable `ssh.attested_cert.issued` event. See [SSH](../features/ssh.md).

   ```sh
   cat > ssh-attested-user.json <<EOF
   {
     "method": "k8s_sat",
     "payload_base64": "$K8S_SAT_B64",
     "public_key": "$(cat ~/.ssh/id_ed25519.pub)",
     "approver": "ssh-approver",
     "principals": ["web"],
     "source_addresses": ["10.0.0.0/24"],
     "force_command": "/usr/local/bin/deploy",
     "key_id": "jit-deployer",
     "ttl_seconds": 900
   }
   EOF
   trstctl ssh issue-attested-user -f ssh-attested-user.json
   ```

   -> the user connects normally and `sshd` validates the certificate against the
   trusted CA with no stored key. Access expires on its own, the approver cannot be the
   attested subject, requested principals must match the attestation, and the issued cert
   carries the source-address/force-command guardrails. The attestation-gated issuer is
   served through the SSH workflow API/CLI/UI and still keeps the private key with the
   user, never in trstctl.

5. Pull a certificate back before it expires. Revoking it puts its serial on the SSH
   CA's key-revocation list, served in OpenSSH binary format at `/ssh/krl`, which a
   host's `sshd` consumes via its `RevokedKeys` directive. See [SSH](../features/ssh.md).

   ```sh
   trstctl ssh status
   trstctl ssh revoke --serial <serial> --reason 'operator requested revocation'
   curl -fsS "$TRSTCTL_SERVER/ssh/krl" -o trstctl.krl
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
