# Disconnected emergency certificate issuance

Use this path when the control-plane API or PostgreSQL is unavailable. The
isolated `trstctl-signer` process reads a sealed recovery CA and a public policy
from its own files. It does not contact the control plane or database. Two
different custodians sign one exact request; knowing their names is insufficient.
The resulting certificate uses the workload's CSR public key. Keep the workload
private key with the workload.

## Prepare before an outage

1. Give each custodian a separate signer host/account and have each run
   `trstctl-signer --offline-generate-custodian <id>
   --offline-custodian-private-out <private.pem>
   --offline-custodian-public-out <public.json>`. The private file is created
   owner-only. Each custodian keeps only their own private file. Collect the two
   public JSON roster entries, never the private files.
2. Write a public policy JSON with `tenant_id`, `deployment_id`, an increasing
   `epoch`, `threshold` (at least 2), `max_ttl_seconds`, a SAN allowlist such as
   `permitted_dns_suffixes`, and the `custodians` roster. A request outside these
   bounds is refused even if custodians sign it.
3. On the isolated recovery signer, run
   `trstctl-signer --offline-init-policy <policy.json> --keystore <offline-vault>
   --kek <offline-kek>`. The signer seals a new CA key in the dedicated vault and
   prints the public kit path and its SHA-256. The offline CA handle is marked
   `offlineOnly`; the generic signer `Sign` RPC refuses it, even when pointed at
   the same key store. Protect the vault and KEK as distinct backup assets.
4. Copy only `offline-kit.json` to the control-plane host. In the deployment
   config, set `breakglass.offline_kit_file` to that read-only copy and
   `breakglass.offline_kit_sha256` to the independently recorded printed digest.
   The kit's tenant must equal `breakglass.tenant_id`, and its deployment must
   equal `breakglass.deployment_id`. A licensed deployment must also match
   `license.deployment_id`. Startup refuses a kit bound to another tenant or
   deployment; the free core can set `breakglass.deployment_id` without a license.
   Keep the existing `breakglass.ca_cert_file` and `public_key_file` trust anchor
   for online ceremonies. Start the control plane and check the recovery route.
   Startup fails if the kit differs from the pin. A self-signed kit alone is not
   a trust anchor.

## Issue while disconnected

1. Create a PKCS#10 CSR with the workload key. Inspect its common name and
   every SAN with `openssl req -in <csr.pem> -noout -text`. Copy the public CSR
   to the isolated signer.
2. Run `trstctl-signer --offline-prepare-kit <offline-kit.json>
   --offline-prepare-csr <csr.pem> --offline-prepare-requester <requester>
   --offline-prepare-subject <exact-csr-common-name>
   --offline-prepare-reason <incident-reason> --offline-prepare-ttl 10m
   --offline-output <request.json>`. This chooses a random operation ID and a
   one-hour approval deadline. Give the same request file to each custodian.
3. Each custodian checks the request's tenant, deployment, policy epoch,
   `ca_public_key_sha256` against their retained public kit, reason, TTL,
   common name and signed SANs, then runs `trstctl-signer
   --offline-approve-request <request.json> --offline-approve-key <their-key.pem>
   --offline-approve-custodian <their-id> --offline-output <their-approval.json>`
   in their own session. Combine the public approval JSON objects into an array
   file, for example `jq -s '.' alice-approval.json bob-approval.json >
   approvals.json`.
4. Run `trstctl-signer --offline-issue-request <request.json>
   --offline-issue-approvals <approvals.json> --keystore <offline-vault>
   --kek <offline-kek> --offline-output <bundle.json>`. The signer verifies
   both signatures and the identity policy before signing. It seals an executing
   marker before the private-key operation and the complete bundle before
   replying. If the process dies before the completed result, the signer
   resumes the same approved intent; if it dies after completion, an exact
   retry returns the same bundle. Changing the request under the same ID is
   refused.
5. Install the leaf and retained workload private key using the target's
   emergency deployment procedure. Check the served endpoint independently with
   `openssl s_client -connect <host:port> -servername <name>
   -CAfile <offline-ca.pem> -verify_hostname <name> -verify_return_error`.

## Recover the control plane

After restoring the API and database, submit the complete bundle with
`POST /api/v1/breakglass/reconcile` or `trstctl-cli breakglass reconcile -f
<body.json>`, where the body is `{"bundles":[<bundle>]}`. The Incidents console
also accepts this JSON. The server checks the independently pinned kit, all
custodian signatures, the CSR/leaf identity and lifetime, and the CA signature.
It writes an immutable `breakglass.issued` v3 event containing the public proof.
An exact retry with another HTTP idempotency key records zero new events; a
different bundle under the same tenant and request ID conflicts. Save the
incident's stock-client served-certificate readback alongside the audit export.

`--allow-insecure-dev-nonlinux` is only for a local macOS lab. Production
recovery signers should run on a hardened Linux host with protected KEK storage.
