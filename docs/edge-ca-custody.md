# Disconnected edge CA key custody

An edge CA is allowed to sign while its host cannot reach the control plane, so
its private key is the dangerous part. The safe default puts that key in a TPM2
object that cannot be exported. The agent persists only a JSON handle containing
the provider name, opaque object ID, algorithm, and public key.

## TPM2 default

Generate generation `1` of the segment key and its CSR:

```sh
trstctl-agent \
  --edge-csr \
  --edge-tenant 77777777-7777-7777-7777-777777777777 \
  --edge-segment 88888888-8888-8888-8888-888888888888 \
  --edge-cn bunker-01-edge-ca \
  --edge-key-provider tpm2 \
  --edge-key-generation 1 \
  --edge-key-handle-out /var/lib/trstctl/edge-ca.keyref.json \
  --edge-csr-out /var/lib/trstctl/edge-ca.csr
```

`--edge-tpm-path` can name `/dev/tpmrm0`, `/dev/tpm0`, or a swtpm Unix
socket. Owner/key authorization values come only from
`--edge-tpm-owner-auth-file` and `--edge-tpm-key-auth-file`; they are read as
bytes and wiped after the device opens. Repeating the same tenant, segment, and
generation reconciles the same persistent object after a lost response. Use a
new generation label when intentionally rotating the edge CA.

The command prints the CSR as base64 and the exact attestation challenge. A
separate TPM attestation identity key (AIK) must already have a certificate
chain issued by the operator's vetted TPM attestation authority. Its private
key stays in the TPM; the public chain is what the segment policy pins. The
AIK handle file has the same public-only JSON shape as `edge-ca.keyref.json`.
Provision the AIK under a *different* durable operation label from the edge CA,
then obtain its AIK-profile certificate from that authority. Do not sign an
arbitrary host-generated AIK public key without the authority's device
enrollment and endorsement checks. A local QA authority may issue a disposable
AIK certificate for a local swtpm; that qualifies only the emulator contract.
To create the separate TPM-resident AIK key and a proof-of-possession CSR with
the shipped agent, use the same tenant and segment but a distinct generation:

```sh
trstctl-agent \
  --edge-csr \
  --edge-tenant 77777777-7777-7777-7777-777777777777 \
  --edge-segment 88888888-8888-8888-8888-888888888888 \
  --edge-key-generation aik-1 \
  --edge-cn bunker-01-aik \
  --edge-key-provider tpm2 \
  --edge-key-handle-out /var/lib/trstctl/edge-aik.keyref.json \
  --edge-csr-out /var/lib/trstctl/edge-aik.csr
```

The attestation authority issues an AIK certificate for that public key with
an empty subject, TPM manufacturer/model/version directory-name SAN, digital
signature use, and the TPM AIK extended key usage `2.23.133.8.3`. Put the AIK
leaf first and its chain through the pinned root in `edge-aik-chain.pem`.

With the edge CSR, both public handle files, and the AIK certificate chain on
the host, have the **same TPM** certify the edge CA's persistent signing object:

```sh
trstctl-agent \
  --edge-attest \
  --edge-tenant 77777777-7777-7777-7777-777777777777 \
  --edge-segment 88888888-8888-8888-8888-888888888888 \
  --edge-key-provider tpm2 \
  --edge-csr-in /var/lib/trstctl/edge-ca.csr \
  --edge-ca-key-handle /var/lib/trstctl/edge-ca.keyref.json \
  --edge-aik-key-handle /var/lib/trstctl/edge-aik.keyref.json \
  --edge-aik-cert-chain /var/lib/trstctl/edge-aik-chain.pem \
  --edge-attestation-out /var/lib/trstctl/edge-attestation.json \
  --edge-parent-ca-id 99999999-9999-9999-9999-999999999999 \
  --edge-host bunker-01 \
  --edge-mint-ttl 24h \
  --edge-mint-request-out /var/lib/trstctl/edge-mint.json
```

Use `--edge-tpm-path` for a swtpm socket or a nondefault TPM device, and
`--edge-tpm-key-auth-file` / `--edge-aik-auth-file` for distinct 0600
authorization files. The agent verifies the CSR against the edge TPM handle,
the AIK certificate against its own TPM handle, and the resulting TPM2_Certify
statement through the same parser used by the server. It writes the WebAuthn
TPM credential as a 0600 file. It refuses a mismatch; there is no software
attestation fallback. The mint request carries the CSR as base64 DER,
`attestation_credential_json` as base64 of that JSON file, and
`key_provider: "tpm2"`. The control plane separately checks the installed
root and binds the attested key digest to the CSR public-key digest. It also
reads the attributes the TPM certified for that key: unless the TPM generated it
(`sensitiveDataOrigin`) and will release it neither to another TPM (`fixedTPM`)
nor under another parent (`fixedParent`), the key is not device-bound and the
mint is refused. Keys the agent creates have all three. The
certificate authority selected for minting must permit a subordinate CA. Review
`edge-mint.json` and send it through the native CLI with a fresh idempotency key:

```sh
trstctl-cli --idempotency-key edge-bunker-01-generation-1 \
  edge delegations mint -f /var/lib/trstctl/edge-mint.json
```

The same JSON body can be sent to `POST /api/v1/edge/delegations`. An absent
`--edge-mint-request-out` leaves only the attestation file; the agent never
contacts the control plane from this offline host mode.

In the console, open Certificates → Certificate authorities → Authorities →
Delegated edge CAs → **Mint delegated edge CA**. Upload or paste the complete
host-generated `edge-mint.json`. The console checks that its segment is enabled
for the chosen provider and shows the exact public CSR and TPM credential before
submission. A lost response keeps the same reviewed request and idempotency
key for retry. Success requires an independent read of the same delegation,
key digest, status, and public certificate chain. Copy that chain from the
read-only result into `edge-ca.crt` on the exact host; the TPM key never crosses
the browser or control plane. The console also offers **Reconcile host journal**
for the host's `edge-journal.json`, showing the exact certificates and counts
for reconciled, already recorded, violated, and rejected leaves. **Revoke
delegated edge CA** reviews the exact host, delegation ID, certificate serial,
and reason before sending the request and reading the revoked state back.
The host agent may write an empty `host` field in its journal; the console
binds that journal to the operator-selected delegation host before sending it.

The delegated CA's initial and revoked status also enqueue signed parent-CA
CRL publication in the same event transaction. Publication is retried by the
outbox worker; an issued-ledger row alone does not mean relying clients can
reject a revoked delegation. The issued event retains the complete public
delegated and parent chain, so
`GET /api/v1/edge/delegations/{id}` recovers exactly what the mint returned
after a lost response or projection rebuild. For older events that retained
only the delegated certificate, detail readback adds the current parent chain
only after checking that its public certificate signed that exact delegated
certificate. If the historical parent cannot be verified, readback refuses
instead of presenting a different trust path as recovered.

After the control plane returns the delegated certificate chain:

```sh
trstctl-agent \
  --edge-issue \
  --edge-key-provider tpm2 \
  --edge-ca-cert /var/lib/trstctl/edge-ca.crt \
  --edge-ca-key-handle /var/lib/trstctl/edge-ca.keyref.json \
  --edge-issue-cn db.edge.example.test \
  --edge-cert-out /var/lib/trstctl/db.crt \
  --edge-leaf-key-out /var/lib/trstctl/db.key \
  --edge-journal /var/lib/trstctl/edge-journal.json
```

The agent verifies that the certificate public key equals the handle public key
before asking the TPM to sign. A missing TPM, unknown handle, changed provider,
or mismatched certificate refuses issuance. None triggers a software fallback.

## PKCS#11 alternative

Set `--edge-key-provider pkcs11` and configure
`--edge-pkcs11-module`, `--edge-pkcs11-token`, and
`--edge-pkcs11-pin-file` for both CSR creation and issuance. The shipping module
creates persistent RSA-2048 private objects with `CKA_SENSITIVE=true` and
`CKA_EXTRACTABLE=false`. The segment policy must explicitly include `pkcs11` in
`allowed_key_providers`.

The default static artifact has CGO disabled and therefore refuses this lane.
Build the agent with CGO enabled on the token host so it can load the vendor's
native PKCS#11 module; a static artifact never substitutes software custody.

The host TPM attestation still authenticates the host and binds the request to
the CSR, but it cannot attest a different PKCS#11 object. Evidence therefore
says `host_attested_operator_claim`. It does not claim that the TPM proved token
custody. Independent token inspection is the deployment proof that the object
is non-extractable.

## Exportable software exception

Software custody needs two independent choices:

1. The segment policy includes `software` in `allowed_key_providers`.
2. Both CSR creation and issuance specify
   `--edge-key-provider software --edge-allow-software-key`.

The agent then uses `--edge-key-out` / `--edge-ca-key` for a mode-0600 PKCS#8
PEM file. The control plane records `key_storage=file`,
`key_exportable=true`, and
`custody_assurance=host_attested_software_exception`. The Sovereign/edge panel
shows that warning. A host TPM proof authenticates the request but never changes
the software key's exportable classification.

## Segment policy shape

An enabled policy is still default-off unless it exists, pins at least one TPM
attestation root, and carries DNS name constraints. Custody is an additional
closed allowlist:

In the console, open Certificates → Certificate authorities → Authorities →
Delegated edge CAs → **Configure edge segment**. An operator with
`issuers:write` can select an existing declared segment ID; an operator who
also has `discovery:write` can declare a segment by name and exact address or
CIDR. Paste public PEM attestation roots, enter comma-separated permitted and
excluded DNS subtrees, then review the entire public root bundle and provider
allowlist before saving. A lost response leaves the reviewed request available
for retry with the same idempotency keys. The resulting row shows the active
policy; it does not prove that a host has attested or that a delegated CA was
minted. Disable an existing segment through the same form to stop new mints.

For automation, declare the segment with `POST /api/v1/discovery/segments` or
`trstctl-cli discovery segments create -f segment.json`, retain the returned
UUID, then use `PUT /api/v1/edge/segments/{segmentID}` or
`trstctl-cli edge segments set <segmentID> -f policy.json`. Read back with
`GET /api/v1/edge/segments` or `trstctl-cli edge segments list`. Keep the
attestation private key on the host or in its test fixture; the policy accepts
only its public root certificate.

```json
{
  "enabled": true,
  "attestation_roots_pem": ["-----BEGIN CERTIFICATE-----..."],
  "permitted_dns_domains": ["edge.example.test"],
  "excluded_dns_domains": ["blocked.edge.example.test"],
  "allowed_key_providers": ["tpm2"]
}
```

Omitting `allowed_key_providers` means exactly `["tpm2"]`. Unknown providers,
duplicate values, and unapproved PKCS#11/software mint requests fail closed.
