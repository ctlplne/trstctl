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

The command prints the CSR as base64 and the exact attestation challenge. TPM
attestation tooling must produce a WebAuthn TPM credential over that challenge
for the CSR key. The mint request uses `key_provider: "tpm2"`. The control plane
checks that the attested public-key digest equals the CSR public-key digest, so
an unrelated software key cannot borrow the host TPM's proof.

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
