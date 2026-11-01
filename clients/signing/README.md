# trstctl signing clients

Stock signing tools sign with a key held in trstctl's isolated signer through
these clients. The private key never leaves the signer: each client hashes
locally, sends the digest to trstctl's code-signing API
(`POST /api/v1/code-signing/sign`), and returns the signature with the
certificate chain configured for the key
(`GET /api/v1/code-signing/keys/{key_id}/certificate`). trstctl's permissions,
policy and approvals apply to every signature.

This directory is its own MPL-2.0 Go module with no dependencies outside the
standard library.

| Client | For | Status |
| --- | --- | --- |
| `cmd/notation-trstctl` | Notation (plugin contract 1.0, `SIGNATURE_GENERATOR.RAW`) | Available; ECDSA P-256 keys |
| `trstctlsign` | Go programs and the clients here | Available |

## Configuration

Every client reads:

| Variable | Meaning |
| --- | --- |
| `TRSTCTL_URL` | The control plane, for example `https://trstctl.example.com` |
| `TRSTCTL_TOKEN` or `TRSTCTL_TOKEN_FILE` | An API token with `keys:write` (and `keys:read`) |
| `TRSTCTL_CA_FILE` | Optional PEM roots for the control plane's TLS certificate |

## Notation

```bash
go build -C clients/signing -o notation-trstctl ./cmd/notation-trstctl
notation plugin install --file notation-trstctl
notation key add release --plugin trstctl --id release-key
notation sign --key release registry.example.com/app@sha256:...
```

The key needs a certificate chain configured in trstctl
(`code_signing.keys[].certificate_chain_file`); `trstctl-cli code-signing keys csr`
gets a certificate request the key signs inside the signer. Verify with a
Notation trust policy rooted at the CA that issued that certificate.

A signature trstctl refuses — a missing permission, a policy denial, or an
approval that is pending or denied — stops the signing with `ACCESS_DENIED` and
trstctl's reason. A retry after a lost response sends the same idempotency key
for the same key, digest and credential, so trstctl returns the first signature
rather than signing twice.
