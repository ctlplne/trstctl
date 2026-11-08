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
| `pkcs11` | PKCS #11 tools: jarsigner, osslsigncode and others (`libtrstctl-pkcs11`) | Available; ECDSA P-256 and RSA keys |
| `ksp`, `cmd/trstctl-ksp-register` | signtool and other Windows CNG tools (`trstctl-ksp.dll`, a key storage provider, and its installer) | Available for 64-bit Windows (x64); ECDSA P-256 and RSA keys |
| `trstctlsign` | Go programs and the clients here | Available |

## Configuration

Every client reads:

| Variable | Meaning |
| --- | --- |
| `TRSTCTL_URL` | The control plane, for example `https://trstctl.example.com` |
| `TRSTCTL_TOKEN` or `TRSTCTL_TOKEN_FILE` | An API token with `keys:write` (and `keys:read`) |
| `TRSTCTL_CA_FILE` | Optional PEM roots for the control plane's TLS certificate |
| `TRSTCTL_APPROVAL_WAIT` | How long a signature waits for a pending approval (Go duration; default `10m`, `0` does not wait) |

## PKCS #11 module

`libtrstctl-pkcs11` is a PKCS #11 v2.40 module with one token, `trstctl`. Its
PIN is the API token; `TRSTCTL_PKCS11_KEYS` names the code-signing keys
(comma-separated) it offers. Each key appears as a private-key handle with its
public key and certificate chain, paired by `CKA_ID` and labeled with the key
id. The private-key handle is sensitive and never extractable — there is no
key in the module — and the token signs and does nothing else.

Mechanisms: `CKM_ECDSA` (a SHA-256 hash in), `CKM_ECDSA_SHA256`, `CKM_RSA_PKCS`
(a SHA-256 DigestInfo in) and `CKM_SHA256_RSA_PKCS`. Each signature is checked
against the key's certificate before it is returned, and trstctl records the
mechanism as the request's artifact type (`pkcs11:CKM_ECDSA_SHA256`). A
signature trstctl refuses is `CKR_FUNCTION_REJECTED`, with trstctl's reason on
standard error.

```bash
make signing-clients     # bin/libtrstctl-pkcs11.so (needs cgo)
export TRSTCTL_URL=https://trstctl.example.com TRSTCTL_PKCS11_KEYS=release-key
```

jarsigner, through the JDK's SunPKCS11 provider:

```bash
printf 'name = trstctl\nlibrary = /opt/trstctl/libtrstctl-pkcs11.so\nslotListIndex = 0\n' > trstctl.cfg
jarsigner -keystore NONE -storetype PKCS11 -addprovider SunPKCS11 -providerArg trstctl.cfg \
  -storepass:env TRSTCTL_TOKEN -sigalg SHA256withECDSA app.jar release-key
```

osslsigncode, through the OpenSSL pkcs11 engine (`libengine-pkcs11-openssl` on Debian):

```bash
osslsigncode sign -pkcs11module /opt/trstctl/libtrstctl-pkcs11.so -certs release-chain.pem \
  -key 'pkcs11:object=release-key;type=private' -readpass token.txt -h sha256 -in app.exe -out app-signed.exe
```

## Windows key storage provider

`trstctl-ksp.dll` is a Windows CNG key storage provider, registered as
`trstctl Key Storage Provider`. `TRSTCTL_KSP_KEYS` names the code-signing keys
(comma-separated) it offers as key containers, each with its certificate chain
configured in trstctl. It signs SHA-256 hashes: ECDSA P-256 keys, and RSA keys
with PKCS #1 v1.5 padding (PSS is refused). Each signature is checked against
the key's certificate before it is returned, and trstctl records the operation
as the request's artifact type (`ksp:ECDSA_P256_SHA256`, `ksp:RSA_PKCS1_SHA256`).
It creates, imports, deletes and exports no private key — there is none in the
provider. A signature waiting for an approval is held open for up to
`TRSTCTL_APPROVAL_WAIT`, as in the other clients, and a signature trstctl
refuses is `NTE_PERM`, with trstctl's reason on standard error.
`TRSTCTL_KSP_TRACE=1` logs every call CNG makes, with its names, flags and
result.

Build it on Linux or macOS with MinGW-w64 (`gcc-mingw-w64-x86-64` and
`binutils-mingw-w64-x86-64` on Debian); the target also builds the installer and
checks the DLL exports `GetKeyStorageInterface` and imports only KERNEL32.dll
and msvcrt.dll:

```bash
make signing-ksp-windows   # bin/trstctl-ksp.dll and bin/trstctl-ksp-register.exe
```

On Windows, from an elevated prompt, install it (the DLL is copied into
System32, where only administrators can replace it) and check that CNG lists it:

```powershell
.\trstctl-ksp-register.exe install .\trstctl-ksp.dll
.\trstctl-ksp-register.exe status
```

Then sign with signtool, naming the provider (`/csp`), the trstctl key (`/kc`)
and the key's certificate (`/f`, the leaf of its chain):

```powershell
$env:TRSTCTL_URL = 'https://trstctl.example.com'
$env:TRSTCTL_TOKEN_FILE = 'C:\trstctl\token.txt'
$env:TRSTCTL_KSP_KEYS = 'release-key'
signtool sign /fd sha256 /f release.cer /csp "trstctl Key Storage Provider" /kc release-key app.exe
signtool verify /pa app.exe
```

`trstctl-ksp-register uninstall` removes the registration and the copied DLL.

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

When trstctl requires a signing approval, the request waits: the client resends
the same request — the same digest and idempotency key, which is what the approver
grants — until the approval is granted (the tool then signs), denied or expired,
or `TRSTCTL_APPROVAL_WAIT` runs out. A signature trstctl refuses — a missing
permission, a policy denial, a denied or expired approval — stops the signing with
`ACCESS_DENIED` and trstctl's reason. A retry after a lost response sends the same
idempotency key for the same key, digest and credential, so trstctl returns the first
signature rather than signing twice.
