# trstctl agent on Windows

The trstctl agent runs on Windows as a Service Control Manager service and
installs certificates into the Windows certificate store (CryptoAPI / CNG). This
directory holds the MSI installer definition; the agent binary itself is built
from `cmd/trstctl-agent`.

## Build, sign, and publish

```sh
make dist-windows
```

This cross-compiles `trstctl-agent.exe` for `windows/amd64`, copies the WiX
source, Authenticode-signs **both the binary and the MSI** when a code-signing
identity is provided, builds the MSI (when a WiX toolchain is present), and writes
a `SHA256SUMS` manifest into `dist/`.

- **Signing.** Set `SIGN_PFX` (and `SIGN_PASS`) to a code-signing PKCS#12 to
  Authenticode-sign the `.exe` and `.msi` with `osslsigncode` (Linux/macOS) — on
  Windows, sign with `signtool`. The target verifies each signature after signing.
  Without a signing identity the artifacts are left unsigned (and the target says
  so). **Published release artifacts are signed:** the `agent-windows` job in
  `.github/workflows/release.yml` provisions the identity from the
  `WINDOWS_CODESIGN_PFX_BASE64` / `WINDOWS_CODESIGN_PASS` secrets and uploads the
  Windows agent artifacts only after signing/verification. If a version-tag run
  does not have that identity, the job skips the upload instead of shipping
  unsigned `.exe`/`.msi` files. The `windows / test + MSI` CI job signs with
  `signtool` when the same secret is configured.
- **MSI.** `make dist-windows` builds the MSI with `wixl` (msitools) when
  available; on Windows use the WiX Toolset (`candle` + `light`) against
  `trstctl-agent.wxs`. Sign the resulting `.msi` the same way as the binary.
- **SHA-256.** `dist/SHA256SUMS` is the published checksum manifest
  (`sha256sum -c` compatible). The same manifest can be produced
  programmatically via `internal/dist.Checksums`.

CI exercises this on two jobs: `windows cross-build` (Linux,
`make windows-build`: `GOOS=windows go build ./... && go vet ./...`) for a fast
guard, and `windows / test + MSI` (a real `windows-latest` runner) which runs
the Windows agent tests — including a round-trip against the live per-user
certificate store — builds the MSI with the WiX Toolset, and Authenticode-signs
the `.exe`/`.msi` with `signtool` when `WINDOWS_CODESIGN_PFX_BASE64` is set. The
`agent-windows` release job (`release.yml`) is the gate that prevents unsigned
Windows agent artifacts from being published on a version tag.

## Install / uninstall

The MSI registers the service automatically (its `ServiceInstall` /
`ServiceControl` elements, generated from the same `winservice.Spec` the agent
uses). A production install must provide the first-boot enrollment settings:
the enrollment base URL, a one-time bootstrap token file, the CA bundle, the
agent-channel endpoint, and the TLS server name the control plane cert carries.

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\trstctl | Out-Null
$token = (trstctl-cli agents enroll-token | ConvertFrom-Json).token
Set-Content -Path C:\ProgramData\trstctl\bootstrap-token.txt -Value $token -NoNewline

msiexec /i trstctl-agent.msi /qn `
  ENROLLURL=https://cp:8443 `
  SERVER=cp:9443 `
  SERVERNAME=cp `
  CABUNDLE=C:\ProgramData\trstctl\ca-bundle.pem `
  BOOTSTRAPTOKENFILE=C:\ProgramData\trstctl\bootstrap-token.txt
```

The agent can also manage the service directly:

```bat
trstctl-agent.exe --service=install --enroll-url https://cp:8443 ^
    --bootstrap-token-file C:\ProgramData\trstctl\bootstrap-token.txt ^
    --ca-bundle C:\ProgramData\trstctl\ca-bundle.pem --server cp:9443 ^
    --server-name cp --name %COMPUTERNAME%
trstctl-agent.exe --service=uninstall
```

`--service=install` registers an auto-start `LocalSystem` service whose command
line reproduces the supplied flags with `--service=run`; the SCM then starts the
agent, which enrolls, maintains mutual TLS, and installs and rotates credentials.
The token file is single-use. After enrollment succeeds and the service persists
its certificate, rotate or delete the token file.

## Certificate store destination

The agent installs certificates into a Windows system store — for example the
machine Personal store, `LocalMachine\MY` — associating the private key
non-exportable under the Microsoft Software Key Storage Provider (CNG). The
CryptoAPI/CNG backend (`internal/agent/destination/certstore`, build-tagged for
Windows) installs a cert-with-key by encoding a transient PKCS#12 in the crypto
boundary (`internal/crypto/pfx`) and importing it with `PFXImportCertStore`,
which persists and links the key. The `windows / test + MSI` CI job runs this
end-to-end against the per-user store on a real Windows runner; the
platform-neutral contract is also exercised on every platform by the in-process
`Memory` store.
