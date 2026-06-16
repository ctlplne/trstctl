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
  so). **Release builds always sign:** the `agent-windows` job in
  `.github/workflows/release.yml` provisions the identity from the
  `WINDOWS_CODESIGN_PFX_BASE64` / `WINDOWS_CODESIGN_PASS` secrets and **fails the
  release if either artifact ships unsigned**, and the `windows / test + MSI` CI
  job signs with `signtool` when the same secret is configured.
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
`agent-windows` release job (`release.yml`) is the gate that signs on every tag.

## Install / uninstall

The MSI registers the service automatically (its `ServiceInstall` /
`ServiceControl` elements, generated from the same `winservice.Spec` the agent
uses). The agent can also manage the service directly:

```bat
trstctl-agent.exe --service=install --enroll-url https://cp:8443/enroll ^
    --ca-bundle C:\ProgramData\trstctl\ca-bundle.pem --server cp:9443 --name %COMPUTERNAME%
trstctl-agent.exe --service=uninstall
```

`--service=install` registers an auto-start `LocalSystem` service whose command
line reproduces the supplied flags with `--service=run`; the SCM then starts the
agent, which enrolls, maintains mutual TLS, and installs and rotates credentials.

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
