# Trust the local evaluation certificate

The local Compose stacks use HTTPS from the first boot. They create one stable,
self-signed server certificate and publish a **certificate-only** copy for your
workstation. Trust that public copy before opening the UI. Do not copy the private
`/data/tls/internal-server.pem` file and do not bypass the browser warning.

This is local trust-on-first-use for a disposable evaluation. Production must use
a certificate issued by an authority your operators already trust.

## 1. Copy and inspect the public certificate

For the blank evaluation on port `8443`:

```bash
docker compose -f deploy/docker/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-eval-control-plane.crt

openssl x509 -in ./trstctl-eval-control-plane.crt \
  -noout -subject -issuer -dates -fingerprint -sha256

curl --cacert ./trstctl-eval-control-plane.crt \
  https://localhost:8443/healthz
```

For the populated demo on port `9443`, use its Compose file and filename:

```bash
docker compose -f deploy/demo/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-demo-control-plane.crt

openssl x509 -in ./trstctl-demo-control-plane.crt \
  -noout -subject -issuer -dates -fingerprint -sha256

curl --cacert ./trstctl-demo-control-plane.crt \
  https://127.0.0.1:9443/healthz
```

Expected: `curl` prints `{"status":"ok"}`. Stop if it does not. Never use `curl -k`
as a substitute: `-k` encrypts traffic but declines to prove which
server answered.

## 2. Trust that exact file for the evaluation

Choose the instructions for the browser profile you will use. Close and reopen
the browser after importing the certificate.

### macOS — Chrome, Edge, and Safari

Open **Keychain Access**, select the **login** keychain, import
`trstctl-eval-control-plane.crt`, open the imported certificate, expand
**Trust**, and set **Secure Sockets Layer (SSL)** to **Always Trust**. Use the
demo filename instead when evaluating port `9443`.

The equivalent terminal command for the current user's login keychain is:

```bash
security add-trusted-cert -r trustRoot \
  -k "$HOME/Library/Keychains/login.keychain-db" \
  ./trstctl-eval-control-plane.crt
```

### Windows — Chrome and Edge

In PowerShell, import only into the current user's root store:

```powershell
$cert = Import-Certificate `
  -FilePath .\trstctl-eval-control-plane.crt `
  -CertStoreLocation Cert:\CurrentUser\Root
$cert.Thumbprint
```

Record the printed thumbprint. It identifies the exact trust entry to remove.

### Linux — Chrome and Chromium

Install the NSS client tools for your distribution once, create the current
user's database if needed, and add this one certificate:

```bash
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password 2>/dev/null || true
certutil -d "sql:$HOME/.pki/nssdb" -A \
  -n "trstctl local evaluation" -t "C,," \
  -i ./trstctl-eval-control-plane.crt
```

Firefox may use its own certificate database. In Firefox, open
**Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import**, select the same public file, and trust it only for
identifying websites.

### Isolated browser profile (any OS)

Every option above changes a trust store on your workstation. If you would rather
change nothing, give the evaluation its own Firefox profile that trusts only this one
certificate, with TLS validation fully on:

```sh
# 1. An empty profile directory and the certificate you inspected above.
mkdir -p ./trstctl-eval-profile && cp control-plane.crt ./trstctl-eval-profile/

# 2. Build the profile's certificate database with NSS certutil (here from a
#    throwaway container, so nothing is installed on the workstation).
docker run --rm -v "$PWD/trstctl-eval-profile:/profile" alpine:3.20 sh -c \
  'apk add --no-cache nss-tools >/dev/null && certutil -N -d sql:/profile --empty-password && \
   certutil -A -n "trstctl evaluation" -t "C,," -i /profile/control-plane.crt -d sql:/profile && \
   certutil -L -d sql:/profile'

# 3. Open Firefox on that profile only.
firefox --profile "$PWD/trstctl-eval-profile" https://127.0.0.1:9443
```

`scripts/dev/isolated-firefox-profile.sh` does the same three steps. Delete the
directory when you finish; no other profile or store ever learned about the
certificate. The same profile drives headless Playwright (`launchPersistentContext`)
for scripted evaluations without `ignoreHTTPSErrors`.

## 3. Open the UI

- Blank evaluation: <https://localhost:8443>
- Populated demo: <https://127.0.0.1:9443>

The demo uses `127.0.0.1` while the blank stack uses `localhost` so their
host-scoped browser session cookies do not replace each other. Both names are
present in the generated certificate and both stay on the local workstation.

The page should open without a certificate warning. If a warning remains, stop
and confirm that the hostname, port, imported file, and SHA-256 fingerprint are
the ones you inspected above.

## Remove the local trust entry

Remove the evaluation certificate when you finish, especially before deleting
or recreating the Compose data volume. A new volume creates a new TLS identity;
the old trust decision must not silently carry over.

- **macOS:** delete the imported certificate from the login keychain in Keychain
  Access.
- **Windows:** use the exact thumbprint recorded at import:

  ```powershell
  Remove-Item "Cert:\CurrentUser\Root\<RECORDED-THUMBPRINT>"
  ```

- **Linux NSS:**

  ```bash
  certutil -d "sql:$HOME/.pki/nssdb" -D -n "trstctl local evaluation"
  ```

Deleting the Compose volume does **not** remove a workstation trust entry. These
are two separate cleanup actions.
