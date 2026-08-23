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
  https://localhost:9443/healthz
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

## 3. Open the UI

- Blank evaluation: <https://localhost:8443>
- Populated demo: <https://localhost:9443>

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
