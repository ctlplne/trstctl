# Lightweight persistent partner lab

This opt-in overlay turns the normal seeded demo into a real local lifecycle lab. It keeps one independent ACME CA (Pebble), its DNS challenge server, a bounded incident receiver for OpsGenie and PagerDuty contracts, a local Mailpit SMTP receiver, and one nonroot edge host running real Apache, NGINX, HAProxy, Caddy, Traefik, and PostgreSQL processes. The same trstctl host collector updates all six services, so host-role jobs cannot race between unrelated collectors.

The tenant DNS-01 provider uses `trstctl.partner-lab.example.com` as the CAA
identifier for trstctl's **served** ACME CA. The separate upstream Pebble CA in
`trstctl-lab.json` uses `pebble.local`. Keep these identities distinct: a CAA record
allowing Pebble must not be presented as authorization for trstctl to issue.
Existing retained labs keep their stored provider configuration. Edit the
**Local Pebble DNS validation** row on **How machines request credentials** and set
its CAA issuer domain to `trstctl.partner-lab.example.com` before using the
served `/directory`; this is a tenant configuration change, not a restart flag.

## Local Envoy PQC host-agent target

`docker-compose.pqc-envoy.yml` runs a real Envoy and a small native REST xDS
controller in one shared network namespace for a separate, loopback-only PQC
migration canary. A trstctl-agent container from the product image can join the
controller service's network namespace to own both management and listener
loopback addresses. It starts with
TLS 1.2, `ECDHE-RSA-AES128-GCM-SHA256`, and classical X25519/P-256 groups.
The controller retains its LDS state in its own named volume and only confirms
a PUT after Envoy's active listener reports the requested policy. The product's
assigned host agent still performs its own TLS handshake and signs the result.

Create a disposable certificate and key in a private directory, then start the
fixture from the repository root:

```sh
mkdir -p -m 700 "$PWD/private/pqc-envoy"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj /CN=pqc-edge.local.qa \
  -addext subjectAltName=DNS:pqc-edge.local.qa \
  -keyout "$PWD/private/pqc-envoy/key.pem" \
  -out "$PWD/private/pqc-envoy/cert.pem"
chmod 600 "$PWD/private/pqc-envoy/"*.pem
PQC_ENVOY_CERT_DIR="$PWD/private/pqc-envoy" \
  docker compose -p trstctl-pqc-lab \
  -f deploy/demo/lab/docker-compose.pqc-envoy.yml up -d
```

The management API is `http://127.0.0.1:19080/v1/tls-posture/pqc-edge`, the
TLS listener is `127.0.0.1:11444`, and Envoy admin is at
`http://127.0.0.1:19180`. All three published ports bind only to loopback.
Register an enabled Envoy deployment target **named `pqc-edge`**, because the
target name selects `/v1/tls-posture/pqc-edge`; `secret_name` selects the SDS
secret and does not select the posture resource. Set `executor: agent`, the
exact enrolled host assignment, `endpoint: http://127.0.0.1:19080`,
`secret_name: pqc-edge`, and `verify_server_name: pqc-edge.local.qa`.
For an agent sharing the fixture's container network namespace, set
`verify_address: 127.0.0.1:8443`; for an agent on the Mac host, use the
published `127.0.0.1:11444`. Start that agent with `--relay-claim` and
`--host-rollback-dir` in persistent private storage. The agent's Go TLS
probe verifies X25519MLKEM768 directly; a native OpenSSL 3.5+ probe is an
optional fallback when the host's Go TLS runtime cannot inspect a served
leaf. Enable `pqc.posture` and
`pqc.posture.rollback` in the control plane's claimable job kinds. These
actions use the normal target registration and agent enrollment APIs; a
controller PUT by itself is only fixture setup, not product migration proof.

Independent checks can use `openssl s_client -connect 127.0.0.1:11444
-servername pqc-edge.local.qa -tls1_2 -brief` before migration and
`-tls1_3 -groups X25519MLKEM768 -brief` afterward. After rollback, repeat
both; the TLS 1.2 predecessor must work again and the hybrid-only TLS 1.3
probe must fail. Keep the fixture's private certificate and the host rollback
store outside disposable temporary directories.

## Run every safe local journey

From the repository root:

```sh
deploy/demo/lab/run.sh
```

The script starts or resumes the lab, executes six real TLS lifecycle journeys, then runs the complete shipped production-assembly census and retains all 81 capability rows as evidence. It deliberately does **not** tear the lab down. On a retained run, the runner finds each existing deployed identity by its exact DNS name, checks its owner, external issuer, connector, bound target, agent, paths, verifier settings, live Pebble-signed certificate, and matching confirmed receipt. A mismatch fails the journey without replacing or deleting the existing binding. It then performs a new target dry run, renewal, independent TLS readback, and host rollback. The renewal wait accepts only the verified receipt for that run's exact idempotency key; older receipts in UUID-sorted history cannot satisfy it. The receipt marks retained binding checks separately from first-time enrollment, so a rerun does not claim another first deployment.

During repair, use the short live profile so a new candidate gets fast service
feedback without claiming that the full release gate ran:

```sh
TRSTCTL_LAB_PROJECT=trstctl-partner-lab-repair \
TRSTCTL_LAB_RUN_DOD=0 deploy/demo/lab/run.sh
```

The default `TRSTCTL_LAB_RUN_DOD=1` is the qualification profile. It follows
the live journeys with the full definition-of-done census and is mandatory
before a candidate is called qualified.

Run that census on native `amd64` Linux or a validated Docker Desktop Rosetta
setup. Apple Silicon Docker using QEMU user emulation cannot expose the guest
executable through `/proc/<pid>/map_files`, which the census requires to prove
the exact binary under test. In that case the live journeys can pass while the
census fails before exercising its rows. See
[the local qualification host limit](../../../docs/limitations.md#local-qualification-host-limit).

Each project name also owns its control, seeder, and front-door image tags.
Docker still shares unchanged layers, but a later repair build cannot invalidate
the image digest an earlier retained census is actively examining.

Open the console at <https://127.0.0.1:9443>. The real target listeners remain at:

- Apache: <https://127.0.0.1:10443>
- NGINX: <https://127.0.0.1:10444>
- HAProxy: <https://127.0.0.1:10445>
- Caddy: <https://127.0.0.1:10446>
- Traefik: <https://127.0.0.1:10447>
- PostgreSQL TLS: `127.0.0.1:10448` (PostgreSQL SSLRequest negotiation, not browser HTTPS)
- Mailpit inbox: <http://127.0.0.1:18025> (local-only SMTP listener is inside the lab network namespace at `127.0.0.1:1025`)

The browser will not recognize the target DNS names when you use the IP address. The automated probes connect to the published ports with the correct SNI names and verify the resulting chains against the pinned public Pebble roots captured for this lab.

Pebble generates a new issuing root when its process restarts. The lab keeps a
private, bounded bundle of roots fetched from Pebble's authenticated root
endpoint, so retained listeners can still be checked against their original CA
while a renewal moves them to the current CA. The current root remains in
`runtime-pebble-root.crt`; `trusted-pebble-roots.pem` and
`pebble-root-trust.json` record the overlap in the project's `labevidence`
volume. The runner still requires TLS chain validation, the exact DNS name,
and a matching product delivery receipt. A repeated `run.sh` performs a fresh
renewal and rollback through the product after checking each retained binding.

If you are upgrading an existing retained lab whose earlier root was overwritten
before the bundle existed, provide the previously captured **public** Pebble
root on the next run:

```sh
TRSTCTL_LAB_PREVIOUS_PEBBLE_ROOT_FILE=/absolute/path/to/previous-pebble-root.crt \
deploy/demo/lab/run.sh
```

The import must be a self-signed CA certificate. If the earlier root was never
captured, the old listener cannot be independently trusted; reissue it under
the current CA through the product before calling the retained journey verified.

## Licensed profile (Enterprise Provider)

The lab can run as a licensed customer deployment. Sign a license with the
vendor helper (`trstctl-license sign --tier provider ...`, see
`docs/editions.md`), keep it as a `0600` file, and start the lab with the
vendor's public key:

```bash
TRSTCTL_LAB_LICENSE_FILE=/secure/partner-lab-license.json \
TRSTCTL_LAB_LICENSE_KEYS_B64="$(base64 -w0 vendor-ed25519.pub)" \
TRSTCTL_LAB_LICENSE_DEPLOYMENT_ID=partner-lab \
TRSTCTL_LAB_RUN_JOURNEYS=0 deploy/demo/lab/run.sh
```

This adds `docker-compose.licensed.yml`: the control plane and signer are built
from the clean `release` image target (not the demo target and its self-minted
license), read the operator's license from the run-owned runtime volume, and
the provider plane pins the lab's local identity provider offline so a provider
operator can sign in at `/provider` with a token from
`http://127.0.0.1:19081/provider/sign-in`. Delegations are bootstrapped with
`trstctl provider-grant` inside the control-plane container (docs/editions.md).

For a local FIPS-capable image, add `TRSTCTL_LAB_GOFIPS140=v1.0.0` and
`TRSTCTL_LAB_FIPS_REQUIRED=1` to the licensed `run.sh` invocation. The first
selects the pinned Go module for both binaries in the image; the second makes
both the control plane and the separate signer refuse startup if their module
is inactive. `GET /api/v1/editions` reports the live control-plane POST result.
The product's own CMVP certificate and any external HSM validation remain
external evidence, as described in `docs/compliance.md`.

## Local SAML identity provider for Enterprise SSO

The optional `saml-idp` fixture is a real SAML HTTP-POST identity provider for
an owned, disposable lab identity. It signs assertions and serves metadata on
an explicit loopback listener. It authenticates its configured actor without a
password, so never expose it outside a lab or register a real operator. The
identity provider's signing key and certificate live in one owner-only PEM file.
Restarting the fixture reuses the same signing identity and pinned metadata.
Keep the file under the task's private directory; never copy it into reports or
container images. To rotate deliberately, stop the fixture, move the private
identity file into a secure task archive, and start it again to generate a new
one. Repin the generated public metadata, then restart the control plane and
signer together. A malformed, expired, or over-permissive identity file causes
startup to fail instead of silently changing the trust anchor.

From the repository root, set a private task directory and the exact tenant ID:

```sh
LAB_SAML_DIR=/secure/partner-lab/saml
install -d -m 700 "$LAB_SAML_DIR"
go build -o "$LAB_SAML_DIR/saml-idp" ./deploy/demo/lab/saml-idp
"$LAB_SAML_DIR/saml-idp" \
  -addr 127.0.0.1:18481 \
  -identity-file "$LAB_SAML_DIR/idp-identity.pem" \
  -metadata-file "$LAB_SAML_DIR/idp-metadata.xml" \
  -sp-metadata-file "$LAB_SAML_DIR/sp-metadata.xml" \
  -sp-entity-id https://127.0.0.1:9443/auth/saml/metadata \
  -subject saml-lab-operator@local.qa \
  -email saml-lab-operator@local.qa \
  -tenant YOUR_TASK_TENANT_ID
```

The process writes `idp-metadata.xml` mode `0600`. Mount that public metadata
read-only into the control plane. Enable `auth.saml` with the SP entity ID and
metadata URL above, ACS URL `https://127.0.0.1:9443/auth/saml/acs`, the mounted
`idp_metadata_file`, a persistent `session_secret_file`, and an exact
subject-to-tenant mapping. See [SAML configuration](../../../docs/configuration.md#browser-sso).
In a licensed stack, restart the signer and control plane together. Before
sign-in, fetch the SP's public metadata into the file the local IdP reads:

```sh
curl --fail --cacert /path/to/pinned-control-plane.crt \
  https://127.0.0.1:9443/auth/saml/metadata \
  --output "$LAB_SAML_DIR/sp-metadata.xml"
```

The browser's **Continue with SAML** action then uses the IdP's signed
assertion and returns to the requested local console page. Keep the IdP process
running for the replay; restart the control plane to test cold session recovery.
The fixture reads only the pinned SP metadata file and refuses any other SP
entity ID.

For a separate Provider-plane SAML login, run a second fixture on another
loopback port and pin `/provider/v1/auth/saml/metadata` as its exact SP entity.
Pass `-attribute groups=provider-admin -attribute amr=mfa` for signed role and
MFA claims matching `provider.saml.role_attribute` and
`provider.saml.mfa_attribute`. The fixture refuses duplicate or reserved
`email`/`tenant` claims. Keep its signing metadata, SP metadata, and persistent
Provider session secret separate from the tenant SAML files; the Provider plane
has its own browser session and must not inherit tenant-console access.

## Customer listener for the provider journey

The front doors also serve `customer-edge.acme-robotics.example.com` on
`127.0.0.1:10449`, a listener reserved for a provider customer's own agent. After
the provider has provisioned the customer tenant, mint an API token in that
tenant (`trstctl token create --tenant <customer tenant id> ...`, kept as a 0600
file) and enroll the customer agent:

```bash
TRSTCTL_LAB_PROJECT=your-running-lab \
TRSTCTL_LAB_CUSTOMER_TOKEN_FILE=/secure/acme-robotics.token \
deploy/demo/lab/enroll-customer.sh
```

Use the same project name as the original `run.sh` command; omitting it selects
`trstctl-partner-lab`. The launcher requires that project's control plane and
front doors to be running. It checks the token file's `0600` or `0400` permissions,
uses the project's already-built seed image, and runs only the enrollment helper.
It does not rebuild or restart services, so a licensed lab keeps its installed
image and license without resupplying the vendor key or licensed overlay. If you
overrode `TRSTCTL_DEMO_SEED_IMAGE` at startup, supply the same override here.
The API token stays in its read-only file mount, never a command argument or an
environment value.

The helper mints a one-time enrollment token inside the customer tenant and
stages it in the front-door state volume; the front-door entrypoint starts a
second `trstctl-agent` (identity `customer-edge-agent`, tenant = the customer)
whose host profile allows only `/lab/tls/customer-edge` and an NGINX reload. The
customer's lifecycle then runs as in the journeys: an NGINX destination with
`cert_path=/lab/tls/customer-edge/edge.crt` and `key_path=/lab/tls/customer-edge/edge.key`,
verified on the wire at `127.0.0.1:10449`.



- **Real local:** actual Apache, NGINX, HAProxy, Caddy, Traefik, and PostgreSQL binaries receive an independently issued certificate, validate or watch their configs, activate the update, and serve the new certificate. PostgreSQL is verified with its real SSLRequest-to-TLS negotiation, and network discovery inventories it the same way: the scanner retries a reachable listener that rejects a bare TLS ClientHello with the PostgreSQL SSLRequest negotiation, so the lab's six listeners discover without a protocol hint.
- **Faithful local:** the repository's production-assembly census drives every other shipped connector against a strict command or protocol receiver. This includes F5, NetScaler, A10, Kemp, Cisco, FortiGate, Palo Alto, cloud certificate stores, databases, and the exact IIS PowerShell/netsh contract.
- **External-only:** full IIS still needs Windows + IIS + HTTP.sys; current Windows CI proves CryptoAPI and MSI/service lifecycle but not a live IIS binding. Physical/vendor appliance qualification needs that appliance; vendor entitlement and public Internet trust need real third-party accounts and domains. Those are the only remaining external walls.

Evidence is retained in the `trstctl-partner-lab_labevidence` named volume. It contains public fingerprints, public Pebble root certificates, resource IDs, stage results, redacted failures, and sanitized alert metadata. It does not contain tokens, cookies, private keys, leaf certificate bodies, or alert credentials.

Set `TRSTCTL_LAB_PROJECT` to a constrained Compose project name when you need a clean before/after qualification while preserving an earlier run, for example `TRSTCTL_LAB_PROJECT=trstctl-partner-lab-repair deploy/demo/lab/run.sh`. The default remains `trstctl-partner-lab`.

## Drive it yourself (start only)

To perform the lifecycle by hand from the console instead of watching the
automated runner do it, start the lab without the journeys:

```sh
TRSTCTL_LAB_RUN_JOURNEYS=0 deploy/demo/lab/run.sh
```

This builds and starts every service, seeds the demo tenant, enrolls the
`partner-lab-frontdoors` agent (host and network-relay roles), registers the
tenant DNS-01 provider config (`Local Pebble DNS validation`, zone
`partner-lab.example.com`) that the lab's ACME CA needs for every issuance, and
configures operator-owned OpsGenie, PagerDuty, and email receivers. The two incident
credentials are generated once as mode `0600` files in the project runtime volume;
the local sink checks their exact values and records only sanitized alert metadata.
Mailpit stores email in its project volume; neither fixture forwards to the Internet.
Each listener stays on its self-signed one-day baseline. Nothing is issued or
deployed until you do it. The definition-of-done census is skipped in this mode;
run the default profile before calling a candidate qualified.

Then:

1. Trust the published console certificate in your evaluation browser
   ([Trust the local evaluation certificate](../../../docs/local-evaluation-tls.md))
   and sign in at <https://127.0.0.1:9443> with the demo SSO user.
2. In **Discover → Sources**, add a *TLS endpoints* source for a listener. The
   front doors share the control plane's network namespace, so target
   `127.0.0.1` with the listener port (for example `10443` for Apache) and turn
   on **Allow loopback targets** under *Advanced local-test boundary*. Reuse the
   `demo-control-plane` scope or declare a new one; the enrolled relay claims
   the run.
3. Claim the finding into a managed identity, create an owner with an alert
   contact, and add an enabled destination. Use the same shape the automated
   runner uses, for Apache:

   ```json
   {"executor":"agent","required_agent_role":"host",
    "cert_path":"/lab/tls/apache.crt","key_path":"/lab/tls/apache.key",
    "verify_address":"127.0.0.1:10443","verify_server_name":"apache.partner-lab.example.com"}
   ```

   `executor: agent` makes the enrolled host agent generate the private key,
   submit only a CSR to the CA, install the certificate, and re-handshake the
   listener; that is the custody path the lab proves. Then run the endpoint
   lifecycle wizard under **Operations → Where credentials are installed**,
   choosing **External CA: Local independent ACME lab CA (Pebble)**.
4. Prove the result yourself, exactly as the automated runner does:

   ```sh
   openssl s_client -connect 127.0.0.1:10443 -servername apache.partner-lab.example.com </dev/null 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256 -issuer -dates
   ```

The other listeners are `nginx.partner-lab.example.com:10444`,
`haproxy.partner-lab.example.com:10445`, `caddy.partner-lab.example.com:10446`,
`traefik.partner-lab.example.com:10447`, and PostgreSQL on `10448`.

## Stop without losing the lab

```sh
docker compose -p trstctl-partner-lab -f deploy/demo/docker-compose.yml -f deploy/demo/lab/docker-compose.yml --profile partner-lab stop
```

## Explicit full reset

The lab runner owns its teardown. `deploy/demo/lab/down.sh` removes exactly one
Compose project's containers, named volumes, and network — across every profile,
so the control plane is torn down too — and exits non-zero if anything of that
project survives (a profile-filtered `stop` is not a teardown: it leaves the
control plane holding 9443 and 10443-10449, which breaks the next bring-up):

```sh
deploy/demo/lab/down.sh                                  # trstctl-partner-lab
TRSTCTL_LAB_PROJECT=my-lab deploy/demo/lab/down.sh       # another project
```

The equivalent raw command, which deletes only the `trstctl-partner-lab` Compose project's containers and named volumes:

```sh
docker compose -p trstctl-partner-lab -f deploy/demo/docker-compose.yml -f deploy/demo/lab/docker-compose.yml --profile partner-lab down --volumes --remove-orphans
```

Use the reset only when you want a first-run certificate change again. Ordinary starts, stops, and repeated journey runs preserve state.
