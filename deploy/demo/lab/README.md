# Lightweight persistent partner lab

This opt-in overlay turns the normal seeded demo into a real local lifecycle lab. It keeps one independent ACME CA (Pebble), its DNS challenge server, one bounded alert receiver, and one nonroot edge host running real Apache, NGINX, HAProxy, Caddy, Traefik, and PostgreSQL processes. The same trstctl host collector updates all six services, so host-role jobs cannot race between unrelated collectors.

## Run every safe local journey

From the repository root:

```sh
deploy/demo/lab/run.sh
```

The script starts or resumes the lab, executes six real TLS lifecycle journeys, then runs the complete shipped production-assembly census and retains all 81 capability rows as evidence. It deliberately does **not** tear the lab down. Re-running it checks convergence against the retained state.

During repair, use the short live profile so a new candidate gets fast service
feedback without claiming that the full release gate ran:

```sh
TRSTCTL_LAB_PROJECT=trstctl-partner-lab-repair \
TRSTCTL_LAB_RUN_DOD=0 deploy/demo/lab/run.sh
```

The default `TRSTCTL_LAB_RUN_DOD=1` is the qualification profile. It follows
the live journeys with the full definition-of-done census and is mandatory
before a candidate is called qualified.

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

The browser will not recognize the target DNS names when you use the IP address. The automated probes connect to the published ports with the correct SNI names and verify the resulting chains against Pebble's pinned public test root.

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

Evidence is retained in the `trstctl-partner-lab_labevidence` named volume. It contains public fingerprints, resource IDs, stage results, redacted failures, and sanitized alert metadata. It does not contain tokens, cookies, private keys, certificate bodies, or alert credentials.

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
leaves each listener on its self-signed one-day baseline. Nothing is issued or
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
