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

## What is honest local evidence?

- **Real local:** actual Apache, NGINX, HAProxy, Caddy, Traefik, and PostgreSQL binaries receive an independently issued certificate, validate or watch their configs, activate the update, and serve the new certificate. PostgreSQL is verified with its real SSLRequest-to-TLS negotiation. Its raw-TLS network-discovery stage remains explicitly unclaimed until the scanner gains protocol-aware discovery.
- **Faithful local:** the repository's production-assembly census drives every other shipped connector against a strict command or protocol receiver. This includes F5, NetScaler, A10, Kemp, Cisco, FortiGate, Palo Alto, cloud certificate stores, databases, and the exact IIS PowerShell/netsh contract.
- **External-only:** full IIS still needs Windows + IIS + HTTP.sys; current Windows CI proves CryptoAPI and MSI/service lifecycle but not a live IIS binding. Physical/vendor appliance qualification needs that appliance; vendor entitlement and public Internet trust need real third-party accounts and domains. Those are the only remaining external walls.

Evidence is retained in the `trstctl-partner-lab_labevidence` named volume. It contains public fingerprints, resource IDs, stage results, redacted failures, and sanitized alert metadata. It does not contain tokens, cookies, private keys, certificate bodies, or alert credentials.

Set `TRSTCTL_LAB_PROJECT` to a constrained Compose project name when you need a clean before/after qualification while preserving an earlier run, for example `TRSTCTL_LAB_PROJECT=trstctl-partner-lab-repair deploy/demo/lab/run.sh`. The default remains `trstctl-partner-lab`.

## Stop without losing the lab

```sh
docker compose -p trstctl-partner-lab -f deploy/demo/docker-compose.yml -f deploy/demo/lab/docker-compose.yml --profile partner-lab stop
```

## Explicit full reset

This deletes only the `trstctl-partner-lab` Compose project's containers and named volumes:

```sh
docker compose -p trstctl-partner-lab -f deploy/demo/docker-compose.yml -f deploy/demo/lab/docker-compose.yml --profile partner-lab down --volumes --remove-orphans
```

Use the reset only when you want a first-run certificate change again. Ordinary starts, stops, and repeated journey runs preserve state.
