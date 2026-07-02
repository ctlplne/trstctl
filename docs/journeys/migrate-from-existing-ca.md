# Migrate from your existing CA

## Goal

You will move certificate issuance off your current authority and onto trstctl
without a flag day: first you find every certificate you already have, then you
stand up trstctl's own issuing authority and the rulebook that constrains it, then
you cut new issuance over to trstctl, and finally you watch the public logs for any
certificate minted for your domains that you did not request. The outcome is one
inventory, one issuing path, and an early-warning trip-wire — replacing scattered,
hand-tracked certificates. This is for a platform or security engineer who owns an
internal PKI and wants to consolidate it.

## Before you start

- A running control plane and an API token. Follow
  [Getting started](../getting-started.md) to bring up the stack and mint your first
  token with `trstctl token create`.
- The CLI configured against your server (`TRSTCTL_SERVER` and `TRSTCTL_TOKEN`), as
  shown in [Getting started](../getting-started.md).
- A network range or host list where your current certificates are served, so
  discovery has somewhere to look. See
  [Discovery & inventory](../features/discovery-and-inventory.md) for what a scan
  sees.

## Steps

1. Point the CLI at your control plane.

   ```sh
   export TRSTCTL_SERVER=https://localhost:8443
   export TRSTCTL_TOKEN=trst_...
   ```

   -> subsequent `trstctl-cli` calls authenticate as your tenant.

2. Tell trstctl where your existing certificates live, then queue a scan. A
   `network` source performs a normal TLS handshake and records the certificate each
   host presents — no software is installed on the targets. Details in
   [Discovery & inventory](../features/discovery-and-inventory.md).

   ```sh
   cat > source.json <<'JSON'
   {"kind":"network","name":"edge","config":{"targets":["10.0.0.10:443"]}}
   JSON
   trstctl-cli discovery sources create -f source.json

   cat > run.json <<'JSON'
   {"source_id":"<source-id>"}
   JSON
   trstctl-cli discovery runs start -f run.json
   ```

   -> the run is recorded, executes from the durable outbox, and discovered
   certificates land in inventory.

3. Confirm what was found. The scan writes each certificate as a `certificate.recorded`
   entry, projected into the inventory.

   ```sh
   trstctl-cli discovery findings list --run_id <run-id>
   trstctl-cli certificates list --limit 50
   ```

   -> you now have a precise, queryable list of the certificates you must replace.

4. Stand up the rulebook trstctl will enforce on every new certificate. A profile
   pins allowed algorithms, key sizes, usages, and maximum validity, so a migrated
   workload cannot accidentally re-mint a too-long or weak certificate. See
   [Issuance & certificate authorities](../features/issuance-and-cas.md).

   ```json
   {
     "name": "tls-server-90d",
     "spec": {
       "allowed_key_algorithms": ["ECDSA"],
       "min_ecdsa_bits": 256,
       "allowed_ekus": ["serverAuth"],
       "max_validity": "2160h"
     }
   }
   ```

   ```sh
   trstctl-cli profiles create -f tls-server-90d.json
   trstctl-cli profiles list
   ```

   -> the profile is versioned and active; old versions stay queryable so you always
   know which rules a past certificate was issued under.

5. Cut new issuance over to trstctl's signer-backed authority. Create an owner and an
   identity for a service, then transition it to `issued`; the certificate is minted
   through the issuing authority whose key stays in the separate signing service.

   ```sh
   owner=$(echo '{"kind":"workload","name":"payments"}' \
            | trstctl-cli owners create -f - | jq -r .id)
   ident=$(echo "{\"kind\":\"x509_certificate\",\"name\":\"payments.svc\",\"owner_id\":\"$owner\"}" \
            | trstctl-cli identities create -f - | jq -r .id)
   echo '{"to":"issued"}' | trstctl-cli identities transition "$ident" -f -
   sleep 2
   trstctl-cli certificates list
   ```

   -> the new certificate appears in inventory, issued under your bound profile. Repeat
   per workload, or drive issuance through an enrollment protocol — see
   [Issuance & certificate authorities](../features/issuance-and-cas.md).

6. Publish revocation pointers so relying parties can check status, then keep watch.
   Point your leaves' CDP/AIA URLs at the binary's `/crl/{tenant}` and
   `/ocsp/{tenant}` endpoints (configured via `ca.crl_distribution_points` /
   `ca.ocsp_servers`), and turn on Certificate Transparency monitoring so any
   certificate issued for your domains that you did *not* request raises an alert. See
   [Observability & risk](../features/observability-and-risk.md).

   -> a query for a revoked serial returns `revoked` over OCSP and the serial appears
   on the published CRL within its freshness window; CT monitoring flags mis-issuance
   you did not authorize through the served CT watchlist, checkpoint, finding, and
   outbox-backed alert path.

## Where next

- [onboard-a-team.md](onboard-a-team.md) — give each team its own isolated slice of
  the platform.
- [ssh-at-scale.md](ssh-at-scale.md) — bring SSH access under the same authority.

**Journey:** J5
**Steps through:** F1, F2, F4, F48, F53, F26, F47, F17
