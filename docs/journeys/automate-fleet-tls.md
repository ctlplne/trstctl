# Automate TLS across your fleet with ACME

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `connector.registry`, `connector_right_size.dispatch`, `protocol_ergonomics.eval_profile`.
    Core surfaces guarded by route and journey tests: `acme_protocol`, `lifecycle_endpoint_bindings`, `certificate_renewal`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

Enroll an ACME client, install its certificate on a real service, verify what the
service serves, and keep it renewing without an operator. Finish by revoking and
retiring the certificate and its unused account. This example uses Certbot, an
RFC2136 DNS server such as BIND, and NGINX on Linux; adapt the installer and scheduler
to your actual target.

The client keeps its account key, leaf key, DNS credentials, and renewal settings.
trstctl validates domain control, issues the leaf, records protocol activity, and
serves renewal information and revocation. `certonly` saves files; the client host
still needs installation and scheduling.

## Before you start

- A reachable trstctl deployment from [Getting started](../getting-started.md), with
  ACME enabled for the intended tenant and a provisioned platform issuer.
- Certbot and its official `certbot-dns-rfc2136` plugin installed in the **same
  environment**, following the [plugin installation instructions](https://certbot-dns-rfc2136.readthedocs.io/en/stable/).
  Run `certbot plugins` and confirm `dns-rfc2136` appears. For another DNS service,
  install its matching authenticator and use that plugin's configuration.
- DNS authority for the requested name. Give the TSIG key permission to update only
  its `_acme-challenge` TXT records. The CA's resolver must see those records.
- Independently trusted HTTPS for the directory, and the expected issuing trust
  bundle for the resulting leaf. For private HTTPS, configure Certbot's trust
  bundle with `REQUESTS_CA_BUNDLE` and use the same setting in its scheduled task.
  Do not disable certificate verification. Directory HTTPS trust and leaf-issuer
  trust may be different bundles.
- If the directory requires EAB, obtain the configured key ID and HMAC credential
  through the approved secret channel and supply them during account registration.
  Keep the credential out of shell history and shared command examples.

The served ACME path currently uses the platform issuer; it does not select a
configured external CA or an EAB-specific certificate profile. If you need to keep
an external CA, use the separate
[existing-CA and connector journey](preserve-existing-ca.md). Do not assume an ACME
order changes issuer because another CA exists in inventory.

To bind a certificate profile, set `ca.default_profile` in the control plane's
configuration file to an active profile name for the ACME tenant. Its
`allowed_protocols` must include `acme`. The served adapter starts with a 30-day
default; the profile's `max_validity` caps the full signed certificate interval,
including its NotBefore backdate. With the default five-minute backdate, a
ten-minute profile leaves at most five minutes after issuance. A maximum that
leaves no usable time fails before signing and appears as an ACME readiness
blocker. Allow time for deployment and automatic renewal when choosing the ceiling.
If finalization reaches that refusal, the Protocols console records an issuance
diagnostic with cause `validity_not_permitted`, the exact order reference, and
profile/backdate guidance. Correct the active profile within your policy and retry
enrollment. Older unknown diagnostics remain unchanged because their retained
events do not contain enough evidence to assign this cause retrospectively.
The normal enrollment command below uses the bound profile; the client need not
request 30 days.
Key, name, usage, and protocol restrictions still apply before signing. A missing
bound profile rejects issuance. Check the returned certificate's actual dates and
renewal window before enabling its scheduler.

## 1. Inspect the ACME surface

Open **How machines request credentials** and read **ACME readiness and next step**.
Check the directory, tenant binding, issuing policy, offered challenge methods, and
account admission. In a configured deployment, the ACME toggle is:

```yaml
protocols:
  acme:
    enabled: true
    tenant_id: "11111111-1111-4111-8111-111111111111"
```

Use your own tenant ID. The directory is `/directory`; account and order resources
are under `/acme/...`. The evaluation profile can offer an activation action in the
console. Production activation is managed by startup configuration.

## 2. Configure DNS proof

Create `/etc/letsencrypt/rfc2136.ini` on the client host, owned by the account that
runs Certbot and readable only by that account (`chmod 600`). Replace these
placeholders with the DNS server address and the scoped TSIG credential:

```ini
dns_rfc2136_server = 192.0.2.53
dns_rfc2136_port = 53
dns_rfc2136_name = acme-client.
dns_rfc2136_secret = <base64-TSIG-secret>
dns_rfc2136_algorithm = HMAC-SHA512
```

Certbot's DNS plugin publishes and removes the TXT proof. A server-side DNS
provider configuration is not required when the client publishes proof for a zone
that trstctl does not manage. Matching managed-zone policy still applies; trstctl
must not silently bypass its CAA, method, or upstream-consent checks.

CNAME delegation is optional. Confirm that **both** the CA validator and your
chosen client plugin support the intended delegated update path before relying on
it. Server-side CNAME support does not make an arbitrary client follow delegation.
See [ACME and DNS validation](../features/acme-and-dns.md) for provider qualification.

## 3. Enroll the client

Replace the directory and domain. The exact Certbot authenticator is essential;
`--preferred-challenges dns` alone does not publish proof.

```sh
certbot certonly \
  --server https://trstctl.example.com/directory \
  --dns-rfc2136 --dns-rfc2136-credentials /etc/letsencrypt/rfc2136.ini \
  --preferred-challenges dns --cert-name api.example.com \
  -d api.example.com
```

Complete account/contact admission as prompted. For a wildcard, add the required
DNS names only after checking wildcard policy and DNS-plugin support. The client
chooses among the methods offered by the server; the server does not install a
client authenticator for you.

Confirm Certbot reports success, the challenge TXT record is removed, and
**Recent domain validation** shows the method actually validated. The client files
are under `/etc/letsencrypt/live/api.example.com/`. Inspect `cert.pem` for the exact
subject, SANs, issuer, serial, fingerprint, and validity period. An imported or
protocol-issued inventory row without an owner is not ownership attestation.

## 4. Install and verify the certificate

In the intended NGINX TLS server block, point to this client's live files:

```nginx
ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
```

Keep private-key permissions restricted to the actual service account. Certbot's
live paths are symlinks; do not copy dangling symlinks to another host or container.
Test the configuration as the service will run it, then reload:

```sh
sudo nginx -t && sudo systemctl reload nginx
```

Use a stock client with the independently acquired issuing trust bundle. Verify
the hostname, chain, and exact served leaf; also make an application request:

```sh
openssl s_client -connect api.example.com:443 -servername api.example.com \
  -verify_hostname api.example.com -CAfile issuing-trust.pem -verify_return_error </dev/null
curl --cacert issuing-trust.pem https://api.example.com/health
openssl s_client -connect api.example.com:443 -servername api.example.com \
  -verify_hostname api.example.com -CAfile issuing-trust.pem -verify_return_error \
  -showcerts </dev/null > endpoint-chain.pem
openssl x509 -in endpoint-chain.pem -noout -fingerprint -sha256
openssl x509 -in /etc/letsencrypt/live/api.example.com/cert.pem \
  -noout -serial -issuer -dates -fingerprint -sha256
```

The application request must return the expected result for your service. Compare
the served certificate's fingerprint with `cert.pem`; a reload acknowledgment
alone is insufficient.

Save an executable deploy hook at
`/etc/letsencrypt/renewal-hooks/deploy/30-trstctl-nginx`, owned by the renewal-task
account and not writable by other users. Set mode `0700`:

```sh
#!/bin/sh
set -eu
# Only this lineage belongs to this NGINX deployment.
[ "$RENEWED_LINEAGE" = /etc/letsencrypt/live/api.example.com ] || exit 0
nginx -t
systemctl reload nginx
```

Use absolute binary paths if your scheduler has a restricted PATH. Certbot runs a
deploy hook after successful renewal. For a remote target, implement the target's
authorized delivery, permission, configuration-test, and readback steps; a local
NGINX hook does not prove delivery to an appliance.

## 5. Schedule renewal and prove recovery

Check whether the Certbot installation already provides a renewal timer or cron
job. Keep one scheduler for this client state. If it provides `certbot.timer`,
inspect its service command, trust settings, and hook environment, then enable it:

```sh
systemctl cat certbot.service certbot.timer
sudo systemctl enable --now certbot.timer
systemctl list-timers --all certbot.timer
```

If no scheduler is installed, create a task on the client host that runs the exact
Certbot binary from that installation twice daily with a randomized delay:

```sh
certbot renew --cert-name api.example.com --server https://trstctl.example.com/directory
```

For systemd, create `/etc/systemd/system/trstctl-acme-renew.service` with the
following content. Replace `/usr/bin/certbot` with `command -v certbot` from the
environment where the DNS plugin is installed, and replace the domain/directory.
For private directory HTTPS, add an `Environment=REQUESTS_CA_BUNDLE=...` line under
`[Service]` pointing to the same trusted bundle used during enrollment.

```ini
[Unit]
Description=Renew the trstctl ACME client certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --cert-name api.example.com --server https://trstctl.example.com/directory
```

Create `/etc/systemd/system/trstctl-acme-renew.timer`:

```ini
[Unit]
Description=Check trstctl ACME renewal twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Validate and enable these two files only when another scheduler is not already
managing this client state:

```sh
sudo systemd-analyze verify /etc/systemd/system/trstctl-acme-renew.service /etc/systemd/system/trstctl-acme-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now trstctl-acme-renew.timer
systemctl list-timers --all trstctl-acme-renew.timer
journalctl -u trstctl-acme-renew.service
```

Run it as the account with access to the renewal state, DNS credential file, TLS
trust bundle, and deploy hook. Record the scheduler's next run and capture failures
in your monitoring. Do not leave this as a command an operator must remember.
[Certbot's renewal guide](https://eff-certbot.readthedocs.io/en/stable/using.html#automated-renewals)
explains the installation-specific scheduler options.

For a disposable test name, make one explicit smoke renewal using the same custom
server and `--force-renewal`. Inspect the hook result and independently read the
successor from the endpoint. This issues a real leaf; it is not an unattended test.
Do not assume `--dry-run` against a public staging CA proves your private directory.

Then observe **two naturally scheduled renewals**, including successful endpoint
activation and application requests. A timer firing early may correctly do nothing
because renewal is not due. ARI at `/acme/renewal-info/{certid}` supplies a suggested
window; it does not create a scheduler. Check actual validity and ARI dates rather
than assuming a requested short lifetime was honored.

In an isolated test, make the client's DNS update unavailable for one renewal
attempt. Confirm the failure is visible, the previous valid certificate continues
to serve the application, and no unsuccessful renewal triggers a deploy hook.
Restore DNS, let the scheduled task retry, and verify the exact successor and TXT
cleanup. Never inject this fault into unrelated production DNS.

## 6. Revoke and retire

For planned retirement, first remove the certificate from the service or replace
it and verify the replacement. Revoke the exact old leaf at the same directory:

```sh
certbot revoke --server https://trstctl.example.com/directory \
  --cert-path /etc/letsencrypt/live/api.example.com/cert.pem \
  --reason cessationofoperation --no-delete-after-revoke
```

For compromise, follow [Respond to compromise](respond-to-compromise.md), use the
appropriate reason, and replace the compromised key. Confirm the exact serial is
revoked in inventory and audit. Fetch the issuer's signed CRL or OCSP status and
verify it independently. For the platform issuer, the tenant CRL is served at
`/crl/<tenant-id>.crl`; trust its signature against the intended issuer, not merely
its download URL. A default browser handshake does not prove revocation enforcement.
Use a stock relying client configured to check revocation, and verify it rejects
the revoked leaf. Some leaves do not contain a CRL distribution-point URL, so the
client may need an explicitly supplied CRL.

For a platform-issued leaf, a local rejection check against the downloaded CRL is:

```sh
curl --fail --cacert directory-trust.pem \
  https://trstctl.example.com/crl/11111111-1111-4111-8111-111111111111.crl \
  -o issuer.crl.pem
openssl crl -in issuer.crl.pem -noout -verify -CAfile issuing-trust.pem
openssl verify -CAfile issuing-trust.pem -CRLfile issuer.crl.pem -crl_check \
  /etc/letsencrypt/live/api.example.com/cert.pem
```

Replace the tenant and trust files with the reviewed values. Require a valid CRL
signature and a current CRL. The final command should fail with
`certificate revoked` for the exact retired serial; an unrelated trust or expiry
error is not revocation proof. Separately verify that the live service presents
the intended replacement or that the retired listener is closed.

Remove service references before deleting Certbot's lineage:

```sh
certbot delete --server https://trstctl.example.com/directory --cert-name api.example.com
```

Revocation alone does not stop the client from renewing. Remove this lineage's
obsolete hook and dedicated scheduled task; preserve shared renewal tasks needed
by other lineages. Preserve audit evidence. When no remaining certificates need
this account, deactivate it:

```sh
certbot unregister --server https://trstctl.example.com/directory
```

Deactivation is permanent, cancels unfinished orders, and survives restart. Later
requests with that account key receive `401 unauthorized`. If a request is still
in flight, retry the `503` after it finishes. Deactivating an account does not
revoke its certificates or stop a service from presenting them.

## Alternative: let trstctl own issuance and deployment

An endpoint binding creates a new managed identity and queues its own issuance
and connector deployment from the explicitly selected CA. It does **not** install
the certificate/key that Certbot just created. Choose that ownership model through
[Preserve your existing CA](preserve-existing-ca.md) and review the exact target,
key custody, issuer, permissions, and deployment effects before execution.

A queued connector receipt has zero attempts and is intent evidence only. If no
native registry or signed plugin owns the connector, the worker records failure;
independent endpoint readback is still required. See
[Deployment connectors](../features/deployment-connectors.md).

## Where next

- [Give your Kubernetes workloads an identity](kubernetes-workload-identity.md)
- [Enroll devices and IoT fleets](enroll-devices.md)

**Journey:** J2
**Steps through:** F5, F69, F70, F71, F72, F73, F74, F6, F46, F7, F27
