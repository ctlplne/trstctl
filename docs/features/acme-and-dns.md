# ACME & DNS validation — automatic certificates, proven by DNS

## What it is

[ACME](../glossary.md) is the protocol that lets a machine get and renew
[certificates](../glossary.md) automatically, with no human in the loop. trstctl
speaks the **CA side** of ACME — the same protocol Let's Encrypt made famous — so any
standard ACME client (certbot, acme.sh, Caddy, cert-manager) can enroll against it.

The hard part of ACME is *proving control*: before signing a certificate for
`api.example.com`, the CA must check that you actually control that name. This page
covers the ACME server itself and the whole **DNS validation** toolkit trstctl uses
to prove control through DNS records — including the pieces that make DNS validation
safe and reliable at scale: a provider plugin framework, CNAME delegation, CAA
enforcement, automatic method selection, and wildcard support.

## Why it exists

A handful of certificates can be renewed by hand. A fleet of thousands cannot — someone
forgets, a certificate expires, and a service goes dark at 3 a.m. ACME removes the
human entirely: machines renew themselves on schedule.

DNS-based validation matters because the simpler method (serving a token over HTTP on
port 80) doesn't work for everything: it can't prove control of a **wildcard**
(`*.example.com`), and it needs an inbound port many hosts don't expose. Proving
control by publishing a DNS record works for wildcards, internal hosts, and anything
without a public web server — but doing it safely (without handing trstctl your
production DNS keys) needs the extra machinery below.

## How it works

### The ACME server (F5)

The ACME conversation is a fixed sequence. The client fetches a **directory** (a JSON
index of endpoints), registers an account key, places an **order** for a name, is given
a **challenge** to prove control, then **finalizes** by sending a [CSR](../glossary.md)
and downloading the signed certificate.

trstctl implements all of it (RFC 8555). Every mutating request is a signed JWS whose
signature is verified through the single isolated cryptography path; each order offers
three challenge types by default (`http-01`, `dns-01`, `tls-alpn-01`); finalize calls the one
[issuance path](issuance-and-cas.md) to mint the certificate. Account registration is
idempotent by key thumbprint, per the spec. **Served** endpoints start at
`GET /directory`; challenge and order endpoints live under `/acme/...`.

Operators can require ACME External Account Binding (EAB, CAP-ISS-04) for account registration.
When `protocols.acme_eab.required` is on, the directory advertises
`externalAccountRequired`, bare `newAccount` requests fail closed, and each supplied
binding is checked as an HS256 JWS over the account JWK using the configured `kid` and
HMAC key.

**A credential is an authorization, not just a door key.** The account remembers which
`kid` admitted it, and every order under that account is checked against that
credential's scope. A credential in `protocols.acme_eab.keys[]` may carry
`allowed_identifiers` (exact names, or `*.example.com`, which covers the apex and
anything beneath it), `max_orders`, an RFC 3339 `not_after`, and `disabled`. An order
for an identifier outside the scope is refused fail-closed, names the identifier and
the credential, and records an `acme.eab.order_denied` event; one out-of-scope
identifier refuses the whole order. A credential with none of those fields behaves
exactly as it did before.

The mechanism: `GET /api/v1/acme/eab-credentials` serves each credential's scope,
quota, window, and live accounts-bound / orders-created / orders-denied counters, and
`POST /api/v1/acme/eab-credentials/{kid}/disable` (or `/enable`) stops or resumes new
accounts and orders under one credential at runtime — the verb you want when a
credential leaks, because it takes effect immediately and leaves certificates already
issued under it valid. The Protocols console shows the same list with the same action.

The exact contract: the served response carries no HMAC key in any encoding, and there
is no API that mints one — **rotation is a configuration operation**: add the new key
id to `protocols.acme_eab.keys`, then disable the old one while clients migrate. The
served disable verb cannot re-enable a credential that configuration disables; config
is the floor. Binding a credential to a certificate profile is not available, because
the ACME server does not select profiles.

The default ACME profile mode is full public-trust domain validation. For internal PKI,
a profile can explicitly set `trust_authenticated`: an already-authenticated internal
ACME account can move an order straight to ready without a DV challenge, while
unauthenticated orders still fail closed. trstctl also applies an account-keyed
order/hour limiter plus a concurrent-order cap, so many clients behind one NAT do not
share a single coarse source-IP budget and one noisy account cannot starve the ACME lane.

An explicitly configured, default-off certificate profile may also offer TPM
`device-attest-01` as a fourth alternative. The running ACME server loads the
active profile through the tenant-scoped PostgreSQL/RLS store, checks the
operator trust roots, identifier allowlist, allowed COSE algorithms, freshness,
and TPM/WebAuthn proof, then records the attested public-key digest in its
event-sourced order state. The proof binds tenant, account, order, challenge,
token, nonce, identifier, CSR key, and timestamp; replay, cross-order,
cross-tenant, stale, untrusted-root, and CSR-key substitutions fail closed.
Finalization must use the same attested key. The parser is the reviewed
BSD-3-Clause `go-webauthn` implementation routed through `internal/crypto`;
trstctl does not hand-roll ASN.1, CBOR, COSE, TPM, or X.509 parsers. Operator
roots are local inputs: there is no manufacturer metadata fetch and no other
phone-home call. The three existing DV methods remain unchanged and available.

### Proving control without a web server: DNS-01 (F69)

In the DNS-01 challenge, the CA says "publish this exact value as a TXT record at
`_acme-challenge.<your-domain>`," then looks it up to confirm. trstctl automates both
sides: the **solver** publishes the record through a DNS provider, optionally waits for
it to propagate, and hands back a cleanup function; the **validator** looks it up and
checks it equals `base64url(SHA-256(keyAuthorization))` — a value computed inside the
single isolated cryptography path, so the publish side and verify side can never drift.

Two reliability features matter in practice. A **propagation checker** polls every
configured resolver until they all see the record (or a budget expires), because DNS is
eventually-consistent and a too-early check fails spuriously. And a **preflight** can
publish a throwaway probe at onboarding to prove the whole DNS-01 path works — so a
broken provider credential surfaces during setup, not during a 3 a.m. renewal. The
validator **fails closed**: a lookup error, missing record, or mismatch is a failure,
never a pass.

The served control plane has a tenant-scoped DNS-01 provider-config API:
`POST/GET/PUT/DELETE /api/v1/acme/dns-01/provider-configs` stores provider metadata,
zone/delegation policy, CAA issuer policy, allowed methods, wildcard policy, and
`credential_refs` only. Inline provider tokens are rejected.
`POST /api/v1/acme/dns-01/preflight` evaluates CNAME delegation, TXT propagation,
live CAA, method policy, and wildcard policy against one of those configs and records an
`acme.dns01.preflighted` event. The matching CLI commands are
`trstctl acme dns-01 provider-configs ...` and `trstctl acme dns-01 preflight`.

On an actual served ACME DNS-01 order, accepting the `dns-01` challenge resolves the
tenant's matching provider config, enqueues `acme.dns01.present` and
`acme.dns01.cleanup` outbox rows, waits for the published TXT record before
validation, and records `acme.dns01.record.presented` /
`acme.dns01.record.cleaned` metadata events. Provider credentials are resolved from
secret references inside the outbox worker; TXT values and credential refs are not
written to the audit events. When the provider config sets `caa_issuer_domain`, the
served DNS-01 path checks authoritative live CAA before enqueueing provider writes and
fails closed if the governing CAA set denies that issuer or cannot be read. When the
provider config sets `delegation_target`, the outbox worker verifies the live
`_acme-challenge` CNAME against that configured target and publishes/cleans up the TXT
only at the delegated validation name.

### Any DNS provider: the plugin framework (F70)

Every DNS host has a different API, so trstctl defines one tiny interface a provider
must satisfy — `PresentTXT(name, value)` and `CleanupTXT(name, value)`, both required
to be idempotent — and ships providers for Route 53, Cloudflare, Google Cloud DNS,
Azure DNS, RFC 2136 dynamic DNS, generic DNS webhooks, NS1, Akamai, UltraDNS, and
acme-dns. A served catalog at `GET /api/v1/acme/dns-01/providers` lists the running
binary's provider coverage, conformance posture, admission state, provenance,
least-privilege capability grant, provider package, and secret-reference fields
without returning raw provider tokens. A conformance harness (`ConformDNSProvider`)
proves a provider is correct before it's used: it presents, validates, cleans up,
and confirms validation then fails.

Operators can also place signed WASM DNS provider modules in `plugins.dns_dir`.
The control plane admits them only after detached Ed25519 provenance verification
and DNS contract checks for `run()`, `present_txt()`, and `cleanup_txt()`. Admitted
plugins appear in the same provider catalog with `kind=plugin`, can be selected by
tenant DNS-01 provider configs, and are activated by the ACME DNS-01 outbox worker
during order-time publish and cleanup. If a plugin is unsigned, signed by an
untrusted key, tampered, or missing the DNS entrypoints, startup fails closed before
the provider is exposed.

Each provider asks only for the narrow capability it needs (network dial to its zone
API host, the least-privilege pattern from the [plugin SDK](extensibility-plugins.md)),
its credentials are held in wipeable memory and never logged, and where a provider needs
cryptography (e.g. Route 53's request signing) it routes through the single isolated
cryptography path rather than touching the low-level crypto libraries directly.

### Keeping production DNS untouched: CNAME delegation (F71)

Handing a certificate tool write access to your production DNS zone makes security teams
nervous — and rightly. **CNAME delegation** removes that risk: you add a *one-time*
CNAME record pointing `_acme-challenge.example.com` at a throwaway validation zone, and
trstctl only ever writes in *that* zone. It never holds production DNS credentials.

trstctl's `DelegatingProvider` wraps any base provider and follows the CNAME before
publishing; if the name isn't actually delegated it **fails closed** rather than
silently writing to production. A `VerifyDelegation` preflight confirms the CNAME points
where it should before you rely on it. The served ACME order-time path applies the same
fail-closed check from the DNS-01 outbox worker, so a missing or mismatched CNAME stops
issuance before any production-zone TXT write can happen. This is the well-known
acme-dns pattern, and trstctl's acme-dns provider is the typical validation-zone backend.

### Who's allowed to issue: CAA (F72)

A **CAA record** (Certification Authority Authorization, RFC 8659) is a DNS record where
a domain owner names which CAs are permitted to issue for the domain — a way to say "only
*this* CA may issue for me." trstctl checks CAA *before* issuing: it walks the DNS tree
from the full name up toward the apex, finds the governing CAA record set, and refuses
if that set doesn't authorize trstctl's issuer. Wildcard requests honor `issuewild`
records with the right precedence, an empty issuer value (`;`) forbids all issuance, and
a lookup error **fails closed**. The served preflight route and the order-time DNS-01
automation both use authoritative live DNS rather than caller-supplied CAA records; an
order-time denial stops before any `acme.dns01.present` outbox row or DNS provider write.
The check runs before the CA is asked to sign, so a CAA violation surfaces with a clear
reason instead of a confusing downstream rejection. RFC 8659.

### Picking the right challenge: multi-method policy (F73)

Rather than make you choose a challenge type per name, trstctl can select one
automatically. `SelectMethod` follows a clear decision tree: an explicit profile
override wins; wildcards must use DNS-01; if port 80 is unreachable it uses DNS-01 (or
TLS-ALPN-01 when DNS isn't managed); otherwise it defaults to HTTP-01. It returns a
human-readable *rationale* string that is recorded in the tamper-evident audit trail, and
it **never silently degrades**. The dispatcher that runs the chosen validator fails closed
on any unknown or unconfigured method — there is no accept-everything path.

Tenant DNS-01 provider configs also carry an `allowed_methods` policy for each managed
zone. Operators manage that policy through the served provider-config API, CLI, and
Protocols page. The preflight route previews the selected method and denial reason, and
the served ACME order path enforces the same policy before validation: new orders only
advertise challenge types allowed by the matching config, and challenge acceptance
re-checks the policy so stale or updated orders cannot use a method that is no longer
allowed.

### Wildcards (F74)

A wildcard certificate (`*.example.com`) covers every subdomain at once. By rule it can
*only* be validated with DNS-01 (you can't prove control of `*.example.com` by serving a
file). trstctl enforces exactly that: wildcards are refused unless the profile
explicitly opts in (`AllowWildcards`, default off) and refused with any method other than
DNS-01. Because the DNS-01 record name strips the `*.` prefix, a wildcard validates at
the *same* `_acme-challenge.example.com` record as the bare domain — so the same solver,
propagation checker, CNAME delegation, and cleanup handle wildcards and ordinary names
identically once the opt-in check passes. RFC 8555 §7.1.1, §8.4.

For served X.509 identity issuance, `POST /api/v1/identities` fails closed for wildcard
names until the request carries both `wildcard_blast_radius_acknowledged=true` and
`validation_method=dns-01` in `attributes`; the Identities page exposes that
acknowledgement before it sends the issue request. Once the wildcard identity is deployed,
the lifecycle scheduler treats it like any other deployed X.509 identity: it queues
`ca.renew`, mints a successor with the same wildcard SAN, and records
`lifecycle.rotation.recorded` evidence for renewal history.

## Use it

Point any ACME client at trstctl's directory. With certbot, using DNS-01:

```sh
certbot certonly \
  --server https://trstctl.example.com/directory \
  --preferred-challenges dns \
  -d 'example.com' -d '*.example.com'
```

On success certbot reports `Successfully received certificate` and trstctl records the
matching issuance event. For the recommended production setup, add the one-time CNAME so
trstctl validates in an isolated zone:

```text
_acme-challenge.example.com.  CNAME  <random-subdomain>.auth.acme-dns.example.net.
```

### Inspect ARI publication and scheduler consumption

The RFC 9773 endpoint `GET /acme/renewal-info/{certid}` is public protocol data for
an ACME client. Operators use the separate, authenticated
`GET /api/v1/acme/ari/posture` route, `trstctl-cli acme ari posture`, or the
**ARI posture** panel on **Protocols**. This read-only surface requires
`lifecycle:read`; PostgreSQL RLS constrains the certificate and lifecycle evidence
to the caller's tenant.

The response separates three facts that are easy to confuse:

- `publication_status` says whether ACME renewal information is actually served for
  this tenant;
- each affected certificate reports its `suggested_window` and its own publication
  state; and
- `scheduler_status`, `scheduler_consumed`, and `rotation_run_id` show whether the
  lifecycle scheduler used that window and how its durable rotation run ended.

No posture read changes renewal behavior or ACME challenge validation. A tenant
without a mounted ACME publisher receives the honest `not_served` state, and a
tenant cannot read another tenant's certificate identifiers or rotation evidence.

## Pitfalls & limits

- **DNS-01 needs a provider credential** scoped to the (validation) zone; prefer CNAME
  delegation so trstctl never holds production DNS keys.
- **Propagation takes time.** Use the propagation checker and the preflight so renewals
  don't fail on a too-early lookup.
- **Wildcards require DNS-01, profile/provider opt-in, and blast-radius acknowledgement**
  — this is deliberate, not a bug.
- **CAA fails closed** on lookup errors: if your DNS is unreachable, issuance is
  refused rather than risked.
- **`trust_authenticated` is not public issuance.** Use it only for internal profiles
  where the ACME account is already authenticated through trstctl's platform controls.

## Reference

- **ACME endpoints:** `GET /directory`; `POST /acme/new-account`,
  `/acme/new-order`, `/acme/order/{id}/finalize`, `/acme/cert/{id}`;
  `GET /acme/renewal-info/{certid}` (ARI).
- **Operator ARI posture:** authenticated `GET /api/v1/acme/ari/posture`
  (`lifecycle:read`), also exposed as `trstctl-cli acme ari posture` and the
  Protocols console's ARI posture panel.
- **Challenge types:** `http-01`, `dns-01`, `tls-alpn-01`.
- **Auth modes:** `public_trust` (full DV, default) and `trust_authenticated`
  (internal authenticated issuance, explicit profile opt-in).
- **External Account Binding:** optional or required EAB on `newAccount`, backed by
  configured `kid` + byte-backed HS256 HMAC keys.
- **Quota:** account-keyed order/hour limiter and concurrent-order cap.
- **DNS providers:** Route 53, Cloudflare, Google Cloud DNS, Azure DNS, RFC 2136,
  webhook, NS1, Akamai, UltraDNS, acme-dns; cataloged at
  `GET /api/v1/acme/dns-01/providers`.
- **DNS-01 provider config:** `POST/GET/PUT/DELETE
  /api/v1/acme/dns-01/provider-configs`; `POST /api/v1/acme/dns-01/preflight`.
- **Order-time DNS-01 automation:** `POST /acme/chal/{id}` for a served `dns-01`
  challenge publishes, validates, and cleans through `acme.dns01.*` outbox rows.
- **Key functions:** `SelectMethod` (method choice), `ConformDNSProvider` (provider
  conformance), `VerifyDelegation` / `PreflightDNS01` (onboarding checks).
- **RFCs:** 8555 (ACME), 8659 (CAA), 9773 (ARI).

## See also

[Issuance & certificate authorities](issuance-and-cas.md) (what happens after
validation) · [Enrollment protocols](enrollment-protocols.md) (non-ACME enrollment) ·
[Lifecycle & PQC](lifecycle-and-pqc.md) (renewal automation) ·
glossary: [ACME](../glossary.md), [certificate](../glossary.md), [CSR](../glossary.md),
[CA](../glossary.md)

**Covers:** F5, F69, F70, F71, F72, F73, F74
