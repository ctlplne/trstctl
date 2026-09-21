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
signature is verified through the single isolated cryptography path. Before consuming
the one-use nonce, the common server wrapper also compares the protected `url`
byte-for-byte with the externally served request URL (scheme, authority, path, and
query), as RFC 8555 §6.4 requires. A routing intermediary therefore cannot move a valid
account signature to another ACME action. Each order offers three challenge types by
default (`http-01`, `dns-01`, `tls-alpn-01`); finalize calls the one [issuance
path](issuance-and-cas.md) to mint the certificate. Account registration is idempotent
by key thumbprint, per the spec. **Served** endpoints start at
`GET /directory`; challenge and order endpoints live under `/acme/...`.
The certificate URL returns `application/pem-certificate-chain` with the
signer-issued leaf first and the exact public issuing certificate second. The same
ordered bytes survive ACME state replay, so strict clients such as Certbot can build
their `cert.pem` and `fullchain.pem` artifacts after either issuance or restart.

Each new order has a durable issuance identity. A renewal order issues a new
certificate even when the client reuses its key and sends identical CSR bytes;
retrying the same order returns its original certificate. The identity survives
restart, including an interruption after signing but before the order completes.
Orders created by older versions without this identity retain their original
CSR-based retry binding during an upgrade, so recovery cannot duplicate a mint.
Create a fresh renewal order after upgrading to obtain the new behavior.

Newly issued ACME inventory records also retain `key_origin=requester`: the client
submitted the public key in its CSR, and this issuance did not receive the private
key. Its storage, exportability, and named generator remain unrecorded. This does
not assign an accountable owner or backfill old records with inferred custody.

The advertised account URL accepts signed POST-as-GET, contact updates, and
`{"status":"deactivated"}`. Registration lookup preserves existing contact details;
send an update to the account URL to change them, or `{"contact":[]}` to clear them.
The account's `orders` URL lists its non-invalid orders in pages of 100, with a
`Link: rel="next"` header when another page exists. These resources require the
owning account's signature.

Account deactivation is permanent and survives restart. It cancels unfinished
orders and authorizations; later requests signed by that account key return
`401 unauthorized`, including registration lookup. An operation already in flight
must finish first: deactivation returns `503` with `Retry-After: 1` while the account
is busy, without changing its status. Retry after that operation completes.
Deactivation does not revoke issued certificates or uninstall them from servers.
Revoke and replace or remove the affected leaves separately, remove obsolete client
renewal jobs/lineages, then deactivate the account with, for example,
`certbot unregister --server https://trstctl.example.com/directory`.
Account changes and canceled validation state rebuild from the tenant's
`acme.account.upserted` events; completed certificate evidence is preserved.

The **Protocols** page is the operator's starting point. Its **ACME readiness and
next step** panel asks the running server for one tenant-bound plan instead of trying
to guess readiness in the browser. That plan joins the mounted `/directory`,
activation gate, issuing profile, EAB admission state, and DNS-01 configuration. It
also names the one next step and the safe recovery steps. Loading the plan performs
no writes and contacts no external system.

Headless operators get the identical JSON plan with `trstctl acme readiness`. It is
an authenticated `GET`; it sends no body or idempotency key and performs no mutation.

In the evaluation profile, an operator with `issuers:write` can activate the already
assembled protocol gate from that panel. The mutation is event-sourced and
idempotent. Production activation remains startup-configuration managed: the console
will not silently expose a public enrollment endpoint. Once the plan says **Ready for
ACME clients**, copy its credential-free Certbot command, replace the DNS-name and
EAB placeholders, and run it from the machine that needs the certificate. Never put
an EAB HMAC key in screenshots, tickets, or shared QA evidence.

The same panel shows **Recent domain validation** from the running ACME server's
event-replayed state. Each row is a real authorization started by an ACME client. It
shows the domain, the challenge methods that tenant policy actually offered, the
method that proved control, and the current authorization/order state. It does not
return the ACME account URL, account key, challenge token, key authorization, or
certificate bytes. A pending row means the client still needs to answer one of the
offered challenges; a validated row is durable proof that the served validator
accepted that method. The same rows rebuild after restart from `acme.order.created`,
`acme.challenge.validated`, and `acme.certificate.issued` events.

If setup is blocked, repair each named prerequisite and reload the effect-free plan.
If a client begins an order but fails, open **Enrollment diagnostics** on the same
page; it shows the refused step and safe retry guidance. Retrying must not mean
weakening domain validation, tenant binding, EAB scope, or the issuing profile.

Operators can require ACME External Account Binding (EAB, CAP-ISS-04) for account registration.
When `protocols.acme_eab.required` is on, the directory advertises
`externalAccountRequired`, bare `newAccount` requests fail closed, and each supplied
binding is checked as an HS256 JWS over the account JWK using the configured `kid` and
HMAC key.

**A credential is an authorization, not a door key.** The account remembers which
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

The client can own DNS publication. Install and configure its DNS authenticator
(for example, Certbot's `dns-rfc2136` plugin); selecting `--preferred-challenges dns`
alone does not install or choose a plugin. When no tenant provider config covers
the requested zone, trstctl validates the client-published TXT through its normal
resolver without publishing or deleting records. Missing or incorrect proof is
refused. An existing managed-zone policy still applies; a provider failure does not
silently switch that zone to client-managed validation.

In the DNS-01 challenge, the CA says "publish this exact value as a TXT record at
`_acme-challenge.<your-domain>`," then looks it up to confirm. For a tenant-configured
managed zone, trstctl automates both sides: the **solver** publishes the record through a DNS provider, optionally waits for
it to propagate, and hands back a cleanup function; the **validator** looks it up and
checks it equals `base64url(SHA-256(keyAuthorization))` — a value computed inside the
single isolated cryptography path, so the publish side and verify side can never drift.

Two reliability features matter in practice. A **propagation checker** polls every
configured resolver until they all see the record (or a budget expires), because DNS is
eventually-consistent and a too-early check fails spuriously. The **preflight** checks
policy and currently observed DNS without publishing a TXT record; it does contact DNS
and records a sanitized audit event. The separate, effect-free **qualification review**
names what a test would change. The confirmed **provider qualification** then publishes
a server-generated throwaway probe during
onboarding, verifies it through the same resolver used by served ACME, and removes it.
That proves the real provider path before a 3 a.m. renewal. The validator **fails
closed**: a lookup error, missing record, or mismatch is a failure, never a pass.

The served control plane has a tenant-scoped DNS-01 provider-config API:
`POST/GET/PUT/DELETE /api/v1/acme/dns-01/provider-configs` stores provider metadata,
zone/delegation policy, CAA issuer policy, allowed methods, wildcard policy, and
`credential_refs` only. Inline provider tokens are rejected.
`POST /api/v1/acme/dns-01/preflight` evaluates CNAME delegation, TXT propagation,
live CAA, method policy, and wildcard policy against one of those configs and records an
`acme.dns01.preflighted` event. The matching CLI commands are
`trstctl acme dns-01 provider-configs ...` and `trstctl acme dns-01 preflight`.

The Protocols page also provides a review-before-run provider test:

1. **Review test** calls
   `POST /api/v1/acme/dns-01/provider-configs/{id}/qualification/preview`. It performs
   no write, generates no probe, calls no signer, and contacts no provider. It names
   the exact record, readiness checks, external effects, least-privilege checklist,
   and recovery plan.
2. **Publish, verify, and clean up** calls
   `POST /api/v1/acme/dns-01/provider-configs/{id}/qualification-runs`. The server
   creates the TXT probe, sends publish and cleanup through the production outbox and
   provider implementation, and verifies propagation through the served ACME
   resolver. Reusing the same idempotency key returns the original result rather than
   publishing twice.
3. **History** calls `GET` on that same `qualification-runs` path. The response is
   rebuilt from tenant-filtered outbox evidence and contains only the provider,
   domain, safe stage/status, timestamps, attempt count, and recovery instructions.
4. **Retry cleanup** calls
   `POST /api/v1/acme/dns-01/qualification-runs/{run_id}/retry-cleanup`. The server
   recovers the original cleanup request from tenant-scoped storage and never asks the
   browser or CLI to resend it.

Headless operators have identical commands:
`trstctl acme dns-01 provider-configs qualification preview <id> -f request.json`,
`... qualification run`, `... qualification history`, and
`trstctl acme dns-01 qualification retry-cleanup <run-id>`. The request file contains
only `{"domain":"example.com"}`. Qualification responses never return provider
tokens, secret-reference values, raw provider configuration, the TXT probe,
idempotency keys, raw outbox payloads, or raw worker errors. Cleanup uses an independent
bounded context, so a disconnected browser does not abandon the DNS record. If cleanup
still fails, the run stays visibly recoverable instead of being reported as green.

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

The console shows the exact running plugin package, Ed25519 provenance result, DNS
publish/cleanup contract result, startup-admission state, and least-privilege
capability grants beside both configuration and testing. A saved config whose plugin
is no longer admitted is shown as unavailable with recovery instructions; trstctl
does not silently substitute another provider. The same effect-free review, real TXT
qualification, sanitized history, and cleanup retry described above work for signed
plugins through the console and the `qualification preview`, `qualification run`,
`qualification history`, and `qualification retry-cleanup` CLI commands. Execution
still enters the production outbox worker, invokes the admitted plugin, publishes
through its configured endpoint, verifies DNS visibility, and cleans up the exact
probe.

The signed-plugin wrapper also appends `acme.dns01.plugin.presented` and
`acme.dns01.plugin.cleaned` to the tenant's tamper-evident audit stream. Denials and
delegate failures use the matching `.denied` / `.failed` event types with a closed
diagnostic code, never a raw provider error. Production's privacy-policy gate treats
the DNS record name as pseudonymizable subject data and rejects undeclared payload
fields. If the audit append itself fails, the outbox delivery fails visibly instead
of reporting an unaudited plugin effect as green.

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

In the Protocols console, **Test provider** turns that rule into an exact per-domain
journey. Its no-change review draws the production challenge name, the required CNAME,
and the isolated provider write target as three separate facts, then gives the one-time
DNS record to create. “Configured” is not shown as “proved”: only the real provider test
can turn the isolation state green, because that test resolves the live CNAME, refuses a
missing or mismatched target before the provider write, publishes a server-generated
probe in the validation zone, verifies DNS visibility, cleans the probe up, and preserves
the sanitized result. A failed run stays visibly unproved and gives the shortest safe
repair/retry path; it never asks the browser for a TXT value or provider credential.

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

The **Protocols → DNS-01 preflight** turns that gate into a complete operator workflow.
It reads authoritative DNS live and shows the DNS name that sets the rule, every public
CAA record in that governing set, the issuers parsed from the relevant `issue` or
`issuewild` properties, and the issuer configured in trstctl. It leads with one of five
plain-language results:

- **CAA policy is not configured:** set the provider config's CAA issuer domain, then
  run the check again.
- **No CAA record limits issuance:** issuance is allowed, but DNS is not restricting
  which CA may issue; the console provides an exact optional record to add that guardrail.
- **CAA allows this issuer:** the live governing policy already names this CA and no
  record change is required.
- **CAA blocks this issuer:** issuance stops; the console shows the current records, the
  allowed issuers, an exact record recommendation, and a safe publish/propagate/re-run path.
- **CAA could not be verified:** issuance stops without guessing. Repair authoritative
  DNS reachability, delegation, or the CAA response and re-run; the console deliberately
  does not invent a DNS record change when it has no trustworthy answer.

Wildcard preflights state that `issuewild` is being evaluated. Each result receives
keyboard focus after a run or re-run, so keyboard and screen-reader operators land on the
new decision rather than having to search the dialog. Exact DNS values remain visible as
monospaced technical evidence, while the decision and recovery stay in deeply technical
ELI5 language. The API carries the same structured evidence in `caa_policy`; CAA is public
DNS policy, and provider credentials or private key material never enter that response.

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
acknowledgment before it sends the issue request. Once the wildcard identity is deployed,
the lifecycle scheduler treats it like any other deployed X.509 identity: it queues
`ca.renew`, mints a successor with the same wildcard SAN, and records
`lifecycle.rotation.recorded` evidence for renewal history.

The **Machine identities** page keeps that journey together. Entering a wildcard name
opens a three-part safety explanation before the issue action: automatic ACME proof is
DNS-01-only, the zone's DNS provider policy must explicitly allow wildcards before ACME
use, and automatic renewal monitoring begins only after deployment. The operator must
acknowledge the larger blast radius. A successful operator issuance returns the exact
issued identity, opens its detail drawer, and makes **Deploy** the next valid action
instead of dropping the operator back into an undifferentiated list.

The operator-issued path and the ACME protocol path have different authorities. The
operator path records an authorized administrator's explicit blast-radius decision;
that acknowledgment is not a DNS ownership proof. A public ACME wildcard order still
must complete DNS-01, and its tenant provider policy is enforced by the ACME server.
The UI states this distinction so an acknowledgment cannot be mistaken for a
successful challenge.

After deployment, **Lifecycle automation** names wildcard items in the due-renewal
queue, opens the same effect-free transition review used by other credentials, and
queues `ca.renew` only after confirmation. **Delivery and rotation evidence** names the
identity beside each durable rotation receipt, so the operator can tie the successor
fingerprint and rollback reference to the exact wildcard. A failed issue keeps the form
open, shows the server's exact safe error, links to DNS-01 setup, and explicitly says not
to weaken validation before retrying.

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

The response separates three facts that operators often confuse:

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
- **Wildcards require DNS-01, profile/provider opt-in, and blast-radius acknowledgment**
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
