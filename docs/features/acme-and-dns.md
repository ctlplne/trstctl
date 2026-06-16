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
signature is verified through the crypto boundary `internal/crypto/jose` (**AN-3**); each
order offers three challenge types (`http-01`, `dns-01`, `tls-alpn-01`); finalize calls
the one [issuance path](issuance-and-cas.md) to mint the certificate. Account
registration is idempotent by key thumbprint, per the spec.

*Code:* `internal/protocols/acme` (`Server`, challenge handlers),
`internal/crypto/jose`. The directory is served at `GET /directory`; challenge and
order endpoints live under `/acme/...`. **Honest status:** the server is a complete,
working `http.Handler` with real challenge validators; mounting it on the public
control-plane endpoint and moving its in-memory order/ARI state onto the event log are
the documented integration steps ([limitations](../limitations.md)).

### Proving control without a web server: DNS-01 (F69)

In the DNS-01 challenge, the CA says "publish this exact value as a TXT record at
`_acme-challenge.<your-domain>`," then looks it up to confirm. trstctl automates both
sides: the **solver** publishes the record through a DNS provider, optionally waits for
it to propagate, and hands back a cleanup function; the **validator** looks it up and
checks it equals `base64url(SHA-256(keyAuthorization))` — a value computed inside the
crypto boundary (**AN-3**), so the publish side and verify side can never drift.

Two reliability features matter in practice. A **propagation checker** polls every
configured resolver until they all see the record (or a budget expires), because DNS is
eventually-consistent and a too-early check fails spuriously. And a **preflight** can
publish a throwaway probe at onboarding to prove the whole DNS-01 path works — so a
broken provider credential surfaces during setup, not during a 3 a.m. renewal. The
validator **fails closed**: a lookup error, missing record, or mismatch is a failure,
never a pass.

*Code:* `internal/protocols/acme/dns01.go`, `solver.go`, `dns01_reliability.go`.

### Any DNS provider: the plugin framework (F70)

Every DNS host has a different API, so trstctl defines one tiny interface a provider
must satisfy — `PresentTXT(name, value)` and `CleanupTXT(name, value)`, both required
to be idempotent — and ships providers for Route 53, Cloudflare, Google Cloud DNS,
Azure DNS, NS1, Akamai, UltraDNS, and acme-dns. A conformance harness
(`ConformDNSProvider`) proves a provider is correct before it's used: it presents,
validates, cleans up, and confirms validation then fails.

Each provider asks only for the narrow capability it needs (network dial to its zone
API host, the least-privilege pattern from the [plugin SDK](extensibility-plugins.md)),
its credentials are opaque and never logged (**AN-8**), and where a provider needs
crypto (e.g. Route 53's request signing) it uses `internal/crypto` rather than
importing `crypto/*` (**AN-3**).

*Code:* `internal/protocols/acme/solver.go` (`DNSProvider`, `ConformDNSProvider`),
`internal/dns/{route53,cloudflare,googledns,azuredns,ns1,akamai,ultradns,acmedns}`.

### Keeping production DNS untouched: CNAME delegation (F71)

Handing a certificate tool write access to your production DNS zone makes security teams
nervous — and rightly. **CNAME delegation** removes that risk: you add a *one-time*
CNAME record pointing `_acme-challenge.example.com` at a throwaway validation zone, and
trstctl only ever writes in *that* zone. It never holds production DNS credentials.

trstctl's `DelegatingProvider` wraps any base provider and follows the CNAME before
publishing; if the name isn't actually delegated it **fails closed** rather than
silently writing to production. A `VerifyDelegation` preflight confirms the CNAME points
where it should before you rely on it. This is the well-known acme-dns pattern, and
trstctl's acme-dns provider is the typical validation-zone backend.

*Code:* `internal/protocols/acme/dns01_delegation.go` (`DelegatingProvider`,
`VerifyDelegation`).

### Who's allowed to issue: CAA (F72)

A **CAA record** (Certification Authority Authorization, RFC 8659) is a DNS record where
a domain owner names which CAs are permitted to issue for the domain — a way to say "only
*this* CA may issue for me." trstctl checks CAA *before* issuing: it walks the DNS tree
from the full name up toward the apex, finds the governing CAA record set, and refuses
if that set doesn't authorize trstctl's issuer. Wildcard requests honor `issuewild`
records with the right precedence, an empty issuer value (`;`) forbids all issuance, and
a lookup error **fails closed**. The check runs before the CA is asked to sign, so a CAA
violation surfaces with a clear reason instead of a confusing downstream rejection.

*Code:* `internal/protocols/acme/caa.go` (`CAAChecker`). RFC 8659.

### Picking the right challenge: multi-method policy (F73)

Rather than make you choose a challenge type per name, trstctl can select one
automatically. `SelectMethod` follows a clear decision tree: an explicit profile
override wins; wildcards must use DNS-01; if port 80 is unreachable it uses DNS-01 (or
TLS-ALPN-01 when DNS isn't managed); otherwise it defaults to HTTP-01. It returns a
human-readable *rationale* string for the audit trail (**AN-2**) and **never silently
degrades**. The dispatcher that runs the chosen validator fails closed on any unknown or
unconfigured method — there is no accept-everything path.

*Code:* `internal/protocols/acme/dvmethod.go` (`SelectMethod`, `Validators`,
`DefaultValidators`).

### Wildcards (F74)

A wildcard certificate (`*.example.com`) covers every subdomain at once. By rule it can
*only* be validated with DNS-01 (you can't prove control of `*.example.com` by serving a
file). trstctl enforces exactly that: wildcards are refused unless the profile
explicitly opts in (`AllowWildcards`, default off) and refused with any method other than
DNS-01. Because the DNS-01 record name strips the `*.` prefix, a wildcard validates at
the *same* `_acme-challenge.example.com` record as the bare domain — so the same solver,
propagation checker, CNAME delegation, and cleanup handle wildcards and ordinary names
identically once the opt-in check passes.

*Code:* `internal/protocols/acme/wildcard.go` (`IsWildcard`, `WildcardPolicy`). RFC 8555
§7.1.1, §8.4.

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

## Pitfalls & limits

- **DNS-01 needs a provider credential** scoped to the (validation) zone; prefer CNAME
  delegation so trstctl never holds production DNS keys.
- **Propagation takes time.** Use the propagation checker and the preflight so renewals
  don't fail on a too-early lookup.
- **Wildcards require DNS-01 and a profile opt-in** — this is deliberate, not a bug.
- **CAA fails closed** on lookup errors: if your DNS is unreachable, issuance is
  refused rather than risked.
- **Serving status:** the ACME server and validators are implemented and tested;
  mounting on the public endpoint and durable order/ARI state are integration steps —
  see [Current limitations](../limitations.md).

## Reference

- **ACME endpoints:** `GET /directory`; `POST /acme/new-account`,
  `/acme/new-order`, `/acme/order/{id}/finalize`, `/acme/cert/{id}`;
  `GET /acme/renewal-info/{certid}` (ARI).
- **Challenge types:** `http-01`, `dns-01`, `tls-alpn-01`.
- **DNS providers:** Route 53, Cloudflare, Google Cloud DNS, Azure DNS, NS1, Akamai,
  UltraDNS, acme-dns.
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
