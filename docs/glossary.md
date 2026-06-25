# Glossary

trstctl's docs assume you start knowing **nothing** about this subject. This page
defines every term of art the rest of the docs use, in plain language: what it is,
why it matters, and where it shows up. Skim it once, or jump back whenever a word
trips you up.

### Non-human identity (NHI)

Any actor on a network that is *not* a person: a server, a container, a script, a CI
job, an AI agent. Humans log in with passwords and MFA; non-human actors prove who
they are with credentials like certificates, keys, and tokens. trstctl exists to
manage those non-human credentials — there are now far more of them than there are
human accounts, and almost no one manages them well.

### Credential

A secret or signed token a non-human identity uses to prove who it is or to get
access: an X.509 certificate, an SSH key, an API key, a password, a token. The whole
job of trstctl is the *lifecycle* of credentials — finding them, issuing them,
deploying them, rotating them, and retiring them.

### Certificate (X.509)

A small digital "ID card" for a machine. **X.509** is the standard format. It binds a
name (like `api.example.com`) to a **public key**, and is signed by a **Certificate
Authority** so others can trust it. When your browser shows a padlock, it has checked
the site's X.509 certificate. Certificates expire on purpose, which is why managing
them at scale is hard enough to need a product.

### Public key / private key (key pair)

Two mathematically linked numbers. The **private key** is kept secret; the **public
key** can be shared freely. Anything signed by the private key can be verified with
the public key, and anything encrypted to the public key can only be opened by the
private key. The private key is the crown jewel — if it leaks, the identity is
compromised. trstctl keeps private keys inside one isolated process (see *signing
service*).

### Certificate Authority (CA)

The trusted issuer that signs certificates. Everyone agrees to trust a CA, so a
certificate the CA signed is trusted too. A **public CA** (like Let's Encrypt) is
trusted by browsers worldwide; a **private CA** is trusted only inside your company.
trstctl can run its own private CA and can also drive certificates out of external
CAs.

### CSR (Certificate Signing Request)

The form a machine sends to a CA to ask for a certificate. It contains the machine's
*public* key and the name it wants, signed by the matching private key (which never
leaves the machine). The CA checks it and signs back a certificate.

### Fingerprint

A short, fixed-length "ID number" for a certificate or key, produced by hashing it
(trstctl uses SHA-256). Two copies of the same certificate have the same fingerprint,
and any change produces a completely different one — so it's the perfect key for
de-duplicating an inventory and for referring to a specific credential without quoting
the whole thing.

### TLS / mTLS

**TLS** is the encryption that protects data in transit (the "S" in HTTPS). It uses
certificates so the client can verify the server. **mTLS** (mutual TLS) goes both
ways: the server also verifies the *client's* certificate. mTLS is how machines
authenticate each other without passwords.

### ACME

The **Automatic Certificate Management Environment** (RFC 8555): a protocol that lets
a machine get and renew certificates automatically, with no human involved. It is how
Let's Encrypt issues hundreds of millions of certificates. trstctl speaks the CA
side of ACME. See [ACME & DNS](features/acme-and-dns.md).

### EST / SCEP / CMP

Three enrollment protocols — fixed conversations a device uses to obtain a
certificate. **EST** (RFC 7030) is the modern one (used by routers, IoT). **SCEP**
(RFC 8894) is the older one still everywhere in network and mobile-device gear.
**CMP** (RFC 4210) is common in telecom and industrial systems. trstctl serves all
three so existing fleets can enroll without changing their clients. See
[Enrollment protocols](features/enrollment-protocols.md).

### SPIFFE / SVID

**SPIFFE** is an open standard for giving workloads (services, pods) a verifiable
identity without hard-coding secrets. The identity document it issues is an **SVID**
(SPIFFE Verifiable Identity Document), delivered as either an X.509 certificate or a
JWT token. It answers "what service is this?" so services can trust each other. See
[Workload identity](features/workload-identity.md).

### Workload

A running unit of software that needs an identity: a service, a container, a
Kubernetes pod, a serverless function, a batch job. "Workload identity" means giving
that software a credential automatically based on *what it is and where it runs*,
rather than planting a secret in it.

### Attestation

Cryptographic proof of *what* and *where* something is before it is trusted —
"this really is a pod in this cluster," "this really is an AWS EC2 instance with this
role," "this really is a genuine TPM chip." trstctl issues credentials only to
workloads that pass attestation, so an attacker can't just ask for one. See
[Workload identity](features/workload-identity.md).

### Secret

Any sensitive value a workload needs: a database password, an API key, a token, an
encryption key. Unlike a certificate, a secret is usually just an opaque string with
no built-in expiry, which is exactly why leaked secrets are so dangerous. trstctl
stores, rotates, and issues secrets. See [Secrets](features/secrets.md).

### Secret scan / Gitleaks

A scan of source code or a CI workspace looking for secrets that were accidentally
committed or copied into build files. trstctl runs the Gitleaks scanner from the
served secrets API, stores only redacted finding metadata (rule, file, line, and
fingerprint), and then shows that leaked credential in discovery, graph, and risk
views. The secret value itself is not stored by trstctl. See [Secrets](features/secrets.md).

### Secret share

A one-time way to hand a sensitive value to another machine or operator. The API
returns a bearer token once, stores only the token's SHA-256 hash plus encrypted
payload bytes, and deletes the row when it is redeemed. So a valid share survives an
API restart, but the database never contains the token or plaintext. See
[Secrets](features/secrets.md).

### API key / token

A string a service presents to prove it is allowed to call another service (think of
it as a long password for machines). They tend to be created once and never changed,
so they pile up and leak. trstctl inventories them and can issue short-lived ones
instead.

### Rotation

Replacing a credential with a fresh one on a schedule or on demand, then retiring the
old one. Frequent rotation means a stolen credential is only useful briefly. Doing it
by hand is error-prone; trstctl automates it. See [Secrets](features/secrets.md) and
[Lifecycle & PQC](features/lifecycle-and-pqc.md).

### Revocation

Declaring a still-valid certificate "no longer trusted" before it expires — for
example after a key leak. Because certificates are accepted until they expire,
revocation is how you pull one back early. It is published via a **CRL** or **OCSP**.

### CRL / OCSP

The two ways relying parties check whether a certificate has been revoked. A **CRL**
(Certificate Revocation List) is a signed list of revoked certificates, published
periodically. **OCSP** (Online Certificate Status Protocol) answers "is *this one*
revoked?" live, one certificate at a time. trstctl publishes both.

### Certificate Transparency (CT)

A global system of public, append-only logs that record (almost) every certificate a
public CA issues. Monitoring CT lets you spot a certificate issued for *your* domain
that you didn't ask for — an early warning of mis-issuance or attack. See
[Observability & risk](features/observability-and-risk.md).

### KEK / DEK

A two-level key scheme for encrypting stored data. A **DEK** (Data Encryption Key)
encrypts the actual data; the **KEK** (Key Encryption Key) encrypts the DEK. To rotate
protection you only re-encrypt the small DEK, not all the data. This pattern is called
*envelope encryption*.

### Envelope encryption

Encrypting data with a per-item **DEK**, then encrypting that DEK with a master
**KEK**. The protected blob carries the wrapped DEK with it. trstctl seals every
stored secret this way, so the master key can live in an HSM and be rotated without
touching the data. See [Configuration](configuration.md).

### HSM / KMS

Hardened places to keep private keys. An **HSM** (Hardware Security Module) is a
tamper-resistant device that performs signing *without ever exposing the key*. A
**KMS** (Key Management Service) is the cloud equivalent (AWS KMS, GCP KMS, Azure Key
Vault). trstctl can keep its CA keys in either. See [Issuance & CAs](features/issuance-and-cas.md).

### Idempotency

The property that doing an operation twice has the same effect as doing it once. A
client that retries a dropped request must not accidentally create two certificates.
trstctl enforces this with an **idempotency key** on every state-changing request
(non-negotiable **AN-5**).

### Event sourcing

A design where the source of truth is an append-only log of everything that happened,
and all other tables are *rebuilt* from that log. Nothing is ever silently
overwritten, so you get a perfect audit trail and can rebuild state after a disaster.
trstctl is event-sourced from the first commit (non-negotiable **AN-2**), using NATS
JetStream as the log.

### Projection

A read-friendly table (for example, "current certificate inventory") that is *built
from* the event log rather than written to directly. Because it is derived, it can be
thrown away and rebuilt. When trstctl shows you a list, you're reading a projection.

### Outbox pattern

A reliability trick: when trstctl needs to call something external (a CA, a webhook),
it writes that intent into an `outbox` table *in the same database transaction* as the
state change, and a separate worker makes the call. The call can never be "lost" even
if the process crashes mid-way (non-negotiable **AN-6**). Workers lease rows before
calling out and finalize them after the call, so a slow external system does not keep
a database transaction open or starve unrelated tenants.

### Multi-tenancy

Running many isolated customers (tenants) on one deployment, where no tenant can ever
see another's data. trstctl carries a `tenant_id` on every row and enforces isolation
in the database itself (see *RLS*), not in fragile application code (non-negotiable
**AN-1**). A single-company deployment simply has one tenant.

### Row-level security (RLS)

A PostgreSQL feature that filters every query by a policy the database enforces — so
even a buggy query physically cannot return another tenant's rows. trstctl uses RLS
as the floor of its multi-tenancy guarantee.

### Bulkhead

A wall between subsystems so a failure in one cannot sink the whole ship (the term is
from ship design). Each trstctl subsystem gets its own bounded worker pool; when one
is overloaded it rejects work fast (with HTTP 429) instead of starving the others
(non-negotiable **AN-7**). See [Operations & resilience](operations.md).

### SSH certificate

A short-lived, signed credential that replaces raw SSH keys in `authorized_keys`.
Instead of copying public keys to every server, you trust one SSH CA, and it signs
certificates that say "this user may log in until 5pm." trstctl runs that SSH CA. See
[SSH](features/ssh.md).

### Dynamic secret

A credential trstctl creates *on demand* when a workload asks, scoped and
time-limited, then automatically deleted when its **lease** ends — for example a
database username/password that exists for one hour. Nothing long-lived to steal. See
[Secrets](features/secrets.md).

### Lease

The "rental agreement" on a dynamic secret: how long it lives and when it must be
renewed or revoked. When the lease expires, trstctl revokes the underlying credential
automatically.

### Transit (encryption-as-a-service)

A service that encrypts and decrypts data *for* applications using keys the
application never sees, so developers get strong encryption without handling key
material. Also called "encryption-as-a-service." trstctl has library code for this
plus **KMIP** for legacy clients, but no served API/CLI surface yet. See
[Secrets](features/secrets.md).

### KMIP

The **Key Management Interoperability Protocol**, a long-standing standard that
enterprise storage arrays, databases, and appliances speak to fetch encryption keys.
trstctl has a bounded KMIP TTLV parser and authenticated library-level operation
model. It does not yet mount a served KMIP listener, so existing gear cannot point at
the running binary until that surface is wired.

### CBOM

A **Cryptographic Bill of Materials**: an inventory of all the cryptography in use —
which algorithms, key sizes, and certificates live where. You need it to answer "where
are we still using weak crypto?" and to plan the migration to post-quantum algorithms.
See [Observability & risk](features/observability-and-risk.md).

### PQC (post-quantum cryptography)

New cryptographic algorithms designed to resist future quantum computers, which will
break today's RSA and elliptic-curve keys. Migrating is a multi-year effort, so
knowing your **CBOM** and being able to swap algorithms behind one boundary matters
now. See [Lifecycle & PQC](features/lifecycle-and-pqc.md).

### Drift

When reality stops matching intent — a certificate that was supposed to be deployed
got removed, or a config was changed by hand. trstctl's agents detect drift and can
correct it. See [Observability & risk](features/observability-and-risk.md).

### Plugin / WASM sandbox

A way to extend trstctl with new CAs or deployment targets without trusting third-
party code with the whole system. Plugins run as **WebAssembly (WASM)** in a sandbox
with only the narrow capabilities they are granted, so a malicious plugin cannot reach
the database or keys. See [Extensibility & plugins](features/extensibility-plugins.md).

### Non-negotiables (AN-1 … AN-8)

trstctl's eight architectural rules, designed in from the first commit and enforced
by a custom build linter: multi-tenant storage (AN-1), event sourcing (AN-2),
cryptography behind one boundary (AN-3), an isolated signing process (AN-4),
idempotency on every mutation (AN-5), an outbox for every external call (AN-6),
bulkheads and backpressure (AN-7), and memory safety for key material (AN-8). They
appear throughout these docs because almost every feature rests on them.

### SAN (Subject Alternative Name)

The field inside a certificate that lists exactly which identities it is valid for —
DNS names like `api.example.com`, IP addresses, or a workload URI like a SPIFFE ID.
Modern TLS matches a server to its certificate by the SAN, not the old "common
name". When trstctl issues a cert, the names you asked for end up here.

### RA (Registration Authority)

The role that decides *whether* a certificate request is allowed before any key is
signed: it vets and approves requests, and the CA only signs what the RA approved.
Keeping the RA separate from the CA — and from the person making the request — is a
core control, so no single actor can both ask for and mint a credential.

### CAA (Certification Authority Authorization)

A DNS record a domain owner publishes that names which CAs are permitted to issue
certificates for that domain (RFC 8659). A well-behaved CA reads it and refuses to
issue if it is not on the list — a cheap, domain-owner-controlled guardrail against
the wrong CA issuing for your names.

### ARI (ACME Renewal Information)

An ACME extension (defined in a draft RFC) where the CA tells each client the ideal
window to renew, so a large fleet renews smoothly instead of all at once — and so a
CA that must revoke a batch early can ask clients to renew ahead of schedule. See the
ACME page.

### TSA (Time-Stamping Authority)

A trusted service that cryptographically stamps "this exact data existed at this
moment" (RFC 3161). It matters for signatures: a timestamp proves a signature was
made while the signing key was still valid, even if the key is later revoked. trstctl
runs one for its code-signing and audit evidence.

### OIDC (OpenID Connect)

A standard sign-in protocol built on top of OAuth 2.0 that lets a person log in to
trstctl with an identity they already have at a provider (Okta, Google, Entra),
instead of a trstctl-specific password. It is how browser logins and **SSO** work.

### SSO (Single sign-on)

Signing in once to your organization's identity provider and then reaching many
applications without re-entering credentials. trstctl's browser login uses SSO via
**OIDC**, so operators authenticate with the account they already manage centrally.

### MDM (Mobile Device Management)

A system that centrally configures fleets of end-user devices — laptops, phones — and
can push certificates and policies to them (e.g. Microsoft Intune). trstctl can
deliver device certificates through an MDM so endpoints enroll without a human at each
machine.

### JIT (Just-in-time issuance)

Minting a short-lived credential only at the moment it is needed — often only after an
approval — instead of handing out long-lived credentials in advance. Less standing
access means a smaller window for a leaked credential to be abused. See the
incident-and-JIT page.
