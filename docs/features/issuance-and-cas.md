# Issuance & certificate authorities — how trstctl mints and governs certificates

## What it is

Issuance is the act of **creating a [certificate](../glossary.md)**: a machine asks
for one, an authority signs it, and the machine gets back a signed ID it can present.
This page covers issuing through *any* authority, running your own
[CA](../glossary.md) hierarchy, the rules that constrain what may be issued, telling
clients when to renew, taking certificates back early, and where the private key
physically lives.

The mental model: trstctl is a **passport office**. A CA prints and signs passports; a
*profile* is the rulebook for what a valid passport may say; a *registration
authority* checks your paperwork but can't print the passport itself; *revocation* is
the bulletin of cancelled passports; and the *HSM* is the locked vault holding the
official seal.

## Why it exists

Certificates expire on purpose and must be re-minted constantly, so issuance has to be
automatic, governed, and auditable. Without a real issuance layer, three things go
wrong: the wrong certificate gets minted (too-long validity, weak key, a name the
requester shouldn't control); the signing key leaks and forges everything; or a
compromised certificate keeps being trusted because nobody can pull it back. trstctl's
issuance layer exists to make each of those hard.

## How it works

### One issuance path, any CA (F4)

Every certificate trstctl issues goes through a single, uniform interface — a `CA`
with one real method, `Issue(request)` — no matter who actually signs. The built-in
signer-backed CA, a CA in your own [hierarchy](#running-your-own-ca-hierarchy-f48), and
14 third-party authorities (Let's Encrypt/ACME, DigiCert, Sectigo, Microsoft AD CS,
AWS Private CA, Azure Key Vault, Google CAS, EJBCA, Smallstep, Venafi TPP/TLS Protect,
Vault PKI, GlobalSign, Entrust, and the shell CA escape hatch) all implement that same
interface. The running binary exposes configured upstreams as a served registry at
`GET /api/v1/external-cas`; callers issue through one selected CA with
`POST /api/v1/external-cas/{id}/issue` using a PEM CSR, DNS names, and an
`Idempotency-Key`. The CA Hierarchy page drives the same route from the browser: pick
a configured external CA, submit CSR/DNS/profile/TTL, watch `outbox-pending` while the
issue intent is recorded, then see `external-ca-issued` evidence — never the
certificate PEM.

The same binary exposes read-only CA discovery at `GET /api/v1/ca/discovery`: one
response normalizing configured public/private upstream CAs and imported private
hierarchy authorities, with counts, source ids, status, and served path pointers —
never certificate PEM or private key material.

That single path wires the intended guarantees to receipts. Each issuance carries an
[`Idempotency-Key`](../glossary.md). For an upstream CA, the request first commits one
tenant-scoped `external-ca.issue` [outbox](../glossary.md) intent; only the normal
bounded dispatcher calls the provider, waiting for its exact tenant/key result rather
than draining unrelated tenants. Before calling a provider without a native request
token, the worker durably claims that operation once; providers whose receiver
enforces the supplied token (AWS PCA, Azure Key Vault, Google CAS) use the reconciled
retry lane, while every unproven adapter stays at-most-once. A completed result
replays byte-for-byte from the `certificate.recorded` projection, so a changed command
gets 409 before provider I/O, and an interrupted tokenless submission is never
resent — it stays explicitly indeterminate rather than guessing the CA did nothing.
After a definite result the worker emits `certificate.recorded`, rebuilds the
certificate inventory, and records the separate `ca.issue` evidence row. The
identity-transition issuance retry path (`POST /api/v1/identities/{id}/transitions` to
`issued`) is exercised by the shipped-stack Compose E2E gate: the gate repeats the
same request with the same key, waits through the real PostgreSQL/JetStream/outbox/
isolated-signer path, and asserts certificate inventory remains exactly one before
revoking that certificate and verifying OCSP and CRL state. This bounded proof does
not turn tokenless or unreconciled upstream adapters into exactly-once receivers. The request's
[CSR](../glossary.md) is inspected through the single isolated cryptography path, and
the active [profile](#profiles-and-the-registration-authority-split-f53) is enforced
*before* signing, with an `issuance.profile_evaluated` event recorded either way.

Upstream CA credentials are configured by the control-plane operator, not tenant
JSON: file references load into locked byte buffers for one outbox attempt and are
wiped afterward. Azure CA private-key operations and Let's Encrypt account JWS
signatures stay in the isolated signer, and the API exposes only the non-secret
registry row (`id`, `type`, `name`, `status`). A reused idempotency key after completion returns
the original certificate without re-signing, even after garbage collection; a crash
before submission is resumed by the outbox worker, and a crash mid-submission with no
way to query the result fails closed as indeterminate rather than blind-repeating the
mint. The production `external_cas` JSON shape, `file:/absolute/path` credentials,
private-endpoint allowlist, custom trust-root, and mTLS fields are documented in
[Configuration](../configuration.md#native-connector-and-external-ca-assembly).

### Kubernetes CRD-native issuance

trstctl ships `Issuer`, `ClusterIssuer`, and `Certificate` CRDs in the `trstctl.com`
API group. The Kubernetes agent reconciles them, marks issuers Ready, signs
cert-manager `CertificateRequest`s only when they target an existing trstctl issuer,
signs approved native `CertificateSigningRequest`s from `certificates.k8s.io/v1`, and
can fulfil a trstctl-native `Certificate` directly into a Kubernetes TLS Secret. The
read-only `GET /api/v1/kubernetes/certificate-signing-requests` / CLI
`trstctl-cli kubernetes csr` report the served CAP-K8S-04 surface, supported signer
names, required RBAC, and residuals.

A cert-manager `Certificate` references trstctl with
`issuerRef: {name: trstctl, kind: ClusterIssuer, group: trstctl.com}`; a workload can
also use trstctl's native API directly:

```yaml
apiVersion: trstctl.com/v1alpha1
kind: Certificate
metadata:
  name: web
spec:
  secretName: web-tls
  dnsNames: [web.apps.svc.cluster.local]
  issuerRef: {name: trstctl, kind: ClusterIssuer, group: trstctl.com}
```

The agent forwards only a CSR to the configured trstctl issue endpoint, adds a stable
`Idempotency-Key`, and authenticates with a token mounted from a Kubernetes Secret:
cert-manager gets the normal `kubernetes.io/tls` Secret; a trstctl-native `Certificate`
gets a locally generated workload key written to `Secret/<secretName>` (transient
buffers wiped) and marked Ready; a native `CertificateSigningRequest` needs Kubernetes
or a separate approver to set `Approved` — the agent never approves its own requests.
It accepts `spec.signerName` values such as
`trstctl.com/trstctl` or `trstctl.com/<issuer-name>`, optionally disambiguated with
the `trstctl.com/issuer-{name,kind,group}` annotations, and writes the PEM chain to
`status.certificate` while preserving the
`Approved` condition — completion is `status.certificate` being present, not a custom
`Ready`. CI proves the cert-manager path against a real `kind` cluster; served
controller acceptance proves both the trstctl-native path and CAP-K8S-04 native CSR
support. The shipped ClusterRole grants `sign` only for `trstctl.com/trstctl`; a named
signer such as `trstctl.com/payments` needs that resource name added rather than
granting every Kubernetes signer.

The same agent serves CAP-K8S-07 trust-bundle distribution: operators apply a
cluster-scoped `TrustBundle.trstctl.com` resource with a public PEM CA bundle and
target namespaces; the controller rejects non-certificate PEM blocks, creates/updates
the named ConfigMap per namespace, and records `status.targets`, `status.bundleSHA256`,
and Ready=True. `GET /api/v1/kubernetes/trust-bundles`,
`trstctl-cli kubernetes trust-bundles`, and the Workloads console disclose the CRD,
RBAC, ConfigMap target, and residuals.

### Running your own CA hierarchy (F48)

trstctl can *be* your private PKI: a root CA, intermediates beneath it, end-entity
certificates beneath those — the usual tree where the root is kept offline-precious and
the intermediates do the day-to-day signing.

The dangerous operations are gated by an **m-of-n key ceremony**: nothing happens
until *m* of *n* named custodians approve. Root and intermediate creation are served
today: open a ceremony, collect distinct custodian approvals, then create or import
the CA. Each operation consumes one pending ceremony whose purpose matches the
reviewed resource: `root:<sha256-of-ca-spec>`,
`intermediate:<parent-ca-id>:<sha256-of-ca-spec>`,
`offline-root:<sha256-of-root-cert-der>:root:<sha256-of-ca-spec>`, or
`offline-intermediate:<parent-ca-id>:<sha256-of-ca-spec>`. Existing CA import uses
`import-existing-ca:<signer-handle>:<sha256-of-chain-der>:root:<sha256-of-ca-spec>`,
binding the reviewed chain to the exact signer-held key handle, and renewal/re-key
uses `rotation:<ca-id>` to create fresh signer-held CA material for the selected
authority. Short approvals return `ErrQuorumNotMet`; an opener approving their own
ceremony, or a ceremony already used or opened for a different resource/spec, fails
closed before the CA mutation commits — stopping one compromised admin account from
minting a rogue root or intermediate, and stopping one valid ceremony from being
replayed against a different CA request.

The console and CLI do not ask an operator to approve a blind change. The
effect-free `POST /api/v1/ca/ceremonies/preview` route validates the exact ceremony
body and returns a non-secret receipt before any approval record or signer action
exists. For zero-downtime rollover,
`POST /api/v1/ca/authorities/{id}/rotate/preview` applies the activation eligibility
rules to the exact predecessor and successor, then explains the routing changes,
trust risks, and proof steps without changing either CA. Both previews return an
exact request fingerprint and explicit empty write/external-effect lists; the later
mutation rechecks authorization and state under lock instead of trusting the preview.

The served hierarchy API lives at `/api/v1/ca/ceremonies/preview`,
`/api/v1/ca/ceremonies`, `/api/v1/ca/authorities`,
`/api/v1/ca/authorities/offline-roots`, `/api/v1/ca/authorities/imported`,
`/api/v1/ca/authorities/{id}/offline-intermediates/csr`,
`/api/v1/ca/authorities/{id}/offline-intermediates`, and
`/api/v1/ca/authorities/{id}/issue`, with zero-downtime successor activation at
`/api/v1/ca/authorities/{id}/rotate/preview` and
`/api/v1/ca/authorities/{id}/rotate`, signer-backed renewal/re-key at
`/api/v1/ca/authorities/{id}/rekey`, cross-signing at
`/api/v1/ca/authorities/{id}/cross-sign`, offline-root successor/cross-certificate
import at `/api/v1/ca/authorities/{id}/offline-rekey`, and offline-root-produced
cross-certificate verification at `/api/v1/ca/authorities/{id}/offline-cross-signs`.
Online root/intermediate private keys live only in the isolated signing service,
referenced by signer handles; the control plane stores certificates, chains,
metadata, and ceremony state, never the CA private key. Existing-CA import verifies a
public chain's first certificate against the supplied signer handle and the
chain/profile before serving normal leaf issuance. Offline-root import accepts
exactly one public certificate PEM (never a private key), generates a signer-held
intermediate CSR for the operator to sign outside trstctl, and imports the result
only if it chains to the offline root, matches the reviewed `CASpec`, and carries the
signer-held public key. Rotation and re-key activations both promote a signer-backed
successor (re-key from a fresh `rotation:<ca-id>` ceremony), mark the predecessor
`superseded`, record `replaces_id`, and keep both issue URLs live while new
certificates chain to the successor; offline-root re-key works the same way but stays
an operator ceremony since the offline key never enters trstctl. Every served step
(`ca.ceremony.started`, `ca.ceremony.approved`, `ca.root.created`,
`ca.authority.imported`, `ca.intermediate_csr.issued`, `ca.intermediate.created`,
`ca.authority.rotated`, `ca.authority.rekeyed`, `ca.cross_signed`,
`ca.endentity.issued`) is a tenant-scoped event recorded immutably in the
tamper-evident log. Cross-signing uses a purpose-bound
`cross-sign:<ca-id>:<sha256-of-target-cert-der>` ceremony: the signer-backed route
signs inside the signer, while offline-root routes verify validity, key usage, EKU,
DNS, path length, subject/public key, and both chain directions first. The full
operator procedure is the
[CA key-ceremony runbook](../runbooks/key-ceremony.md).

### Executing a CA migration in waves (H2)

CA rollover is served as a durable trust-before-leaf workflow, not as a batch loop.
First run the read-only assessment:

```sh
trstctl migrations assess -f assessment.json
```

Then start a reviewed manifest with a fresh `Idempotency-Key` (the CLI supplies one
unless you override it):

```json
{
  "plan_id": "root-rollover-2026",
  "new_authority_id": "11111111-1111-4111-8111-111111111111",
  "waves": [
    {
      "id": "canary",
      "ordinal": 1,
      "members": [
        {
          "identity_id": "22222222-2222-4222-8222-222222222222",
          "agent_id": "33333333-3333-4333-8333-333333333333",
          "trust_anchor_path": "/etc/trstctl/roots/next.pem"
        }
      ]
    }
  ]
}
```

`new_authority_id` must name an active signer-backed hierarchy authority in the
same tenant. The control plane reads its public certificate and freezes both the
authority ID and anchor fingerprint into every member binding. Private keys never
enter the manifest or control-plane process. When the trust receipt arrives, the
successor is signed by that exact authority; a later CA rotation does not silently
reroute an already-reviewed run.

The phase order is fixed: install and read back the public anchor, issue against a
host-generated CSR, deploy, handshake the configured listener, then release the next
wave. Agent receipts are signature- and lease-verified before they can move a gate.
Any failed receipt halts publication of later work and automatically starts the
newest-first inverse. Every effect published for the failed gate is settled, including
work that was already leased and reports after rollback began. `pause` prevents new
publication while retaining receipts for already-leased work; `resume` reconstructs
only the unfinished actions. The manual `rollback` control uses the same inverse:
restore and verify predecessor leaves newest wave first, restore inventory truth from
the same migration event, and remove successor trust only after the leaf inverse
passes. A failed inverse halts with its durable attempt cursor; a later manual retry
uses fresh outbox identities rather than replaying a terminal job.

Starting and resuming require both `keys:write` and `certs:issue`, because either
operation can release a successor mint. Pause and rollback require `keys:write`.

```sh
trstctl migrations start -f run.json
trstctl migrations list
trstctl migrations show RUN_ID
trstctl migrations pause RUN_ID
trstctl migrations resume RUN_ID
trstctl migrations rollback RUN_ID
```

The REST equivalents are `POST /api/v1/migrations/runs`, `GET
/api/v1/migrations/runs`, `GET /api/v1/migrations/runs/{id}`, and the three action
routes below that run. The current executable boundary is internally issued,
DNS-only X.509 identities deployed by enabled host-agent connectors with a configured
verification listener. Unsupported membership is rejected before any trust job is
published.

### Profiles and the registration-authority split (F53)

A **certificate profile** is a versioned, tenant-scoped rulebook: allowed key
algorithms and minimum sizes, extended key usages, maximum validity, DNS suffixes,
and protocols. Editing a profile creates a *new version*; old versions stay
queryable, so you always know which rules a past certificate was issued under. On
every issuance, `enforceProfile` fetches the active version, validates the request,
and emits an audit event for the allow-or-deny decision.

The **registration-authority (RA) model** is a role split that prevents the classic
PKI abuse of one person approving and fulfilling their own request. The built-in
`ra-officer` role can read/write profiles and *request* certificates but doesn't hold
`certs:issue` — only an operator/admin can issue. The split is enforced by
[RBAC](policy-and-governance.md), not convention, and a test asserts it. Authoring
profiles is covered in the
[certificate-profile guide](../guides/profile-authoring.md).

The self-service requester path is served end to end for X.509 requests. `/request`
lists active profiles and tenant-visible owners, makes the requester choose the
accountable owner by name, and sends the exact proposed body to the effect-free
`POST /api/v1/issuance-requests/preview` route. The same server admission rule used
by submission checks the owner, validates an optional public CSR, and resolves an
active profile name to its exact immutable version. The answer names blockers,
key-custody posture, independent approval authority, and the writes that a later
submission would perform. Preview itself appends no event, writes no projection,
creates no idempotency record, and contacts no CA. The console fails closed: it
enables submission only while a green preview still matches every reviewed field.
Operators and automation can ask the same question with
`trstctl issuance-requests preview --body request.json`.

Submission sends the normalized body to `POST /api/v1/issuance-requests`. The
server re-runs that shared admission rule before appending
`issuance.request.opened`; missing or malformed values return 400, while absent and
other-tenant owner UUIDs return the same 422 answer. The console links directly to
Profiles, Owners, and CA hierarchy when a prerequisite needs configuration. This is
important: `oidc|dev-1` names an authenticated caller, while an owner UUID names a
tenant database row. They are different identifiers and are never substituted for
one another.

The requester's `/request` history and the `/approvals` inbox read the same
first-class issuance-request projection. A submission therefore remains
`requested`; it does not create an identity or mint a certificate. A distinct
principal can approve or deny the exact request, and approval is still not issuance:
the request becomes `issued` only after the authorized issuance outcome is linked.
If issuance is interrupted after approval, the approved row remains visible and the
console offers **Retry safely**. Preparation reuses the request's deterministic
identity and stable issuance key, so retry continues the same operation instead of
minting a second certificate.

The built-in `ra-officer` can read owners, author/read profiles, and request
certificates, but still cannot write identities or hold `certs:issue`.

Profile recovery is served as an append-only operation. `POST
/api/v1/profiles/{name}/versions/{version}/restore/preview` returns an effect-free
receipt for copying a known-good historical spec into the next version. The receipt
pins the current active version, semantic spec digest, reason, request fingerprint,
issuance risks, and proof steps; it emits no event and performs no external call.
`POST /api/v1/profiles/{name}/versions/{version}/restore` rechecks that active-version
fence under the projection lock, creates one new event-sourced active version, and
leaves every historical row untouched. Reusing the idempotency key returns the same
result. A newer concurrent version fails closed with `409`, and profiles governed by
`requires_approval` retain non-requester dual control. The console exposes the same
flow after a version diff; the CLI commands are `profiles restore-preview` and
`profiles restore`. See the [profile-authoring guide](../guides/profile-authoring.md)
for a complete example.

A profile create or edit that falls under `requires_approval` answers **202**
with an `approval_id` and `state: awaiting_approval` instead of a new version.
A distinct reviewer holding `profiles:write` finds the parked request with
`GET /api/v1/profiles/approvals` (or `GET /api/v1/profiles/approvals/{id}`) and
approves it with `POST /api/v1/profiles/approvals/{id}/approvals`; quorum (one
non-requester approval) applies the queued spec as the new active version and the
record reads `state: issued` with the created `profile_id`. The requester's own
approval is refused with **403** (dual control). Identical retries of the
approval with the same `Idempotency-Key` replay the one decision. The parked
request is event-sourced (`profile.edit_approval.requested` / `.approved`,
projected into `profile_edit_approvals`), so it survives a control-plane
restart and is visible to every replica; it expires 24 hours after the 202
(`state: expired`, approval answers **409**) and the requester resubmits the
change to open a new request.

### Telling clients when to renew: ARI (F46)

If thousands of clients renew at the same fixed "30 days before expiry," they
stampede — and if a certificate must be replaced *early* (a mass revocation), there's
no way to tell them. **ACME Renewal Information (ARI, RFC 9773)** fixes both: the CA
publishes a *suggested renewal window* per certificate, and clients renew within it.

trstctl computes the window as the last third of the certificate's life and has each
client pick a deterministic, spread-out point inside it. If the CA flags a
certificate for early renewal, the window jumps to "right now" and compliant clients
renew immediately.

Served by the ACME server at `GET /acme/renewal-info/{certid}` and consumed by the
served lifecycle scheduler for trstctl-issued deployed X.509 identities — certificates
can renew when their ARI window opens, even before the fixed `renew_before` fallback.

Operators inspect the same chain through the read-only
`GET /api/v1/acme/ari/posture` route, the `trstctl-cli acme ari posture` command,
or the **ARI posture** panel on **Protocols**. The authenticated route requires
`lifecycle:read` and PostgreSQL RLS limits every certificate and rotation-run row to
the caller's tenant. It reports whether ARI publication is served for that tenant,
the exact suggested window for each affected certificate, and whether the lifecycle
scheduler is pending, running, succeeded, or failed for that window. It never returns
certificate bytes, fingerprints, tenant IDs, account/order data, or private-key
material.

The public ACME route and the operator route answer different questions:
`/acme/renewal-info/{certid}` tells an ACME client *when it should renew*;
`/api/v1/acme/ari/posture` tells an authenticated operator *what is being published
and whether trstctl's scheduler consumed it*. If ACME is not mounted for the tenant,
the posture says `not_served` rather than pretending the certificate is published.
An empty `items` array honestly means that the tenant has no affected deployed
certificate rows.

### Revocation: OCSP and CRLs (F47)

When a certificate must stop being trusted before it expires, you **revoke** it and
publish that fact two ways. A **[CRL](../glossary.md)** is a signed list of revoked
serials, regenerated periodically; **[OCSP](../glossary.md)** answers "is *this one*
revoked?" live, one certificate at a time. For its own hierarchy trstctl does both:
`Revoke(serial, reason)` emits `ca.certificate.revoked` to the tamper-evident log, and
`GenerateCRL` bumps the CRL number, signs a fresh list through the isolated
cryptography path, and emits a v3 `ca.crl.published` event (CRL DER, artifact kind,
shard metadata, delta base, validity window) so CRL state rebuilds from the log.
Small estates use the plain `/crl/{tenant}` full CRL; at scale the same publication
also serves `/crl/{tenant}/manifest.json`, `/crl/{tenant}/shards/{index}`, and
`/crl/{tenant}/delta/{base}`, so relying parties fetch bounded or RFC 5280 delta CRLs
instead of a 10-100M-row monolith. The OCSP responder signs with a delegated
responder certificate (OCSPSigning EKU + ocsp-nocheck) rather than the CA
certificate; rotations emit `ca.ocsp_responder.rotated`, and the responder runs in
its own bounded [lane](../glossary.md) so a flood can't starve the API.

RFCs 6960 (OCSP), 5280 (CRL).

Revocation is typed and batchable: requests use an RFC 5280 named revocation reason
such as `keyCompromise`, `cessationOfOperation`, or `privilegeWithdrawn` (unknown raw
integers are rejected), and bulk revoke at `/api/v1/certificates/bulk-revoke` /
`/api/v1/identities/bulk-revoke` returns matched, revoked, skipped, and failed counts
so a wide incident response is explicit about partial success. OCSP responses echo a
valid OCSP nonce when the request carries one and sign with the delegated responder;
CRL serving returns weak ETag validators and honors `If-None-Match` with `304 Not
Modified` so relying parties don't refetch an unchanged CRL. `GET
/api/v1/revocation/crls` / `trstctl-cli revocation crls` and the Certificates console
expose the same distribution state (full CRL, shards, delta base, freshness window).

Bulk identity revocation requires both `identities:write` and the privileged
`certs:issue` authority. Every selected identity must pass the lifecycle policy and
attribute-based restrictions before any selected identity is changed. A denial is
not partial success: no revocation intent is queued for the selected batch.
When dual control is required, the bulk request cannot supply the exact one-use
approval for each identity and is refused. Use the individual reviewed revocation
workflow below; a standing approval does not authorize a bulk action.

To select actual inventory certificates rather than lifecycle identities, send
`certificate_ids` with 1–100 UUIDs and a named `reason`. An empty array is invalid.
Do not combine this field with `ids`, `identity_ids`, owner/issuer filters, kind,
or status. The same authorization, policy and approval restrictions apply, even
when no certificate matches. `removeFromCRL` is an unhold operation, not a valid
reason for this exact-certificate revocation command.

The exact path verifies the public certificate's signature against the served
issuing CA and requires an existing tenant-scoped issuer record. It does not guess
from an issuer name or serial, revoke same-owner siblings, or substitute the
internal CA for an external issuer. This path currently handles leaves issued by
the running server's issuing authority. Other authorities return an explicit
per-item unsupported result; use their documented revocation path. HTTP 200 can
contain failed items, so always inspect the returned counts and items.

One retained `certificate.revocation.batch.applied` command records the exact
selection and outcome. Its projection updates certificate inventory, the CA's
revocation record and a `revocation.crl.publish` outbox intent in the same database
transaction. If inventory and issuer disagree, it reconciles them while preserving
the issuer's first revocation time and reason. `revoked` therefore includes a
reconciled record; it is not a count of newly revoked serials at the CA. `skipped`
means inventory and the issuer already agree that the certificate is revoked.

Reuse the same `Idempotency-Key` for the same authenticated route and request.
Retries recover the original result from retained events even after the HTTP
result cache expires or an append succeeds before the database transaction fails.
Changing the selection or reason under that key returns `409`. CRL publication is
asynchronous: a committed result is not proof that publication or a relying-party
check succeeded. Follow the delivery outcome, verify signed CRL/OCSP data, and test
a client configured to enforce revocation before declaring containment complete.

For one managed certificate, **Certificates → Revocation & CT → Revocation center** is the
safe operator path. It is a three-step journey: choose the X.509 identity and factual
RFC 5280 reason; fetch an effect-free server preview; then type the exact credential
name to execute. The preview is bound to the identity's current lifecycle version and
request fingerprint. It explains the event, same-transaction outbox intent,
asynchronous `revocation.publish` work, graph-derived affected systems, and verification
steps while writing no event and contacting no external system. Execution echoes that
reviewed version, so a certificate that changes after review fails with `409` and must
be reviewed again. After success, the center links directly to the immutable
`identity.revoked` audit evidence and the affected-systems graph. The lifecycle event
and outbox remain the only mutation authority; the console does not invent a second
browser-only revocation path.

External distribution health is monitored separately from trstctl's own
publication state. An hourly leader derives distinct CDP and AIA OCSP URLs from
the certificate inventory and queues bounded `revocation.probe` work for a
network relay, so private PKI endpoints are checked from the network that uses
them. The relay verifies CRL/OCSP signatures and exact certificate context, then
returns a signed lease-bound report. `GET /api/v1/revocation/health` and
Certificates → Revocation & CT expose fresh, expiring, stale, unreachable, and invalid
answers with latency, `nextUpdate`, relay identity, and evidence digest; non-fresh
answers create notifications. A missing observation is shown as unknown, never healthy.
This proves the relay's observation, not every relying party's fail-closed or
soft-fail configuration. Controlled CRL/OCSP responders cover repository CI; a
real Windows AD CS lab run remains external infrastructure evidence.

Dark-segment serving is a separate local-cache path. A network-role agent can load a
bounded `--revocation-cache-config` with multiple issuers and explicit local CRL and
OCSP routes. It verifies CRL issuer signature, number, and signed time window before
caching. For OCSP it also binds the request to the configured issuer and validates
the responder signature, requested serial, nonce, `thisUpdate`, and `nextUpdate`.
Only nonce-free answers are reused, and stale or invalid objects produce 503 with no
protocol bytes. Each mTLS heartbeat signs metadata per segment/issuer/protocol;
`GET /api/v1/revocation/caches` and Protocols → Revocation cache by segment expose
fresh, stale, empty, and error without exporting upstream URLs or cached objects.
An unreported relay is unknown, not healthy.

CT submission is served at `POST /api/v1/revocation/ct-submissions` /
`trstctl-cli revocation ct-submit`: the outbox queues a precertificate and final
certificate to configured RFC 6962 CT logs, recording `ct.submission.queued` then
`ct.submission.delivered` after `add-pre-chain`/`add-chain` — inclusion proof remains
the external log's responsibility.

Rogue and non-compliant certificate posture is served at
`GET /api/v1/revocation/rogue-certificates` / `trstctl-cli revocation
rogue-certificates` and the Certificates console: unexpected CT findings from
monitored logs combined with policy violations such as weak keys, expired active
certificates, over-long public-TLS lifetimes, and missing owners/issuer metadata —
metadata and projection references only, never certificate PEM or private-key
material.

### Where the private key lives: HSM/KMS (F26)

A CA's private key is the system's single most valuable secret — anyone who has it can
forge any certificate, so trstctl keeps it in hardware or a cloud key service that
signs without revealing it. An [HSM/KMS](../glossary.md) backend implements one
interface (`Backend` → `GenerateKey` → a `Signer` that signs via the device); trstctl
supports PKCS#11 HSMs, TPM 2.0, YubiHSM 2, AWS KMS, Azure Key Vault, and GCP Cloud KMS.
Adding one is a single change because *all* cryptography goes through one isolated
path: key material never leaves the device — it lives in a separate isolated signing
service, wipeable in memory, and only signatures/public keys cross the wire. Every
backend must pass a conformance harness (`ConformBackend`) that signs a probe,
verifies it, and confirms a wrong message and a tampered signature both fail.

The release includes a dedicated cgo HSM signer artifact: its PKCS#11 adapter opens
the configured native module using stable token `CKA_ID` values across restarts, TPM
2.0 uses `google/go-tpm` persistent handles, and YubiHSM 2 uses Yubico's
`yubihsm_pkcs11` ABI. The launched-binary gate proves SoftHSM/swtpm lifecycle behavior
with independent command-line readback; the default control-plane artifact stays
static and never loads a native module, keeping provider credentials and private-key
operations inside the separate signer.

CAP-KEY-05 — Multiple algorithms (RSA / ECDSA / Ed25519) + Enterprise/PQC — is served:
the profile path is `POST /api/v1/profiles` and
`trstctl-cli profiles create -f profile.json`. The profile API validates
`allowed_key_algorithms` through `internal/crypto`, then stores the accepted policy as
`profile.created` evidence. It accepts classical `RSA`, `ECDSA`, and `Ed25519` labels
in the MPL core; PACKAGING-007 makes the PQC signature labels proprietary Enterprise/PQC
capabilities under `ee/`: `Hybrid-ML-DSA-44-ECDSA-P256`, `ML-DSA-65`,
and `SLH-DSA-SHA2-128s`. Unknown labels fail closed, and ML-KEM stays out of
certificate-signing profiles because it's a key-encapsulation mechanism, not a signing
algorithm. `internal/server/crypto_agility_served_test.go`'s
`TestServedCryptoAgilityProfilesValidateBoundaryAlgorithms` proves the served profile
create/list round trip; those Enterprise/PQC issuance proofs live under `ee/pqc` and
`ee/pqcmigration`, so they don't count as MPL-core served evidence.

The managed-key API spine is configuration- and license-gated for AWS KMS, Azure Key
Vault/Managed HSM, GCP Cloud KMS, PKCS#11, TPM 2.0, and YubiHSM 2 custody: once
`managed_keys.enabled` is true and `managed_keys.provider` selects `aws`,
`azure-key-vault`, `gcp-kms`, `pkcs11`, `tpm2`, or `yubihsm2`, the control plane
exposes:

- `GET /api/v1/managed-keys/custody` — return a secret-free startup plan for all six
  providers, the configured provider, signer attachment, and exact blockers;
- `POST /api/v1/managed-keys/preview` — validate provider and algorithm without
  writing state or calling the signer/provider, then name the later execution effects
  and verification evidence;
- `POST /api/v1/managed-keys` — create a non-extractable KMS/HSM-resident signing key
  (`extractable: false`; no private material returned);
- `POST /api/v1/managed-keys/approvals` — record a distinct custodian's approval for
  an opaque key handle and `rotate`/`revoke`/`zeroize`;
- `POST /api/v1/managed-keys/rotate` — mint a successor key;
- `POST /api/v1/managed-keys/revoke` — disable the current key at the provider;
- `POST /api/v1/managed-keys/zeroize` — schedule provider-side destruction.

The **Certificate authorities → Key custody** console turns those first two routes
into a three-step ELI5 journey: choose a provider and algorithm, review proof that
nothing changed, then generate and manage the key. It lists configuration variable
and file-reference names but never accepts provider credentials, file contents, or
private-key bytes in the browser. A provider mismatch, disabled lifecycle, missing
signer attachment, non-effect-free preview, or any server blocker keeps generation
locked.

The CLI mirrors those verbs under `trstctl managed-keys`, including `approve`.
Approval requires `keys:approve`; lifecycle mutation requires `keys:write`; the
requester never counts as an approver; and every request is tenant-scoped, idempotent,
and recorded as a key-material-free event before its PostgreSQL outbox command reaches
the signer. A required gate launches the shipped control plane and cgo signer,
exercises all six providers end to end against faithful cloud emulators, SoftHSM, or
swtpm, and stops the signer mid-rotation to independently verify the resulting state
(see Pitfalls & limits for what that proves and doesn't).

The same posture includes the served CAP-KEY-03 FIPS path: `GET /api/v1/editions` and
the Platform page expose the live FIPS POST booleans, `make fips-build` build target,
`fips-capable build (GOFIPS140)` CI gate, and `internal/crypto` boundary, keeping the
NIST CMVP product certificate as the external lab-certification residual.

## Use it

Issue and govern through the served API and CLI:

```sh
# create a versioned profile (RA officer or admin)
trstctl-cli profiles create -f tls-server-90d.json

# list active profiles
trstctl-cli profiles list
```

A profile spec looks like this — note the explicit, enforced constraints:

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

A hybrid transition profile allows the hybrid key label and binds it to the protocols
allowed to request it:

```json
{
  "name": "hybrid-web-30d",
  "spec": {
    "allowed_key_algorithms": ["Hybrid-ML-DSA-44-ECDSA-P256"],
    "allowed_protocols": ["acme", "est", "scep", "cmp"],
    "allowed_ekus": ["serverAuth"],
    "max_validity": "720h"
  }
}
```

Issuance happens through the enrollment protocols ([ACME](acme-and-dns.md),
[EST/SCEP/CMP](enrollment-protocols.md)), the private-CA hierarchy API, and the
external CA registry API, each of which calls the one issuance path with an
`Idempotency-Key`. Revoke from the incident flow in [Incident response](incident-and-jit.md).

## Pitfalls & limits

- **Private-key custody is a deployment boundary.** All six managed-key backends are
  census-served through the separate HSM signer artifact, but the operator must still
  provision an Enterprise BYOK license, one provider, credential files, IAM, network
  egress, and device/module trust — see [configuration](../configuration.md) for the
  startup contract.
- **Emulator proof is not deployment certification.** The cloud gate uses faithful
  vendor-protocol emulators, PKCS#11/YubiHSM use a SoftHSM-backed ABI target, and TPM
  uses swtpm — stronger than an author-injected registry or unit test, but not a live
  cloud account, a physical customer HSM, or the device's FIPS certificate. The native
  bindings ship in the cgo HSM signer artifact, not the default static control-plane
  artifact.
- **ARI scheduling covers trstctl-issued deployed X.509 identities.** Certificates
  discovered from another CA can still be inventoried and risk-scored, but renewing
  them needs a configured issuer path that can replace that outside certificate.
- **External CA registration is operator configuration.** Tenants can list and use
  configured upstream CAs, but provider credentials aren't created through the tenant
  REST API.
- **Revocation covers trstctl's own hierarchy.** Third-party CA certificates are
  revoked through those CAs.

## Reference

- **CLI groups:** `profiles`, `issuers`, `external-cas`, `certificates`, and
  `acme ari posture`.
- **Served routes:** `POST|GET /api/v1/profiles`,
  `GET /api/v1/profiles/{name}/versions/{version}`, the effect-free
  `POST /api/v1/profiles/{name}/versions/{version}/restore/preview`, append-only
  `POST /api/v1/profiles/{name}/versions/{version}/restore`, `POST /api/v1/certificates`,
  `GET /api/v1/external-cas`, `POST /api/v1/external-cas/{id}/issue`,
  `GET /api/v1/acme/ari/posture` (`lifecycle:read`),
  `POST /api/v1/ca/authorities/{id}/rotate`,
  `POST /api/v1/ca/authorities/{id}/rekey`,
  `POST /api/v1/certificates/bulk-revoke`,
  `POST /api/v1/identities/bulk-revoke`.
- **Upstream CA adapters:** AD CS, AWS Private CA, Azure Key Vault, DigiCert, EJBCA,
  Entrust, GlobalSign, Google CAS, Let's Encrypt/ACME, Sectigo, shell CA, Smallstep,
  Vault PKI, and Venafi TPP/TLS Protect.
- **Key ceremony:** `StartCeremony` → ≥`threshold` × `Approve` → `CreateRoot` /
  `ImportExisting` / `CreateIntermediate`. See the
  [runbook](../runbooks/key-ceremony.md).
- **Events:** `ca.issue`, `issuance.profile_evaluated`, `ca.root.created`,
  `ca.authority.imported`, `ca.intermediate.created`, `ca.authority.rotated`,
  `ca.authority.rekeyed`, `ca.cross_signed`, `ca.certificate.revoked`,
  `ca.crl.published`.
- **RFCs:** 5280 (X.509/CRL), 6960 (OCSP), 9773 (ARI).

## See also

[ACME & DNS](acme-and-dns.md) · [Enrollment protocols](enrollment-protocols.md) ·
[Certificate-profile guide](../guides/profile-authoring.md) ·
[CA key-ceremony runbook](../runbooks/key-ceremony.md) ·
[Signing-service design](../design/signing-service.md) ·
glossary: [CA](../glossary.md), [CSR](../glossary.md), [OCSP](../glossary.md),
[CRL](../glossary.md), [HSM/KMS](../glossary.md)

**Covers:** F4, F48, F53, F46, F47, F26
