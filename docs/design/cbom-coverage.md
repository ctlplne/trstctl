<!-- GENERATED FILE — do not edit by hand.
     Regenerate: go run ./tools/cbomcoveragedoc
     CI verifies freshness with -check (make cbom-docs-check). -->

# Computed cryptographic discovery coverage

Discovery tools all answer "what did you find." This one also answers
**"how would you know what you missed."** Every discovery source the server
can execute declares an *observability envelope* — the asset classes it can
see, what the deployment must provide before it can run, and how long an
observation stays current. The estate is then sorted into three buckets, so a
gap is a row with a reason instead of an absence nobody notices.

This page is generated from the model. The tables below are read out of
`internal/cbom/coverage` at generation time and the numbers are computed by
running the real classifier over a fixed fixture estate — so the page cannot
describe a registry the code does not have.

## The three buckets

| Bucket | Means | What closes it |
|---|---|---|
| `OBSERVED` | A source whose envelope covers the class completed a run inside its freshness window | nothing — this is the good case |
| `OBSERVABLE-UNOBSERVED` | The class is inside some configured source's envelope, but no run has covered it | the per-row action: configure, fix, or re-run the named source |
| `STRUCTURALLY-UNOBSERVABLE` | No configured source can ever observe this class | a new source kind, or an honest statement that trstctl does not cover it |

The headline number is coverage, not asset count. An `OBSERVABLE-UNOBSERVED` row always
carries both the specific reason and the action that would close it; a
`STRUCTURALLY-UNOBSERVABLE` row names the class and states plainly that no served
source covers it.

## Observability envelopes — 17 served source kinds

The authoritative catalog is the **served executor set**: the source kinds the
server can actually run when an operator queues a discovery run
(`discoveryRunExecutors` in `internal/server/discovery.go`). Coverage is a claim
about what this deployment can do, not about which interfaces exist in the
library. `TestEveryDiscoverySourceDeclaresEnvelope` welds this registry to that
catalog in both directions — a served kind with no envelope and an envelope for
a kind the server cannot execute both fail the build — so the table below is the
served set by construction.

| Source kind | Observes | Preconditions | Freshness |
|---|---|---|---|
| `api_key` | `api-key-token` | `connector-credential-configured` | 24h0m0s |
| `cloud_certificate` | `cloud-certificate` | `cloud-credential-configured` | 24h0m0s |
| `cloud_secret` | `stored-secret` | `cloud-credential-configured` | 24h0m0s |
| `credential_compromise` | `compromised-credential` | `connector-credential-configured` | 24h0m0s |
| `ct_log` | `ct-exposed-certificate` | `monitored-domains-configured` | 24h0m0s |
| `drift` | `deployed-certificate` | `deployment-baseline-configured` | 24h0m0s |
| `k8s_ingress_gateway` | `kubernetes-tls-endpoint` | `cluster-credential-configured` | 24h0m0s |
| `manual` | `operator-declared` | `operator-supplied-findings` | 24h0m0s |
| `network` | `certificate-key`, `tls-endpoint` | `scan-ranges-configured` | 24h0m0s |
| `nhi_behavior` | `nhi-behavior` | `connector-credential-configured` | 24h0m0s |
| `nhi_cross_surface` | `nhi-identity` | `connector-credential-configured` | 24h0m0s |
| `oauth_grant` | `oauth-grant` | `connector-credential-configured` | 24h0m0s |
| `secret_repo` | `repository-secret` | `repository-configured` | 24h0m0s |
| `secret_store` | `stored-secret` | `cloud-credential-configured` | 24h0m0s |
| `secret_third_party` | `third-party-secret` | `connector-credential-configured` | 24h0m0s |
| `service_account` | `service-account` | `connector-credential-configured` | 24h0m0s |
| `ssh` | `ssh-host-key`, `ssh-private-key` | `scan-targets-configured` | 24h0m0s |

`manual` is the served fallback: a source of any kind with no dedicated
connector records operator-supplied findings, and its envelope says exactly
that — the operator's own declarations, nothing observed by trstctl itself.

## Structurally unobservable classes — 7

These are the honest edges of the product. They are enumerated **in code**
(`internal/cbom/coverage/unobservable.go`), not in prose, and a class added
without a stated reason fails `TestEnvelopeRegistryShape`. A class cannot be
both observable and structurally unobservable — that contradiction fails the
same test.

| Class | Why no configured source can observe it |
|---|---|
| `firmware-embedded-crypto` | no source inspects device firmware; vendor-published CBOM ingest is not built, and a firmware scanner is a standing non-goal |
| `vendor-embedded-crypto` | cryptography inside third-party appliances and products is invisible to every served source; vendor CBOM ingest (WS-3) is not built |
| `data-at-rest-posture` | volume, database, and KMS at-rest encryption state is invisible to network or API observation; the agent posture source (WS-4) is not built |
| `unroutable-segment` | workloads scans cannot reach and where no agent runs are invisible — the cloudcert blind-spot admission generalized: reachability is a precondition of every active source |
| `directory-unlinked-account` | a served one-sided source cannot claim AD or cloud directory category coverage from only one side (the serviceaccount admission); accounts visible only in an unconnected directory are not observed |
| `passive-wire-traffic` | trstctl probes actively and never captures traffic; taps, span ports, and inline appliances are a deliberate non-goal |
| `dormant-kmip-object` | KMIP-managed objects not presently in use are not enumerated (WS-5 not built); traffic- and use-based observation cannot see them by construction |

## Worked example

Computed by running `coverage.Classify` over a four-source fixture estate at a
fixed clock, exercising every UNOBSERVED branch. This is the generator's own
output, not an illustration.

Estate: a `network` source that succeeded 2h ago, an `ssh` source whose last
success was 72h ago (past its 24h0m0s window), a `ct_log` source whose last run
failed, and a `cloud_certificate` source that has never completed a run.

**2 observed · 16 observable-unobserved · 7 structurally unobservable** across 25 classes.

| Class | Bucket | Reason / attribution |
|---|---|---|
| `api-key-token` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind api_key (needs: connector-credential-configured)** |
| `certificate-key` | `OBSERVED` | observed by dc-east |
| `cloud-certificate` | `OBSERVABLE-UNOBSERVED` | source "acm-prod" is configured but has never completed a run — **run discovery source "acm-prod"** |
| `compromised-credential` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind credential_compromise (needs: connector-credential-configured)** |
| `ct-exposed-certificate` | `OBSERVABLE-UNOBSERVED` | last run of "ct-watch" finished "failed", not "succeeded" — **fix and re-run discovery source "ct-watch"** |
| `deployed-certificate` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind drift (needs: deployment-baseline-configured)** |
| `kubernetes-tls-endpoint` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind k8s_ingress_gateway (needs: cluster-credential-configured)** |
| `nhi-behavior` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind nhi_behavior (needs: connector-credential-configured)** |
| `nhi-identity` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind nhi_cross_surface (needs: connector-credential-configured)** |
| `oauth-grant` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind oauth_grant (needs: connector-credential-configured)** |
| `operator-declared` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind manual (needs: operator-supplied-findings)** |
| `repository-secret` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind secret_repo (needs: repository-configured)** |
| `service-account` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind service_account (needs: connector-credential-configured)** |
| `ssh-host-key` | `OBSERVABLE-UNOBSERVED` | last successful run of "bastions" completed 2026-07-29T12:00:00Z, older than the 24h0m0s freshness window — **re-run discovery source "bastions"** |
| `ssh-private-key` | `OBSERVABLE-UNOBSERVED` | last successful run of "bastions" completed 2026-07-29T12:00:00Z, older than the 24h0m0s freshness window — **re-run discovery source "bastions"** |
| `stored-secret` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind cloud_secret or secret_store (needs: cloud-credential-configured)** |
| `third-party-secret` | `OBSERVABLE-UNOBSERVED` | no configured source observes this class — **configure a discovery source of kind secret_third_party (needs: connector-credential-configured)** |
| `tls-endpoint` | `OBSERVED` | observed by dc-east |
| `firmware-embedded-crypto` | `STRUCTURALLY-UNOBSERVABLE` | no source inspects device firmware; vendor-published CBOM ingest is not built, and a firmware scanner is a standing non-goal |
| `vendor-embedded-crypto` | `STRUCTURALLY-UNOBSERVABLE` | cryptography inside third-party appliances and products is invisible to every served source; vendor CBOM ingest (WS-3) is not built |
| `data-at-rest-posture` | `STRUCTURALLY-UNOBSERVABLE` | volume, database, and KMS at-rest encryption state is invisible to network or API observation; the agent posture source (WS-4) is not built |
| `unroutable-segment` | `STRUCTURALLY-UNOBSERVABLE` | workloads scans cannot reach and where no agent runs are invisible — the cloudcert blind-spot admission generalized: reachability is a precondition of every active source |
| `directory-unlinked-account` | `STRUCTURALLY-UNOBSERVABLE` | a served one-sided source cannot claim AD or cloud directory category coverage from only one side (the serviceaccount admission); accounts visible only in an unconnected directory are not observed |
| `passive-wire-traffic` | `STRUCTURALLY-UNOBSERVABLE` | trstctl probes actively and never captures traffic; taps, span ports, and inline appliances are a deliberate non-goal |
| `dormant-kmip-object` | `STRUCTURALLY-UNOBSERVABLE` | KMIP-managed objects not presently in use are not enumerated (WS-5 not built); traffic- and use-based observation cannot see them by construction |

## What this does not prove

An `OBSERVED` class means a source that declares it completed a run inside
its freshness window. It does **not** mean every instance of that class in the
estate was found — a scan covers the ranges it was given, and coverage cannot
know about a subnet nobody declared. What the model does guarantee is that a
class no source can reach is named and reasoned rather than silently absent,
and that a source cannot claim reach it never declared.

## How this page stays honest

`make cbom-docs-check` regenerates this page and fails when the committed copy
differs. It runs in CI beside the claim-traceability and CWE-register checks.
Adding a source kind, an asset class, or an unobservable class without
regenerating is a red build.
