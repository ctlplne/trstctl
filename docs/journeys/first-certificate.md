# Issue your first certificate

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `built_in_ca`, `identity_requests`, `approvals`, `certificate_inventory`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

The [Getting started](../getting-started.md) page explains installation. In the
first-certificate wizard, enter the owner attribution and paste a public PKCS#10
CSR made where the workload's private key is held. The wizard accepts no private
key and does not create one. The separate signer's health is a prerequisite;
a catalog label is not an issuing-authority selection. The completed certificate
reports its actual issuer.

Submitting the identity transition accepts work. It does not mean that a
certificate exists yet. Keep the page open while it reads the result for that
identity and its exact issuance request key. A pending result offers no download.
An issued result exposes only the recorded public leaf and the returned public
chain. Neither downloading a chain nor seeing an issuer name installs trust,
proves a hostname match, or proves that the workload uses the certificate.

If a response is lost, retry the retained attempt without changing its CSR or
keys. The owner, attestation, identity creation and issuance each retain their
original key. An unrelated 400/403/409 response is not permission to start a new
issuance. When the server returns the exact `identity_csr_rejected_before_transition`
disposition for the retained tenant, subject, identity, CSR and key, the wizard
offers an explicit CSR correction. That action keeps the owner and identity and
creates one new issuance key. The original refusal remains replayable. An
approval refusal still needs the actual approval workflow; this page cannot
approve its own request.

Recovery keys stay only in this document's memory. Route navigation preserves
them; reloading, signing out or closing the tab can lose them. After such an
interruption, inspect identity inventory and audit history before deliberately
starting another request. Absence of local browser state does not prove that
issuance failed. Fresh principal checks do not form an atomic cross-tab cookie
session lock.

For a requester-held key, served renewal follows the certificate's explicit
same-tenant predecessor chain to that identity's exact issued transition CSR.
It checks the CSR signature, public key, common name and SANs against the
predecessor and still applies the current authority/profile gate. It never falls
back to control-plane key generation when requester history is absent, ambiguous
or inconsistent. Lookup is limited to 64 certificates; exhausted history needs
explicit operator recovery. Old inventories without retained transition CSR and
immutable issuance provenance are not silently upgraded. Connector deployment,
workload possession, certificate installation, restart retention and stock-client
TLS acceptance require their own real observations.

**Journey:** J1
