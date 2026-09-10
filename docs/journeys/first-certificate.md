# Issue your first certificate

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `built_in_ca`, `identity_requests`, `approvals`, `certificate_inventory`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

This walkthrough now lives in **[Getting started](../getting-started.md)** —
the wizard path and the equivalent CLI path, end to end, including the
issuer-credential step. This page remains as a pointer for existing links.


The served API exposes `GET /api/v1/identities/{id}/issuance-result` for an
accepted issuance. Supply the exact transition `Idempotency-Key` as the required
`request_key` query parameter. The caller needs certificate-read permission and
the identity must belong to its tenant. A `pending` result contains no certificate;
`issued` returns the public leaf and its recorded public chain. This result does
not prove connector deployment, workload key possession, or TLS acceptance.

The transition accepts one public PKCS#10 CSR, at most 64 KiB, with a valid
signature and no additional PEM blocks. An exact
`identity_csr_rejected_before_transition` response is retained for replay with
that request key. A generic error does not authorize starting a new issuance.

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
