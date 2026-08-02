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

**Journey:** J1
