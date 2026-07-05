# AGENTS.md - ee/succession/store

Proprietary Enterprise/Provider persistence for PCAS. Every source file carries
`SPDX-License-Identifier: LicenseRef-trstctl-EE`. MPL core must never import this
package outside the tagged ee_attach seam (AN-9).

Package-local rules:

- **AN-1 / RLS is the isolation boundary.** Every table carries `tenant_id` with
  `ENABLE` + `FORCE ROW LEVEL SECURITY` and an isolation policy keyed on
  `current_setting('trstctl.tenant_id')`. Every repository method runs inside the
  core `Store.WithTenant` RLS-scoped transaction; never use `SystemPool` for
  tenant data. A cross-tenant read/write must be denied (`TestRLS_CrossTenantDenied`).
- **Do not fork core.** This package layers on the MPL core store through the
  feature-neutral `store.WithExtraMigrations(fs.FS)` seam and `WithTenant`; it does
  not copy the migration runner or the pool. PCAS DDL ships here as embedded
  `migrations/*.sql`.
- **Reserved migration band.** Extension migrations use versions `>= 900000` so
  they never collide with core migration versions.
- **Serving copy only.** `identity_algorithm_epoch` is the control-plane serving
  high-water; the signer's sealed floor remains the authority (INV-3). The
  store-layer monotonic upsert is defense in depth, not the enforcement point.
