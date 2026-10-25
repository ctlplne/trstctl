// SPDX-License-Identifier: BUSL-1.1

package projections

// EventRevocationProbeRequested records an operator's request to probe the
// tenant's CRL and OCSP endpoints now (who asked, and the request's bucket).
// It is audit evidence: the read model is unchanged until the relay's signed
// observations project as revocation.health.observed.
const EventRevocationProbeRequested = "revocation.probe.requested"
