// Package agent holds the in-network agent's worker logic: certificate and
// credential discovery, deployment to host destinations, SSH trust
// configuration, and drift reconciliation.
//
// Private keys are generated and used locally and never leave the host. This
// package backs the certctl-agent binary; implementation begins in sprint S5.1.
package agent
