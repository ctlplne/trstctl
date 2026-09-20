// SPDX-License-Identifier: BUSL-1.1

// Package agent holds the in-network agent's worker logic: certificate and
// credential discovery, deployment to host destinations, SSH trust
// configuration, and drift reconciliation.
//
// Private keys are generated and used locally and never leave the host. This
// package backs the trstctl-agent binary: Agent registers with the control
// plane through an Enroller, renews its own client certificate before it
// expires, heartbeats, and reports inventory findings.
package agent
