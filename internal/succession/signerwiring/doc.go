// SPDX-License-Identifier: BUSL-1.1

// Package signerwiring wires the PCAS succession minter into the isolated AN-4
// signer for production. It constructs a fully-gated minter over a durable epoch
// floor and a real key backend and attaches it via signing.WithSuccessionMinter,
// so a running trstctl-signer actually mints successions (the production
// constructor lands in INT-02). The RPC round-trip across the real signer
// transport — a mint requested by a control-plane client and served by an isolated
// signer process, with no private key crossing the boundary — is proven by the
// integration test in this package (INT-01).
package signerwiring
