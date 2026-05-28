// Package signing holds the signing-service logic and its gRPC-over-UDS
// protocol (AN-4).
//
// This code runs inside the certctl-signer process, which owns the private-key
// operations and is never run in-process with the control plane. It carries no
// HTTP server, no SQL driver, and a minimal, fully-audited transport
// dependency.
//
// Design lands in sprint S1.3 and implementation in S1.4; this file reserves
// the package.
package signing
