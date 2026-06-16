// Package signing holds the signing-service logic and its gRPC-over-UDS
// protocol (AN-4).
//
// This code runs inside the trstctl-signer process, which owns the private-key
// operations and is never run in-process with the control plane. It carries no
// HTTP server, no SQL driver, and a minimal, fully-audited transport
// dependency.
//
// The Server implements the SignerService over the UDS; private keys are held
// as crypto.LockedSigner values (AN-8) and never cross the boundary. Client and
// StartChild are the control-plane side: StartChild launches the signer as a
// child process and Client/RemoteSigner sign through it. See the design at
// docs/design/signing-service.md.
package signing
