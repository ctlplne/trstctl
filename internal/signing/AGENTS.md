# AGENTS.md - internal/signing

This package is the logic behind `cmd/trstctl-signer`, the isolated AN-4 signing
process. It is the only process that performs private-key operations, and it is
reached over gRPC on a Unix domain socket or mTLS. A compromise here compromises
the signing root, so changes require signer-level caution.

Read `CLAUDE.md` in this directory for the detailed package-local rules until the
legacy filename is retired. Keep these invariants in your head while editing:

- No HTTP server, SQL driver, NATS client, heavy logging stack, or broad dependency
  surface in the signer.
- Never run signer logic in-process with the control plane; single-node mode still
  launches a child process.
- Private keys never cross the process boundary; RPCs return signatures only.
- Preserve peer authentication, key constraints, and dual-control intent checks.
- The signer proto is wire-sensitive; additive changes need generated code and
  buf compatibility gates.
