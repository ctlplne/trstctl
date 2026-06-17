# AGENTS.md - internal/crypto

This is the AN-3 cryptography boundary. It is the only tree allowed to import the
standard library `crypto/*` packages or third-party crypto implementations. All
X.509, SSH, JOSE/JWS, PQC, sealing, and timestamping operations route through the
interfaces in this package.

Read `CLAUDE.md` in this directory for the detailed package-local rules until the
legacy filename is retired. Keep these invariants in your head while editing:

- Add algorithms or backends here; do not fork a parallel crypto path elsewhere.
- Keep secret and key material in byte-backed, locked, zeroized buffers, never in
  `string`.
- Fuzz every parser that touches untrusted bytes and keep committed seed corpora.
- Ask before changing custody boundaries such as live HSM/KMS placement.
