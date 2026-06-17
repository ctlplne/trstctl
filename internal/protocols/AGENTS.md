# AGENTS.md - internal/protocols

This tree contains the protocol servers that parse untrusted issuance and
enrollment traffic: ACME/ARI, EST, SCEP, CMP, SPIFFE, and SSH. Treat every request
body and wire field as attacker-controlled.

Read `CLAUDE.md` in this directory for the detailed package-local rules until the
legacy filename is retired. Keep these invariants in your head while editing:

- Every untrusted parser needs fuzz coverage, property tests, and committed seeds.
- Keep differential tests against reference tools where they exist; do not remove a
  reference test just to make a local run green.
- Fail closed on malformed, oversized, unauthenticated, or tenantless requests.
- All signing routes through `internal/crypto` and the isolated signer process.
- Keep docs honest about what is served by the assembled control-plane listener.
