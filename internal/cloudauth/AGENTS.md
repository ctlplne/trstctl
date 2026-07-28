# AGENTS.md — cloud workload-identity token minter

The root `AGENTS.md` remains canonical. These rules protect the shared cloud-auth
seam created by I-093b9270.

- This package is the one provider-neutral `sign/POST/cache/refresh-before-expiry`
  core beside `internal/cloudhttp`. AWS, GCP, and Azure add only thin wire-format
  encoders. Never build a parallel cache, transport, or bearer-token stack inside a
  provider package.
- A provider exchange may run only from the existing bounded secret-sync outbox
  worker. Callers must supply its durable operation ID. Request/API/configuration
  paths may store reference-only policy, but they may not resolve a workload proof
  or make token-exchange egress.
- Workload proofs and returned secret/token material stay in mutable `[]byte` and
  `internal/crypto/secret.Buffer`, are never logged or persisted, and are explicitly
  destroyed. A cached credential must self-destruct at provider expiry even if the
  source is never used again.
- Validate OIDC proof signatures and exact issuer, audience, subject, expiry, and
  not-before claims through `internal/crypto` before exchange. Collapse failures to
  closed, content-free errors so an attacker-controlled token cannot enter durable
  evidence.
- Air-gap policy is checked before transport and is an honest terminal disabled
  state, not a retry loop. Every exchange is explicitly configured and off by
  default.
- HOMEGROWN standard-library REST is the default because all three existing cloud
  integrations already use `internal/cloudhttp`. A new direct module requires the
  sealed dependency-policy `deps-check` and written why-not-homegrown evidence first.
