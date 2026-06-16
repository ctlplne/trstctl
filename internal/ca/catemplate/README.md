# CA plugin template

Every trstctl CA plugin satisfies the same `ca.CA` interface and rides the same
issuance rails (idempotency AN-5, outbox AN-6, via `ca.IssuanceService`). The
only thing that differs between authorities is *how a CSR is sent upstream to be
signed*. This package factors out everything else so a new CA is a small,
near-identical change — the structure first established by the Let's Encrypt
plugin (S4.3) and extracted here (S4.6).

## The seam you implement

```go
type Backend interface {
    CAName() string
    Issue(ctx context.Context, req ca.IssueRequest) (chainPEM []byte, err error)
}
```

`Issue` submits `req.CSR` to your CA (authorizing `req.DNSNames`, requesting
`req.TTL` where the CA honours it) and returns the issued chain, leaf first, PEM.
That is the only CA-specific code you write.

The template's `Plugin` (from `New(backend)`) contributes the rest: implementing
`ca.CA`, rejecting an empty CSR, parsing the chain, extracting the serial and
expiry, labelling the issuer, and wrapping errors.

## Adding a CA plugin

1. **Copy the scaffold.** Copy `internal/ca/example` to
   `internal/ca/<your-ca>` and rename the package.
2. **Fill in the backend.** Replace the local-authority `backend.Issue` with a
   call to your CA's API (ACME finalize, a REST enrollment endpoint, a cloud SDK,
   DCOM/RPC, …). Keep any client/credentials on the `backend` struct. Build CSRs
   and handle key material only through `internal/crypto` (AN-3/AN-8); never
   import `crypto/*` directly.
3. **Self-validate.** Run the shared conformance suite against your plugin
   (wired to your CA or a faithful test double):

   ```go
   report := catemplate.Conformance(ctx, plugin)
   if !report.OK() { /* inspect report.Checks */ }
   ```

   The suite checks that the plugin names itself, issues a real certificate for a
   requested identifier (chain parses, carries the SAN), reports a serial and a
   future expiry, and rejects a malformed request.
4. **Ride the rails.** Construct your plugin and pass it to
   `ca.NewIssuanceService(plugin, idem, outbox, store)` — issuance is then
   idempotent and recorded in the outbox exactly as for every other CA, with no
   plugin-specific work.

See `internal/ca/example` for a complete, conformance-passing reference and
`internal/ca/letsencrypt` for a real ACME implementation of the same seam.
