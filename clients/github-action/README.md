# trstctl attested issuance — GitHub Action

Issue a short-lived X.509 certificate from a workflow **without the pipeline
becoming a CA admin**. The workflow proves who it is with its ambient GitHub
OIDC token; trstctl's `github_oidc` attestor verifies issuer, audience, expiry
and (when configured) the allowed repository owners against GitHub's JWKS, and
only then signs. The API token the workflow carries is scoped to
`certs:issue` — it cannot approve, configure, or revoke — and the private key
is generated inside the runner and never leaves it.

## Sample workflow

```yaml
name: issue-deploy-cert
on: [push]
permissions:
  id-token: write   # what makes the OIDC token available
  contents: read
jobs:
  issue:
    runs-on: ubuntu-latest
    steps:
      - uses: <owner>/trstctl/clients/github-action@main
        id: cert
        with:
          url: https://trstctl.example.com
          token: ${{ secrets.TRSTCTL_CI_TOKEN }}   # scoped to certs:issue only
          audience: trstctl
          ttl-seconds: "900"
      - run: openssl x509 -in "${{ steps.cert.outputs.certificate }}" -noout -subject -dates
```

## Server-side setup

1. Configure a `github_oidc` attestation source (`attested_issuance` config
   block): issuer `https://token.actions.githubusercontent.com`, the audience
   your workflows request, and — recommended — `allowed_owners` pinning your
   GitHub organization. An unpinned source attests every repository on GitHub.
2. Mint an API token scoped to `certs:issue` and store it as a repository or
   organization secret. The scope is the point: the OIDC attestation names the
   workflow, and the token authorizes nothing but issuance.

## What the attestation binds

The issued SVID's identity comes from the VERIFIED token claims — repository,
ref, workflow — not from anything the workflow asserts about itself. A fork
cannot impersonate the upstream repository: its token carries its own
`repository` claim, and an `allowed_owners` pin refuses it outright.
