# trstctl attested issuance — GitHub Action

Issue a short-lived X.509 certificate from a workflow **without the pipeline
becoming a CA admin**. The workflow proves who it is with its ambient GitHub
OIDC token; trstctl's `github_oidc` attestor verifies issuer, audience, expiry
and (when configured) the allowed repository owners against GitHub's JWKS, and
only then signs. The API token the workflow carries is scoped to
`certs:issue` — it cannot approve, configure, or revoke — and the private key
is generated inside the runner and never leaves it.

## Sample workflow

The first release carrying the bounded/fork-closed Action is `v0.6.0`. Do not
replace it with `main`: the tag is created only by the gated release workflow,
which publishes the Action archive, `SHA256SUMS`, and SLSA provenance. Until
that tag exists in GitHub, the release is not published and this example is
intentionally unavailable.

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
      - uses: ctlplne/trstctl/clients/github-action@v0.6.0
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
The Action also reads GitHub's event document and refuses fork pull requests
before requesting OIDC. That local check is defense in depth; `allowed_owners`
on the server is the signed-token security boundary.

## Reruns and idempotency

The idempotency key binds `GITHUB_RUN_ID`, `GITHUB_JOB`, and `GITHUB_ACTION`;
it deliberately excludes `GITHUB_RUN_ATTEMPT`. A rerun on a fresh runner
creates a different private key, so the server's exact request binding returns
HTTP 409 instead of minting a second certificate or returning a certificate
that does not match the new key. Start a new workflow run when a new credential
is required.

## Verify the released Action

Download these three assets from the same `v0.6.0` GitHub Release:

- `trstctl-github-action-v0.6.0.tar.gz`
- `SHA256SUMS`
- `trstctl-github-action.intoto.jsonl`

Verify the archive digest before inspecting or vendoring it:

```bash
sha256sum -c SHA256SUMS
tar -tzf trstctl-github-action-v0.6.0.tar.gz
```

The release workflow re-runs the full test suite at the exact tag, creates a
deterministic archive from `clients/github-action`, checks its digest, and
publishes SLSA provenance. For maximum pin stability after publication,
resolve `v0.6.0` to its full 40-character commit and use that commit in the
`uses:` line; GitHub accepts the same subdirectory syntax with a commit SHA.
