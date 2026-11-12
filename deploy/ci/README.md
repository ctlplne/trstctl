# trstctl CBOM import in CI

Two templates run `trstctl-cli cbom scan-source` over a repository and import the
CycloneDX CBOM into trstctl on every pipeline run (X6-L7). Importing the same BOM
again changes nothing, so a pipeline that runs often adds a run only when the code's
crypto changes.

- `github/trstctl-cbom.yml` is a reusable GitHub Actions workflow
  (`on: workflow_call`). Copy it into `.github/workflows/` and call it with
  `trstctl-version`, `server` and the `TRSTCTL_TOKEN` secret; `source` defaults to
  `source:<owner>/<repo>`.
- `gitlab/trstctl-cbom.gitlab-ci.yml` is a GitLab CI job. Include it and set the
  `TRSTCTL_RELEASE_VERSION`, `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` CI/CD variables;
  `CBOM_SOURCE` defaults to `source:<group>/<project>`.

Both install `trstctl-cli` from a published release the way the install guide does:
the archive and manifest are checked against the release's checksums, and the binary
must report the manifest's source commit.

The token needs only `discovery:write`. Mint it for the pipeline, with an expiry:

```sh
cat > ci-token.json <<'JSON'
{"subject": "ci:payments", "scopes": ["discovery:write"], "expires_at": "2027-01-01T00:00:00Z"}
JSON
trstctl-cli access tokens create -f ci-token.json
```

Store it as a masked, protected CI secret (`TRSTCTL_TOKEN`). trstctl's own CI/CD
secret-store syncs can keep it there.
