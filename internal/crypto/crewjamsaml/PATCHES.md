# Local SAML parser patch (CR-651)

This nested Go module is the runtime source of `github.com/crewjam/saml` v0.5.1,
fetched through `proxy.golang.org` and checked by the root `go.sum` entry
`h1:g+mfp0CrLuLRZCK793PgJcZeg5dS/0CDwoeAX2zcwNI=`. Its upstream BSD-2-Clause
`LICENSE` stays with it. The root `go.mod` replaces that exact module with this
directory so shipped binaries execute the patched source.

Parser changes touch four upstream Go files:

- `schema.go` decodes `Subject.NameID` only from the SAML assertion namespace.
  It keeps the original marshal shape so signed artifact fixtures still match.
- `service_provider.go` rejects missing assertion, subject, conditions,
  confirmation data, signed XML root, and logout response issuer before reading
  them.
- `xmlenc/gcm.go` refuses ciphertext shorter than the nonce.
- `xmlenc/cbc.go` refuses a missing or partial encrypted block.

Repository integration also labels the upstream debt comments with the local
security owner, replaces old gosec suppression comments with registered
`#nosec` reasons for fixed protocol constants and legacy digest support, and
keeps the runtime source under the repository's architecture checks. These
comment-only adaptations do not change parser behavior.

The full patched upstream source, tests, examples, and fixtures are retained in
`../r2/evidence/crewjamsaml-v0.5.1-patched-tests.tar.gz` (SHA-256
`012307ea4e17f01a6cff5fb45c477f7cb6f7536dc3569e3f6facfa90e6912414`).
The upstream suite passed in that complete tree. Its tests and fixtures stay in
the workspace archive because they include published example private keys and
token strings that the repository's Gitleaks gate correctly detects. The
shipped source copy contains the runtime packages and upstream license; no
scanner rule or test assertion was changed. Two archived upstream fixture
files have trailing spaces removed for `git diff --check`.

The root regressions `TestCR651*` send signed assertions and malformed encrypted
responses through `internal/crypto/samlsp`. They fail against the untouched
v0.5.1 source and pass against this module. Run
`go test ./internal/crypto/samlsp` from the repository root, and extract the
retained archive into a private temporary directory to rerun its full upstream
`go test ./...` suite.
`make vuln` remains enabled without exclusions. A local module replacement has
no upstream fixed-version metadata for govulncheck, so the direct regression
tests and the four-file parser source diff are required alongside its scan result.
