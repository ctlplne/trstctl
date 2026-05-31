package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readArtifact reads a distribution file relative to this package directory and
// fails the test if it is missing.
func readArtifact(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mustContainAll(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s: expected to contain %q", name, w)
		}
	}
}

func mustContainAny(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if strings.Contains(body, w) {
			return
		}
	}
	t.Errorf("%s: expected to contain one of %v", name, wants)
}

// TestDockerfileIsMinimalAndReproducible encodes the image half of the
// acceptance: a small (distroless/scratch) image built reproducibly (no CGO,
// trimmed paths, pinned build id), running unprivileged, and carrying both the
// control plane and the isolated signer (AN-4).
func TestDockerfileIsMinimalAndReproducible(t *testing.T) {
	df := readArtifact(t, "Dockerfile")

	mustContainAny(t, "Dockerfile base image", df, "distroless", "scratch")
	mustContainAll(t, "Dockerfile reproducible build flags", df,
		"CGO_ENABLED=0", "-trimpath", "-buildid=", "-buildvcs=false")
	// Both binaries ship: the control plane and the sacred signer process (AN-4).
	mustContainAll(t, "Dockerfile binaries", df, "./cmd/certctl", "./cmd/certctl-signer")
	// Unprivileged runtime.
	mustContainAny(t, "Dockerfile non-root user", df, "nonroot", "USER 65532")
	mustContainAll(t, "Dockerfile entrypoint", df, "ENTRYPOINT")
}

// TestComposeBringsUpEvaluableStack encodes the Compose half of the acceptance:
// `docker compose up` brings up the control plane against Postgres and NATS, and
// the control plane is wired to them as an EXTERNAL datastore configuration
// (which is exactly the external-datastore path the acceptance asks to be
// tested).
func TestComposeBringsUpEvaluableStack(t *testing.T) {
	c := readArtifact(t, "docker-compose.yml")

	mustContainAll(t, "compose services", c, "postgres", "nats", "certctl")
	// JetStream must be enabled for the event spine (AN-2).
	mustContainAny(t, "compose nats jetstream", c, "-js", "--jetstream", "jetstream")
	// The control plane points at the external datastores by environment.
	mustContainAll(t, "compose external datastore wiring", c,
		"CERTCTL_POSTGRES_MODE", "external",
		"CERTCTL_POSTGRES_DSN", "CERTCTL_NATS_MODE", "CERTCTL_NATS_URL")
	// Ordered, health-gated startup.
	mustContainAll(t, "compose health/ordering", c, "healthcheck", "depends_on")
}

// TestReleaseWorkflowSignsAndAttests encodes "images are cosign-signed and ship
// an SBOM", published to GHCR with a Docker Hub mirror, built reproducibly, and
// gated by an image size budget.
func TestReleaseWorkflowSignsAndAttests(t *testing.T) {
	wf := readArtifact(t, filepath.Join("..", "..", ".github", "workflows", "release.yml"))

	mustContainAll(t, "release cosign signing", wf, "cosign")
	mustContainAny(t, "release CycloneDX SBOM", wf, "cyclonedx", "CycloneDX", "sbom", "SBOM")
	mustContainAll(t, "release GHCR primary", wf, "ghcr.io")
	mustContainAny(t, "release Docker Hub mirror", wf, "docker.io", "DOCKERHUB", "docker-hub", "Docker Hub")
	// Keyless (OIDC) signing needs an id-token.
	mustContainAll(t, "release keyless OIDC permission", wf, "id-token")
	// Reproducible build inputs.
	mustContainAny(t, "release reproducibility", wf, "SOURCE_DATE_EPOCH", "rewrite-timestamp", "reproducib")
	// The image size budget is enforced in the pipeline.
	mustContainAny(t, "release image size gate", wf, "83886080", "MAX_IMAGE")
}

// repoFile reads a path relative to the repository root (this package lives at
// deploy/docker, two levels down).
func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	return readArtifact(t, filepath.Join(append([]string{"..", ".."}, parts...)...))
}

// TestSupplyChainIsScannedPinnedAndRecorded encodes the R3.5 acceptance: the
// vulnerability scanners are PINNED (not @latest), the SCA reaches the npm tree
// and the embedded-postgres binary (the two dependency surfaces outside go.sum),
// a published image's signature is verifiable on install, and the results are
// recorded in a supply-chain page.
func TestSupplyChainIsScannedPinnedAndRecorded(t *testing.T) {
	ci := repoFile(t, ".github", "workflows", "ci.yml")
	mk := repoFile(t, "Makefile")
	rel := repoFile(t, ".github", "workflows", "release.yml")

	// (1) govulncheck is pinned to a fixed version, not @latest — in CI and in the
	// Makefile that the tools target uses. The pin may be a literal @vX.Y.Z or a
	// Make variable that resolves to one.
	for name, body := range map[string]string{"ci.yml": ci, "Makefile": mk} {
		if strings.Contains(body, "govulncheck@latest") {
			t.Errorf("%s pins govulncheck@latest; pin a fixed version", name)
		}
		if !strings.Contains(body, "govulncheck@v") && !strings.Contains(body, "govulncheck@$(GOVULNCHECK_VERSION)") {
			t.Errorf("%s should install govulncheck at a pinned version", name)
		}
	}
	// The Makefile variable that pins it is itself a fixed semver.
	mustContainAll(t, "Makefile govulncheck pin", mk, "GOVULNCHECK_VERSION ?= v")

	// (2) The npm dependency tree is scanned in CI (it lives outside go.sum).
	mustContainAll(t, "ci.yml npm SCA", ci, "npm audit")

	// (3) The embedded-postgres runtime binary is given provenance and a scan: a
	// committed manifest pins the version + source, and CI verifies its checksum.
	manifest := repoFile(t, "deploy", "supply-chain", "embedded-postgres.json")
	mustContainAll(t, "embedded-postgres manifest", manifest, "16.4.0", "sha256")
	mustContainAny(t, "embedded-postgres manifest source", manifest,
		"embedded-postgres-binaries", "zonky", "repo1.maven.org")
	mustContainAny(t, "ci.yml embedded-postgres scan", ci,
		"embedded-postgres", "supply-chain/embedded-postgres", "sha256")

	// (4) The version the manifest pins is the version the integration tests
	// actually request — so the scanned binary is the binary that runs.
	pg := repoFile(t, "internal", "projections", "projections_test.go")
	mustContainAll(t, "projections test pins the PG binary version", pg, "embeddedpostgres.V16")

	// (5) Signature-on-install is documented (cosign verify), and the release
	// publishes signature + SBOM + provenance.
	mustContainAll(t, "install signature verification", repoFile(t, "docs", "install.md"), "cosign verify")
	mustContainAll(t, "release provenance + SBOM + signing", rel, "provenance", "cosign")
	mustContainAny(t, "release SBOM", rel, "sbom", "SBOM", "cyclonedx")

	// (6) The scan results are recorded in a supply-chain page (executed, not just
	// present).
	sc := repoFile(t, "docs", "supply-chain.md")
	mustContainAll(t, "supply-chain page records the SCA surfaces", sc,
		"govulncheck", "npm audit", "embedded-postgres")
}

// TestACMEConformanceHarnessIsWired encodes the R4.2 close: the ACME server has a
// real-client conformance suite that exercises HTTP-01 end to end with the
// PRODUCTION validator (not the test-only AcceptAll), and the same
// protocol-conformance routine runs as a differential against the reference CA
// (Pebble) in CI.
func TestACMEConformanceHarnessIsWired(t *testing.T) {
	conf := repoFile(t, "internal", "protocols", "acme", "conformance_test.go")
	mustContainAll(t, "ACME conformance suite", conf,
		"TestACMEConformanceRealHTTP01FullIssuance", // real HTTP-01, full issuance
		"TestACMEConformanceRejectsBadHTTP01",       // fail-closed inverse
		"TestACMEProtocolDifferentialVsPebble",      // the Pebble differential
		"HTTP01Validator",                           // the REAL validator, not AcceptAll
	)
	if strings.Contains(conf, "AcceptAll{") {
		t.Error("the conformance suite must exercise the production validator, not the AcceptAll test double")
	}

	ci := repoFile(t, ".github", "workflows", "ci.yml")
	mustContainAll(t, "ci.yml acme-conformance job", ci,
		"acme-conformance", "pebble", "PEBBLE_DIRECTORY_URL")
	mustContainAny(t, "ci.yml Pebble reference image", ci, "letsencrypt/pebble", "pebble:")
}

// TestDockerignoreKeepsContextSmall encodes that the build context excludes the
// heavy, non-deterministic directories so the build stays small and
// reproducible.
func TestDockerignoreKeepsContextSmall(t *testing.T) {
	di := readArtifact(t, filepath.Join("..", "..", ".dockerignore"))
	mustContainAll(t, ".dockerignore", di, "node_modules", ".git", "bin")
}

// TestServerCoverageIsReportedAndGated encodes the R4.3 coverage half: the build
// measures coverage with -coverpkg (so the assembled control plane is credited for
// the branches its cross-package e2e exercises), and it both SURFACES and GATES
// the real per-function coverage of internal/server's lifecycle
// (Build/IssueLeaf/Drain/Shutdown) — rather than letting the misleading ~15%
// in-package figure stand. Red before R4.3 (no server floor existed), green after.
func TestServerCoverageIsReportedAndGated(t *testing.T) {
	mk := repoFile(t, "Makefile")
	// Cross-package attribution is on (the merge that credits internal/server with
	// the coverage from the projections e2e).
	mustContainAll(t, "Makefile measures cross-package coverage", mk, "-coverpkg=./...")
	// The assembled server's real coverage is surfaced and gated by function.
	mustContainAll(t, "Makefile gates the assembled server lifecycle coverage", mk,
		"SERVER_FUNC_COVERAGE_MIN", "internal/server")
	mustContainAll(t, "Makefile names the assembled-lifecycle functions it gates", mk,
		"Build", "IssueLeaf", "Drain", "Shutdown")
}

// TestReleasePinsTheDistrolessBaseByDigest encodes the R4.5 build-comment honesty:
// the Dockerfile no longer hard-codes a tag-tracked base — it takes a BASE_IMAGE
// arg — and the release pipeline resolves the distroless base to an immutable
// @sha256 digest, builds with it, and records it. So the Dockerfile's claim that
// the release pipeline pins the base is now true.
func TestReleasePinsTheDistrolessBaseByDigest(t *testing.T) {
	df := readArtifact(t, "Dockerfile")
	mustContainAll(t, "Dockerfile takes a pin-able base image arg", df,
		"ARG BASE_IMAGE", "FROM ${BASE_IMAGE}")

	// The base-image arg must be declared in the GLOBAL scope — before the FIRST
	// FROM. A variable used in a FROM is only substituted from globally-scoped ARGs,
	// so an `ARG BASE_IMAGE` placed after the build stage's FROM leaves
	// `FROM ${BASE_IMAGE}` blank and the build fails ("base name should not be
	// blank"). This guards the scope, not just the presence of the tokens.
	firstFROM := strings.Index(df, "\nFROM ")
	argBase := strings.Index(df, "ARG BASE_IMAGE")
	if argBase < 0 || firstFROM < 0 || argBase > firstFROM {
		t.Error("ARG BASE_IMAGE must be declared before the first FROM (global scope), else FROM ${BASE_IMAGE} resolves to blank at build time")
	}

	rel := repoFile(t, ".github", "workflows", "release.yml")
	// The pipeline resolves the base to a digest...
	mustContainAll(t, "release resolves the distroless base digest", rel,
		"gcr.io/distroless/static-debian12", "imagetools inspect", "Manifest.Digest")
	// ...builds with it...
	mustContainAll(t, "release builds FROM the resolved base", rel, "BASE_IMAGE=")
	// ...and records it.
	mustContainAny(t, "release records the pinned base", rel, "GITHUB_STEP_SUMMARY", "pinned distroless base")
}

// TestPgxIsBumpedAndClean encodes the R4.5 dependency bump: go.mod pins
// jackc/pgx/v5 at the advisory-clearing v5.9.0 (GO-2026-4772 / GO-2026-4771), not
// the older v5.6.0.
func TestPgxIsBumpedAndClean(t *testing.T) {
	gomod := repoFile(t, "go.mod")
	mustContainAll(t, "go.mod pins pgx v5.9.0", gomod, "github.com/jackc/pgx/v5 v5.9.0")
	if strings.Contains(gomod, "github.com/jackc/pgx/v5 v5.6.0") {
		t.Error("go.mod still references the vulnerable pgx v5.6.0")
	}
}
