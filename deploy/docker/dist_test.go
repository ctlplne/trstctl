package docker

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// TestDockerfileIsMinimalAndReproducible encodes the image half of the acceptance:
// a small (distroless/scratch) image built reproducibly (no CGO, trimmed paths,
// pinned build id), running unprivileged, and carrying the control plane, the
// isolated signer (AN-4), the agent, and the operator.
//
// Behavioural (OPS-008): instead of only substring-matching "./cmd/trstctl-agent",
// this extracts every `./cmd/<bin>` the Dockerfile builds and asserts each names a
// REAL cmd package directory on disk — so the image cannot claim to build a binary
// that does not exist (the OPS-002 unbuilt-image class), and conversely every
// flag-bearing binary a deploy manifest runs must be one the image builds. The
// reproducibility of the resulting binary is proven by a real double-build in
// reproducible_test.go.
func TestDockerfileIsMinimalAndReproducible(t *testing.T) {
	df := readArtifact(t, "Dockerfile")

	mustContainAny(t, "Dockerfile base image", df, "distroless", "scratch")
	mustContainAll(t, "Dockerfile reproducible build flags", df,
		"CGO_ENABLED=0", "-trimpath", "-buildid=", "-buildvcs=false")

	// Extract the ./cmd/<bin> targets the Dockerfile actually builds and assert each
	// resolves to a real package directory (cmd/<bin> with at least one .go file).
	built := dockerfileCmdTargets(df)
	if len(built) == 0 {
		t.Fatal("Dockerfile builds no ./cmd/<binary> targets")
	}
	for _, bin := range built {
		dir := filepath.Join("..", "..", "cmd", bin)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("Dockerfile builds ./cmd/%s, but cmd/%s does not exist (OPS-002: building a phantom binary): %v", bin, bin, err)
			continue
		}
		hasGo := false
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".go") {
				hasGo = true
				break
			}
		}
		if !hasGo {
			t.Errorf("Dockerfile builds ./cmd/%s, but cmd/%s has no .go source", bin, bin)
		}
	}
	// The four flag-bearing/runtime binaries the deploy manifests run MUST be built by
	// the image (so there is no separate, un-built -agent/-operator/-signer image —
	// OPS-002/OPS-004). This binds the Dockerfile to the manifests' entrypoints.
	for _, must := range []string{"trstctl", "trstctl-signer", "trstctl-agent", "trstctl-operator"} {
		if !containsStr(built, must) {
			t.Errorf("Dockerfile does not build ./cmd/%s, but a deploy manifest runs it (OPS-002): the image must carry every binary the manifests reference", must)
		}
	}

	// Unprivileged runtime + an entrypoint.
	mustContainAny(t, "Dockerfile non-root user", df, "nonroot", "USER 65532")
	mustContainAll(t, "Dockerfile entrypoint", df, "ENTRYPOINT")

	// Mutation proof: a Dockerfile line building a non-existent ./cmd/<bin> is detected
	// by the same extractor (the cmd dir would not exist); a real one resolves.
	t.Run("detects_phantom_cmd_target", func(t *testing.T) {
		targets := dockerfileCmdTargets("RUN go build -o /out/x ./cmd/trstctl-does-not-exist")
		if len(targets) != 1 || targets[0] != "trstctl-does-not-exist" {
			t.Fatalf("extractor did not parse the phantom ./cmd target: %v", targets)
		}
		if _, err := os.ReadDir(filepath.Join("..", "..", "cmd", targets[0])); err == nil {
			t.Fatal("cmd/trstctl-does-not-exist unexpectedly exists — adjust the negative probe")
		}
		// And the real target resolves.
		if _, err := os.ReadDir(filepath.Join("..", "..", "cmd", "trstctl")); err != nil {
			t.Errorf("the cmd-target check wrongly failed to resolve the real cmd/trstctl: %v", err)
		}
	})
}

// dockerfileCmdTargets extracts the distinct `<bin>` names from every `./cmd/<bin>`
// reference in a Dockerfile (the build targets).
func dockerfileCmdTargets(df string) []string {
	re := regexp.MustCompile(`\./cmd/([A-Za-z0-9._-]+)`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(df, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// composeFile is the slice of the compose schema this suite drills.
type composeFile struct {
	Services map[string]struct {
		Image       string         `yaml:"image"`
		Entrypoint  []string       `yaml:"entrypoint"`
		Command     yaml.Node      `yaml:"command"`
		Environment map[string]any `yaml:"environment"`
		Volumes     []string       `yaml:"volumes"`
		Ports       []any          `yaml:"ports"`
		DependsOn   map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
		Healthcheck struct {
			Test yaml.Node `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

// TestComposeBringsUpEvaluableStack encodes the Compose half of the acceptance:
// `docker compose up` brings up the control plane against Postgres and NATS, wired
// as an EXTERNAL datastore configuration.
//
// Behavioural (OPS-008): the old version string-matched "postgres", "depends_on",
// "TRSTCTL_POSTGRES_MODE", "external" anywhere in the file — it could pass even if
// the dependency graph was wrong or a flag was undefined. This PARSES the compose
// file and asserts the real structure: the four services exist, NATS runs with
// JetStream, the control plane depends on Postgres+NATS being HEALTHY, every
// TRSTCTL_* env it sets is read by the binary, and every command flag the signer
// and control-plane services pass is a flag the corresponding binary DEFINES (the
// signer/control-plane compose flags were previously unchecked entirely).
func TestComposeBringsUpEvaluableStack(t *testing.T) {
	raw := readArtifact(t, "docker-compose.yml")
	var cf composeFile
	if err := yaml.Unmarshal([]byte(raw), &cf); err != nil {
		t.Fatalf("docker-compose.yml is not valid YAML: %v", err)
	}

	// (1) The evaluation stack must declare the four services.
	for _, want := range []string{"postgres", "nats", "trstctl", "signer"} {
		if _, ok := cf.Services[want]; !ok {
			t.Errorf("docker-compose.yml has no %q service", want)
		}
	}

	// (2) NATS must enable JetStream (the AN-2 event spine), read from the parsed
	// command — not a substring anywhere in the file.
	natsCmd := nodeToStrings(cf.Services["nats"].Command)
	if !anyContains(natsCmd, "jetstream") && !anyContains(natsCmd, "-js") {
		t.Errorf("nats service command %v does not enable JetStream (AN-2)", natsCmd)
	}

	// (3) The control plane must wait for Postgres AND NATS to be HEALTHY before
	// starting (the ordered, health-gated startup), as parsed depends_on conditions.
	cp := cf.Services["trstctl"]
	for _, dep := range []string{"postgres", "nats"} {
		d, ok := cp.DependsOn[dep]
		if !ok {
			t.Errorf("trstctl service does not depend_on %q", dep)
			continue
		}
		if d.Condition != "service_healthy" {
			t.Errorf("trstctl depends_on %q with condition %q, want service_healthy (health-gated startup)", dep, d.Condition)
		}
	}

	// (4) The control plane points at the external datastores, asserted on the parsed
	// env VALUES (mode=external), and every TRSTCTL_* key it sets is one the binary
	// reads (reconciled against the config loader).
	known := composeLoaderKeys(t)
	env := cp.Environment
	if asEnvString(env["TRSTCTL_POSTGRES_MODE"]) != "external" {
		t.Errorf("trstctl TRSTCTL_POSTGRES_MODE = %q, want external", asEnvString(env["TRSTCTL_POSTGRES_MODE"]))
	}
	if asEnvString(env["TRSTCTL_NATS_MODE"]) != "external" {
		t.Errorf("trstctl TRSTCTL_NATS_MODE = %q, want external", asEnvString(env["TRSTCTL_NATS_MODE"]))
	}
	for k := range env {
		if strings.HasPrefix(k, "TRSTCTL_") && !known[k] {
			t.Errorf("compose trstctl service sets %s, which the config loader does not read (phantom env, OPS-008)", k)
		}
	}

	// (5) Every flag the signer + control-plane services pass must be defined by the
	// corresponding binary (the compose flags were previously unchecked). The control
	// plane uses --health-check in its healthcheck; the signer uses --socket/--keystore/--kek.
	signerFlags := binaryHelpFlags(t, "trstctl-signer")
	for _, fl := range commandFlagNames(nodeToStrings(cf.Services["signer"].Command)) {
		if !signerFlags[fl] {
			t.Errorf("compose signer service passes --%s, which trstctl-signer does not define (real: %v)", fl, sortedHelpKeys(signerFlags))
		}
	}
	cpFlags := binaryHelpFlags(t, "trstctl")
	for _, fl := range commandFlagNames(nodeToStrings(cp.Healthcheck.Test)) {
		if !cpFlags[fl] {
			t.Errorf("compose trstctl healthcheck passes --%s, which the trstctl binary does not define (real: %v)", fl, sortedHelpKeys(cpFlags))
		}
	}

	// Mutation proof: an injected phantom env key and an undefined command flag are
	// both rejected; the real ones pass.
	t.Run("rejects_phantom_env_and_flag", func(t *testing.T) {
		if known["TRSTCTL_KMS_PROVIDER"] {
			t.Fatal("config loader unexpectedly knows TRSTCTL_KMS_PROVIDER — adjust the negative probe")
		}
		if !known["TRSTCTL_POSTGRES_MODE"] {
			t.Error("the loader-key check wrongly rejected the real TRSTCTL_POSTGRES_MODE")
		}
		if signerFlags["totally-made-up"] {
			t.Fatal("trstctl-signer unexpectedly defines --totally-made-up — adjust the negative probe")
		}
		if !signerFlags["socket"] {
			t.Error("the flag-vs-binary check wrongly rejected the real signer --socket flag")
		}
	})
}

// TestComposeSignerIsSeparateService locks ARCH-005's Docker topology: the eval
// stack must keep the signer as its own process/service, not fold private-key
// custody back into the control plane. The only shared signing channel is the UDS
// volume mounted at /run/trstctl, and the control plane must explicitly dial it as
// an external signer.
func TestComposeSignerIsSeparateService(t *testing.T) {
	raw := readArtifact(t, "docker-compose.yml")
	var cf composeFile
	if err := yaml.Unmarshal([]byte(raw), &cf); err != nil {
		t.Fatalf("docker-compose.yml is not valid YAML: %v", err)
	}

	signer, ok := cf.Services["signer"]
	if !ok {
		t.Fatal("docker-compose.yml has no separate signer service (AN-4)")
	}
	cp, ok := cf.Services["trstctl"]
	if !ok {
		t.Fatal("docker-compose.yml has no control-plane service")
	}

	if ep := strings.Join(signer.Entrypoint, " "); !strings.Contains(ep, "/usr/local/bin/trstctl-signer") {
		t.Errorf("signer entrypoint = %q, want the isolated trstctl-signer binary", ep)
	}
	if !containsStr(nodeToStrings(signer.Command), "--socket=/run/trstctl/signer.sock") {
		t.Errorf("signer command %v does not bind the shared UDS socket", nodeToStrings(signer.Command))
	}
	if len(signer.Ports) != 0 {
		t.Errorf("signer service exposes ports %v; Compose AN-4 topology should use only the shared UDS", signer.Ports)
	}

	dep, ok := cp.DependsOn["signer"]
	if !ok {
		t.Fatal("control-plane service does not depend on the separate signer service")
	}
	if dep.Condition != "service_started" {
		t.Errorf("control-plane depends_on signer condition = %q, want service_started", dep.Condition)
	}
	if asEnvString(cp.Environment["TRSTCTL_SIGNER_MODE"]) != "external" {
		t.Errorf("TRSTCTL_SIGNER_MODE = %q, want external", asEnvString(cp.Environment["TRSTCTL_SIGNER_MODE"]))
	}
	if asEnvString(cp.Environment["TRSTCTL_SIGNER_SOCKET"]) != "/run/trstctl/signer.sock" {
		t.Errorf("TRSTCTL_SIGNER_SOCKET = %q, want /run/trstctl/signer.sock", asEnvString(cp.Environment["TRSTCTL_SIGNER_SOCKET"]))
	}

	if _, ok := cf.Volumes["signersock"]; !ok {
		t.Fatal("compose file does not declare the shared signersock volume")
	}
	if _, ok := cf.Volumes["signerkeys"]; !ok {
		t.Fatal("compose file does not declare the signerkeys custody volume")
	}
	if !hasComposeVolumeMount(signer.Volumes, "signersock", "/run/trstctl") {
		t.Errorf("signer volumes %v do not mount signersock at /run/trstctl", signer.Volumes)
	}
	if !hasComposeVolumeMount(cp.Volumes, "signersock", "/run/trstctl") {
		t.Errorf("control-plane volumes %v do not mount signersock at /run/trstctl", cp.Volumes)
	}
	if !hasComposeVolumeMount(signer.Volumes, "signerkeys", "/data/signer") {
		t.Errorf("signer volumes %v do not mount signerkeys at /data/signer", signer.Volumes)
	}
	if hasComposeVolume(cp.Volumes, "signerkeys") {
		t.Errorf("control-plane volumes %v must not mount the signer's key-custody volume", cp.Volumes)
	}
}

// nodeToStrings flattens a compose command/test field, which YAML may model as a
// single string or a sequence of strings, into a string slice.
func nodeToStrings(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		// A shell-form command string: split on whitespace.
		return strings.Fields(n.Value)
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	}
	return nil
}

func hasComposeVolumeMount(volumes []string, volume, mountPath string) bool {
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && parts[0] == volume && parts[1] == mountPath {
			return true
		}
	}
	return false
}

func hasComposeVolume(volumes []string, volume string) bool {
	for _, v := range volumes {
		if strings.Split(v, ":")[0] == volume {
			return true
		}
	}
	return false
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func asEnvString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// commandFlagNames extracts long-flag names from a command token list.
func commandFlagNames(tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if !strings.HasPrefix(tok, "--") {
			continue
		}
		name := strings.TrimLeft(tok, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// binaryHelpFlags runs `go run ./cmd/<bin> --help` from the repo root (two levels up
// from deploy/docker) and returns its real flag set.
func binaryHelpFlags(t *testing.T, bin string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/"+bin, "--help")
	cmd.Dir = filepath.Join("..", "..")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	_ = cmd.Run()
	re := regexp.MustCompile(`(?m)^\s+-([A-Za-z][\w-]*)`)
	flags := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(out.String(), -1) {
		flags[m[1]] = true
	}
	if len(flags) == 0 {
		t.Fatalf("could not parse flags from `go run ./cmd/%s --help`:\n%s", bin, out.String())
	}
	return flags
}

// composeLoaderKeys parses internal/config/config.go for the TRSTCTL_* keys the
// loader reads — the binary's env contract.
func composeLoaderKeys(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	re := regexp.MustCompile(`set(?:String|Bool|BoolPtr|Int|CSV)\(getenv,\s*"(TRSTCTL_[A-Z0-9_]+)"`)
	keys := map[string]bool{"TRSTCTL_CONFIG_FILE": true}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		keys[m[1]] = true
	}
	if len(keys) < 10 {
		t.Fatalf("parsed only %d loader keys — extractor broken", len(keys))
	}
	return keys
}

func sortedHelpKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

// TestPatchedGoToolchainPinned keeps the build and release toolchain on the
// patched Go line recorded by SUPPLY-001. A vulnerable standard library is still
// reachable if only local developer machines move forward while Docker, CI, or
// source-build docs lag behind.
func TestPatchedGoToolchainPinned(t *testing.T) {
	const patched = "1.26.4"

	gomod := repoFile(t, "go.mod")
	mustContainAll(t, "go.mod pins patched toolchain", gomod,
		"go 1.26.0", "toolchain go"+patched)

	dockerfile := repoFile(t, "deploy", "docker", "Dockerfile")
	mustContainAll(t, "Dockerfile pins patched Go build image", dockerfile,
		"ARG GO_VERSION="+patched)

	ci := repoFile(t, ".github", "workflows", "ci.yml")
	rel := repoFile(t, ".github", "workflows", "release.yml")
	mustContainAll(t, "ci.yml uses go.mod toolchain", ci, "go-version-file: go.mod")
	mustContainAll(t, "release.yml uses go.mod toolchain", rel, "go-version-file: go.mod")

	mustContainAll(t, "README advertises patched Go floor", repoFile(t, "README.md"), "Go-"+patched+"+", "Go "+patched+"+")
	mustContainAll(t, "getting started advertises patched Go floor", repoFile(t, "docs", "getting-started.md"), "Go\n  "+patched+"+")
	mustContainAll(t, "install advertises patched Go floor", repoFile(t, "docs", "install.md"), "Go "+patched+"+")
	mustContainAll(t, "supply-chain records patched Go scanner receipt", repoFile(t, "docs", "supply-chain.md"), "go"+patched, "0 vulnerabilities")
}

func TestProductionInstallPathsAvoidMutableLatest(t *testing.T) {
	forbidden := regexp.MustCompile(`ghcr\.io/imfeelingtheagi/trstctl:latest|(?m)^\s*image:\s+.*:latest\b`)
	for _, path := range []string{
		"README.md",
		"deploy/docker/docker-compose.yml",
		"deploy/docker/README.md",
		"deploy/kubernetes/daemonset.yaml",
		"deploy/operator/operator.yaml",
		"docs/install.md",
		"docs/uninstall.md",
	} {
		if body := repoFile(t, strings.Split(path, "/")...); forbidden.MatchString(body) {
			t.Errorf("%s still contains a mutable production image reference", path)
		}
	}
	mustContainAll(t, "Sigstore admission policy", repoFile(t, "deploy", "kubernetes", "sigstore-policy.yaml"),
		"ClusterImagePolicy",
		"ghcr.io/imfeelingtheagi/trstctl@sha256:*",
		"https://token.actions.githubusercontent.com",
		"release.yml")
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
	mustContainAll(t, "embedded-postgres scanner receipt policy", manifest,
		"receiptArtifact", "embedded-postgres-trivy-receipt", "failOnFixableCritical", "lastResult")
	if strings.Contains(manifest, "pending first CI run") {
		t.Fatal("embedded-postgres manifest still says the scanner receipt is pending")
	}
	mustContainAny(t, "embedded-postgres manifest source", manifest,
		"embedded-postgres-binaries", "zonky", "repo1.maven.org")
	mustContainAll(t, "ci.yml embedded-postgres scan receipt", ci,
		"TRSTCTL_EMBEDDED_PG_SCAN_DIR", "embedded-postgres-trivy-receipt", "if-no-files-found: error")
	verifyPG := repoFile(t, "scripts", "supply-chain", "verify-embedded-postgres.sh")
	mustContainAll(t, "embedded-postgres Docker Trivy DB receipt path", verifyPG,
		`trivy_cache="$archWorkdir/trivy-cache"`,
		`-v "${trivy_cache}:/root/.cache/trivy"`,
		`-v "${trivy_cache}:/root/.cache/trivy:ro" "$TRIVY_IMAGE" --version >"$trivy_version_out"`)

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
		"govulncheck", "npm audit", "embedded-postgres", "Trivy version/DB metadata")
}

func TestEmbeddedPostgresScanReceiptPolicySelfTest(t *testing.T) {
	cmd := exec.Command("bash", filepath.Join("scripts", "supply-chain", "embedded-postgres-scan-receipt_selftest.sh"))
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded-postgres scan receipt self-test failed: %v\n%s", err, out)
	}
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
	if strings.Contains(di, "internal/webui/dist/assets") {
		t.Fatal(".dockerignore must not exclude internal/webui/dist/assets: Docker builds embed the served React bundles from that directory")
	}
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
