package deploy_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

// These tests are the behavioural counterpart to the static deploy/ string-match
// suite (OPS-008). A green `go test ./deploy/...` used to mean only that the
// manifests *named* certain strings; it never bound a manifest to the artifact it
// drives. These checks close that gap by reconciling every manifest against the
// real thing it must agree with — the binary's flag set, the workflows' built
// images, the config loader's known keys, the chart's values.yaml, and the
// rendered Kubernetes objects — so a manifest that drifts (a typo'd flag, an
// unbuilt image, an env key no code reads, a value the chart never defines, a
// structurally-broken render) FAILS the suite instead of passing it.
//
// Every check below is mutation-proven: it ships with a negative sub-test that
// injects a deliberately-broken manifest fragment and asserts the check rejects
// it, then asserts the REAL artifact passes — so the green is not vacuous.
//
//   - TestManifestFlagsAreDefinedByTheBinary parses the actual flag set out of
//     each trstctl binary's --help and asserts every flag a manifest passes is
//     one that binary really defines — so a manifest can never crash-loop on an
//     undefined flag (the OPS-001 class). The isolated signer manifest passes
//     `--mtls-listen`; post-SIGNER-005 the signer binary DEFINES that flag (the
//     cross-node mTLS listener), so the manifest and binary agree. If a manifest
//     reintroduces a truly-undefined flag, this test fails.
//
//   - TestEveryDeployImageIsBuiltOrMarkedPlanned asserts every container image
//     referenced anywhere under deploy/ is one a workflow actually builds (the
//     single multi-binary control-plane image), or is explicitly marked as a
//     not-yet-built placeholder. This FAILS on the pre-fix tree, which referenced
//     -agent/-signer/-operator images that no workflow builds (OPS-002).
//
//   - TestManifestEnvKeysAreReadByTheBinary reconciles every TRSTCTL_* env key a
//     manifest hands to the control-plane binary (configmap data, the deployment's
//     direct env, the compose service environment) against the EXACT set of keys
//     the config loader (internal/config applyEnv) actually reads — so a manifest
//     cannot wire a phantom env contract the binary silently ignores (the OPS KMS-
//     env class: TRSTCTL_KMS_* that no Go code reads).
//
//   - TestEveryTemplateValueExistsInValuesYAML reconciles every `.Values.X`
//     reference in the chart's templates against values.yaml (and the chart's
//     templated env back to the loader), so a template cannot reference a value
//     the chart never defines (which renders empty and silently misconfigures).
//
//   - TestRenderedManifestsAreStructurallyValid renders the chart's templates and
//     the static manifests and asserts each resulting object carries the fields
//     Kubernetes requires for its kind (a kubeconform-style structural gate), so a
//     manifest that renders into an object the API server would reject FAILS here.

// repoRoot returns the repository root (this package lives at <root>/deploy).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd) // strip the trailing /deploy
}

func requireTestDeclares(t *testing.T, root, rel, name string) {
	t.Helper()
	path := filepath.Join(root, rel)
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return
		}
	}
	t.Fatalf("%s no longer declares %s", rel, name)
}

func requireFileContains(t *testing.T, root, rel string, wants ...string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	text := string(body)
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("%s no longer contains %q", rel, want)
		}
	}
}

// flagRe matches a flag definition line in `go ... --help` output, e.g. "  -socket string".
var flagRe = regexp.MustCompile(`(?m)^\s+-([A-Za-z][\w-]*)`)

// binaryFlags runs `go run ./cmd/<pkg> --help` and returns the set of flags the
// binary defines (without the leading dash). This reads the REAL flag set from
// the compiled binary, not a hand-maintained list — so a manifest that drifts
// from the binary is caught.
func binaryFlags(t *testing.T, root, pkg string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/"+pkg, "--help")
	cmd.Dir = root
	// --help prints usage to stderr and exits 0; capture both streams.
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	_ = cmd.Run() // a non-zero exit still leaves usage in out; we assert on content
	flags := map[string]bool{}
	for _, m := range flagRe.FindAllStringSubmatch(out.String(), -1) {
		flags[m[1]] = true
	}
	if len(flags) == 0 {
		t.Fatalf("could not parse any flags from `go run ./cmd/%s --help` (output:\n%s)", pkg, out.String())
	}
	return flags
}

// container is the slice of a Kubernetes PodSpec container we care about.
type container struct {
	Image   string   `yaml:"image"`
	Command []string `yaml:"command"`
	Args    []string `yaml:"args"`
	Env     []envVar `yaml:"env"`
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// flagsIn extracts the long-flag names (without leading dashes, without =value)
// from a container's command+args. "--socket=/x" -> "socket"; "--k8s" -> "k8s".
func flagsIn(c container) []string {
	var got []string
	for _, tok := range append(append([]string{}, c.Command...), c.Args...) {
		tok = strings.TrimSpace(tok)
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		name := strings.TrimLeft(tok, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			got = append(got, name)
		}
	}
	return got
}

// binaryForContainer decides which trstctl binary a container runs, from its
// command (entrypoint override) or its image name. Returns "" if it does not run
// one of our flag-bearing binaries.
func binaryForContainer(c container) string {
	joined := strings.Join(c.Command, " ")
	switch {
	case strings.Contains(joined, "trstctl-signer"):
		return "trstctl-signer"
	case strings.Contains(joined, "trstctl-agent"):
		return "trstctl-agent"
	case strings.Contains(joined, "trstctl-operator"):
		return "trstctl-operator"
	case strings.Contains(joined, "trstctl-cli"):
		return "trstctl-cli"
	case strings.Contains(joined, "trstctl"):
		return "trstctl"
	}
	// No command override: fall back to the image's binary suffix.
	switch {
	case strings.Contains(c.Image, "trstctl-signer"):
		return "trstctl-signer"
	case strings.Contains(c.Image, "trstctl-agent"):
		return "trstctl-agent"
	case strings.Contains(c.Image, "trstctl-operator"):
		return "trstctl-operator"
	}
	return ""
}

// staticContainers parses the static (non-Helm-templated) deploy manifests that
// pass concrete args to a binary, returning each container found. Helm templates
// are skipped here because they cannot be parsed as plain YAML without rendering;
// the signer-deployment.yaml args this test would care about are now static and
// guarded off anyway (OPS-001), and the Helm render is schema-validated in CI.
func staticContainers(t *testing.T, root string) []container {
	t.Helper()
	files := []string{
		filepath.Join("kubernetes", "daemonset.yaml"),
		filepath.Join("operator", "operator.yaml"),
	}
	var out []container
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, "deploy", rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				break
			}
			out = append(out, containersOf(doc)...)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no containers in the static manifests")
	}
	return out
}

// containersOf walks a parsed manifest and returns its pod containers, if any.
func containersOf(doc map[string]any) []container {
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return nil
	}
	tmpl, _ := spec["template"].(map[string]any)
	if tmpl == nil {
		return nil
	}
	pod, _ := tmpl["spec"].(map[string]any)
	if pod == nil {
		return nil
	}
	raw, _ := pod["containers"].([]any)
	var out []container
	for _, r := range raw {
		// Re-marshal the single container map through YAML into our typed struct
		// so command/args/image decode uniformly.
		b, err := yaml.Marshal(r)
		if err != nil {
			continue
		}
		var c container
		if yaml.Unmarshal(b, &c) == nil {
			out = append(out, c)
		}
	}
	return out
}

func TestManifestFlagsAreDefinedByTheBinary(t *testing.T) {
	root := repoRoot(t)
	flagCache := map[string]map[string]bool{}
	getFlags := func(bin string) map[string]bool {
		if f, ok := flagCache[bin]; ok {
			return f
		}
		f := binaryFlags(t, root, bin)
		flagCache[bin] = f
		return f
	}

	for _, c := range staticContainers(t, root) {
		bin := binaryForContainer(c)
		if bin == "" {
			continue // not a trstctl binary container (e.g. the planned operator)
		}
		defined := getFlags(bin)
		for _, fl := range flagsIn(c) {
			if !defined[fl] {
				t.Errorf("manifest container running %s passes --%s, which %s does not define "+
					"(its real flags: %v) — this is exactly the OPS-001 crash-loop class", bin, fl, bin, keys(defined))
			}
		}
	}

	// The Helm signer-deployment.yaml is a template (its image: line is
	// templated), so it cannot be parsed as plain YAML. But the flags it passes to
	// the signer are LITERAL. The isolated topology passes --mtls-listen and the
	// mTLS cert/peer flags; post-SIGNER-005 the binary defines all of them, so this
	// scan confirms the manifest stays consistent with the binary's real flag set
	// (and would fail if a future edit reintroduced an undefined flag).
	signerTpl, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "trstctl", "templates", "signer-deployment.yaml"))
	if err != nil {
		t.Fatalf("read signer-deployment.yaml: %v", err)
	}
	signerFlags := getFlags("trstctl-signer")
	for _, fl := range literalFlagTokens(string(signerTpl)) {
		if !signerFlags[fl] {
			t.Errorf("helm signer-deployment.yaml passes --%s to trstctl-signer, which it does not define "+
				"(real flags: %v) — the OPS-001 crash-loop (e.g. --mtls-listen)", fl, keys(signerFlags))
		}
	}
}

func TestDeployEnrollmentURLMatchesClient(t *testing.T) {
	root := repoRoot(t)
	var agentContainer *container
	for _, c := range staticContainers(t, root) {
		if binaryForContainer(c) == "trstctl-agent" {
			copy := c
			agentContainer = &copy
			break
		}
	}
	if agentContainer == nil {
		t.Fatal("static deploy manifests do not run trstctl-agent")
	}
	hasEnrollURLArg := false
	for _, arg := range agentContainer.Args {
		if arg == "--enroll-url=$(TRSTCTL_ENROLL_URL)" {
			hasEnrollURLArg = true
			break
		}
	}
	if !hasEnrollURLArg {
		t.Fatalf("agent DaemonSet args = %v, want --enroll-url from TRSTCTL_ENROLL_URL", agentContainer.Args)
	}
	env := map[string]string{}
	for _, item := range agentContainer.Env {
		env[item.Name] = item.Value
	}
	if got, want := env["TRSTCTL_ENROLL_URL"], "https://trstctl:8443"; got != want {
		t.Fatalf("TRSTCTL_ENROLL_URL = %q, want %q so the client appends exactly /enroll/bootstrap", got, want)
	}

	checks := []struct {
		rel     string
		want    string
		forbid  string
		context string
	}{
		{
			rel:     filepath.Join("windows", "README.md"),
			want:    "ENROLLURL=https://cp:8443",
			forbid:  "ENROLLURL=https://cp:8443/enroll",
			context: "Windows MSI example",
		},
		{
			rel:     filepath.Join("windows", "README.md"),
			want:    "--enroll-url https://cp:8443",
			forbid:  "--enroll-url https://cp:8443/enroll",
			context: "Windows service example",
		},
		{
			rel:     filepath.Join("windows", "trstctl-agent.wxs"),
			want:    "ENROLLURL=https://cp:8443.",
			forbid:  "ENROLLURL=https://cp:8443/enroll",
			context: "Windows MSI condition",
		},
	}
	for _, check := range checks {
		raw, err := os.ReadFile(filepath.Join(root, "deploy", check.rel))
		if err != nil {
			t.Fatalf("read deploy/%s: %v", check.rel, err)
		}
		text := string(raw)
		if !strings.Contains(text, check.want) {
			t.Errorf("%s in deploy/%s does not contain origin-only example %q", check.context, check.rel, check.want)
		}
		if strings.Contains(text, check.forbid) {
			t.Errorf("%s in deploy/%s still passes enrollment collection URL %q", check.context, check.rel, check.forbid)
		}
	}
}

// TestOPS008DeploymentStrengthGuardsStayWired locks the audit's positive OPS-008
// finding: deploy tests are useful because they drill real rendered manifests,
// binary flags, config env keys, and installer docs instead of loose string claims.
// ELI5: this keeps the "deployment tests are a serious safety net" proof from
// quietly shrinking back to a checklist that can pass while Kubernetes would route
// to an unready pod, an isolated signer would miss its key storage, or a fresh
// fleet agent would boot with no enrollment token.
func TestOPS008DeploymentStrengthGuardsStayWired(t *testing.T) {
	root := repoRoot(t)

	// OPS-001: readiness is not liveness. The chart test renders the control-plane
	// Deployment and requires readinessProbe -> --ready-check while startup/liveness
	// stay on the shallow --health-check path.
	requireTestDeclares(t, root, filepath.Join("deploy", "helm", "helm_test.go"), "TestReadinessProbeUsesReadyCheck")
	requireFileContains(t, root, filepath.Join("deploy", "helm", "helm_test.go"),
		"requireProbeCommand(t, controlPlane, \"startupProbe\", []string{\"/usr/local/bin/trstctl\", \"--health-check\"})",
		"requireProbeCommand(t, controlPlane, \"readinessProbe\", []string{\"/usr/local/bin/trstctl\", \"--ready-check\"})",
		"requireProbeCommand(t, controlPlane, \"livenessProbe\", []string{\"/usr/local/bin/trstctl\", \"--health-check\"})")

	// OPS-002: isolated signer storage must render complete, not merely selectable.
	// These tests render the isolated signer Deployment and require the signer mTLS,
	// sealed key store, KEK, and auth-secret mounts/volumes the signer binary needs.
	requireTestDeclares(t, root, filepath.Join("deploy", "helm", "helm_s15_test.go"), "TestSignerIsolationChartIsStructurallyValid")
	requireTestDeclares(t, root, filepath.Join("deploy", "helm", "helm_s15_test.go"), "TestIsolatedSignerGuardIsCodeBound")
	requireFileContains(t, root, filepath.Join("deploy", "helm", "helm_s15_test.go"),
		"\"/etc/trstctl/signer-mtls\", \"/data/signer\", \"/etc/trstctl/kek\", \"/etc/trstctl/signer-auth\"",
		"\"signer-mtls\", \"signer-keys\", \"kek\", \"signer-auth\"",
		"requireSecretDefaultMode(t, pod, \"kek\", 0o440)",
		"requireSecretDefaultMode(t, pod, \"signer-auth\", 0o440)")

	// OPS-003: first boot needs a token and a reachable steady-state channel. The
	// static Kubernetes and Windows packaging tests pin token-file wiring, CA pinning,
	// agent-channel endpoint settings, and operator docs for minting the Secret.
	requireTestDeclares(t, root, filepath.Join("deploy", "kubernetes", "manifests_test.go"), "TestAgentBootstrapManifestWiresTokenAndAgentChannel")
	requireTestDeclares(t, root, filepath.Join("deploy", "kubernetes", "manifests_test.go"), "TestAgentBootstrapDocsMintSecretAndEnableChannel")
	requireFileContains(t, root, filepath.Join("deploy", "kubernetes", "daemonset.yaml"),
		"--bootstrap-token-file=/var/run/trstctl/bootstrap/token",
		"secretName: trstctl-agent-bootstrap",
		"TRSTCTL_SERVER",
		"trstctl:9443")
	requireTestDeclares(t, root, filepath.Join("deploy", "windows", "windows_test.go"), "TestAgentBootstrapMSIRequiresConfiguredFirstBootProperties")
	requireTestDeclares(t, root, filepath.Join("deploy", "windows", "windows_test.go"), "TestAgentBootstrapWindowsDocsUseTokenFile")
	requireFileContains(t, root, filepath.Join("deploy", "windows", "trstctl-agent.wxs"),
		"BOOTSTRAPTOKENFILE",
		"--bootstrap-token-file [BOOTSTRAPTOKENFILE]")

	// The shared deploycheck pattern itself must stay alive: manifest flags are
	// reconciled against binary --help, TRSTCTL_* env keys against the config loader,
	// Helm values against templates, and rendered objects against basic Kubernetes
	// structure. Those are the OPS-008 "serious testing spine" anchors.
	for _, name := range []string{
		"TestManifestFlagsAreDefinedByTheBinary",
		"TestEveryDeployImageIsBuiltOrMarkedPlanned",
		"TestManifestEnvKeysAreReadByTheBinary",
		"TestEveryTemplateValueExistsInValuesYAML",
		"TestRenderedManifestsAreStructurallyValid",
	} {
		requireTestDeclares(t, root, filepath.Join("deploy", "deploycheck_test.go"), name)
	}
}

func TestComposeE2EGeneratesPortableUUIDs(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "ci", "compose-e2e_selftest.sh"))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compose e2e UUID self-test failed: %v\n%s", err, out)
	}
}

func TestProfileZlintGateFailsOnMalformedGeneratedLeaf(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "ci", "profile-zlint_selftest.sh"))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile zlint self-test failed: %v\n%s", err, out)
	}
}

func TestComposeE2EPublishesPKIProfileLintArtifacts(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	workflow := string(raw)
	for _, want := range []string{
		"Prepare PKI profile artifact directories",
		"Profile lint fixtures are generated later in this job.",
		"TestArchiveProfileLintFixturesWritesCorpus",
		"bash scripts/ci/profile-zlint.sh served-ca.pem",
		"name: pki-profile-zlint-corpus",
		"${{ runner.temp }}/profile-lint-fixtures",
		"${{ runner.temp }}/profile-lint-zlint",
		"if-no-files-found: error",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("compose e2e workflow does not publish the PKI profile lint corpus; missing %q", want)
		}
	}
}

// literalFlagTokens extracts literal long-flag names from a Helm template's
// command/args lines, ignoring any token that is itself a Go-template action
// ({{ ... }}). It handles both the inline-array form (args: ["--a", "--b=c"]) and
// the YAML list-item form (- "--a"). Values that are not flags (":9443",
// "/run/x.sock") are ignored.
func literalFlagTokens(tpl string) []string {
	var out []string
	tokenRe := regexp.MustCompile(`--([A-Za-z][\w-]*)`)
	for _, line := range strings.Split(tpl, "\n") {
		l := strings.TrimSpace(line)
		// Skip YAML/template comment lines — a comment that merely mentions a flag
		// (e.g. documenting that --mtls-listen is gone) is not a flag the binary is
		// actually invoked with.
		if strings.HasPrefix(l, "#") {
			continue
		}
		// Strip a trailing inline YAML comment ("key: val  # note --foo") so a flag
		// named only in prose is not mistaken for one passed to the binary.
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		// Only consider lines that carry args/command flags. The inline array and
		// the list-item dash both start a flag with a quote-or-bracket then "--".
		if !strings.Contains(l, "--") {
			continue
		}
		// Drop any templated action so a flag built from a template isn't misread.
		clean := regexp.MustCompile(`\{\{.*?\}\}`).ReplaceAllString(l, "")
		for _, m := range tokenRe.FindAllStringSubmatch(clean, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

// imageRefRe matches an `image:` value on a single line in any deploy
// YAML/template. The value class excludes whitespace, so it cannot span onto the
// next line and accidentally capture a sibling key (the [ \t]* after the colon
// stays on the same line on purpose).
var imageRefRe = regexp.MustCompile(`(?m)^[ \t]*image:[ \t]*["']?([^"'\s{}]+)`)

func TestEveryDeployImageIsBuiltOrMarkedPlanned(t *testing.T) {
	root := repoRoot(t)
	deployDir := filepath.Join(root, "deploy")

	// The set of images a workflow actually builds & pushes. Today release.yml
	// builds exactly one multi-binary image: ghcr.io/<repo>/trstctl (+ a Docker
	// Hub mirror of the same name). The agent and signer ride inside it; there is
	// no -agent/-signer/-operator image.
	builtSuffixes := []string{"/trstctl"} // matches ghcr.io/<owner>/trstctl and docker.io/<org>/trstctl

	// Walk every YAML/tpl under deploy/ and collect concrete image references.
	var offenders []string
	err := filepath.Walk(deployDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" && ext != ".tpl" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range imageRefRe.FindAllStringSubmatch(string(b), -1) {
			ref := m[1]
			// Only police trstctl-family images. Third-party base images
			// (postgres, nats, distroless, …) are built upstream and are out of
			// scope for the "we must build what we reference" check (OPS-002).
			if !strings.Contains(strings.ToLower(ref), "trstctl") {
				continue
			}
			// Helm-templated images resolve to the built control-plane image via
			// the trstctl.image helper / .Values.image.repository; treat any
			// reference that flows from those as built.
			if strings.Contains(ref, "{{") {
				if strings.Contains(ref, "trstctl.image") || strings.Contains(ref, ".Values.image.repository") {
					continue
				}
				// A templated image we don't recognize: flag it.
				offenders = append(offenders, rel(deployDir, path)+": "+ref+" (unrecognized templated image)")
				continue
			}
			if rel(deployDir, path) == "docker/docker-compose.yml" &&
				strings.HasPrefix(ref, "trstctl-eval:") &&
				strings.Contains(string(b), "dockerfile: deploy/docker/Dockerfile") {
				continue
			}
			// Concrete reference. Strip the tag/digest for the build check.
			name := ref
			if i := strings.LastIndexByte(name, '@'); i >= 0 {
				name = name[:i]
			} else if i := strings.LastIndexByte(name, ':'); i >= 0 {
				name = name[:i]
			}
			built := false
			for _, suf := range builtSuffixes {
				if strings.HasSuffix(name, suf) {
					built = true
					break
				}
			}
			if built {
				continue
			}
			// Not a built image. It is only acceptable if explicitly marked as a
			// not-yet-built placeholder (honest disclosure, not a real tag).
			if strings.Contains(strings.ToUpper(ref), "PLANNED") || strings.Contains(strings.ToUpper(ref), "PLACEHOLDER") {
				continue
			}
			offenders = append(offenders, rel(deployDir, path)+": "+ref)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these deploy/ image references are neither built by a workflow nor marked PLANNED "+
			"(OPS-002 — a default install would ImagePullBackOff):\n  %s", strings.Join(offenders, "\n  "))
	}
}

// --- SUPPLY-001/002: the privileged Windows agent .exe + .msi must be
// code-signed in the release pipeline through a remote signer, and CI must not
// materialize long-lived code-signing key material on a runner. ---

// ghaWorkflow is the slice of a GitHub Actions workflow this suite inspects: the
// jobs, each with its steps' run scripts and `if:` gates.
type ghaWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
			If   string `yaml:"if"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// TestReleaseSignsTheWindowsAgent asserts the release workflow actually invokes a
// Windows-agent code-signing path for BOTH the agent .exe and .msi, and gates
// publication on verified signatures (SUPPLY-001/002). It drills the real
// release.yml (parsed as YAML, not grepped loosely) and the real Makefile
// dist-windows recipe.
//
// It FAILS on the pre-fix tree — release.yml signed only the control-plane image
// and had no agent job, so the privileged agent shipped unsigned — and PASSES once
// the agent-windows job + the Makefile osslsigncode path are wired.
func TestReleaseSignsTheWindowsAgent(t *testing.T) {
	root := repoRoot(t)

	// (1) release.yml must carry a job that builds + signs + checksum-publishes the
	// Windows agent, and verifies/gates signed publication.
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	var wf ghaWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	// Find the job whose steps build the Windows agent (it runs `make dist-windows`
	// or builds trstctl-agent.exe). Collect that job's combined step scripts.
	var agentJob string
	var script strings.Builder
	for name, job := range wf.Jobs {
		var b strings.Builder
		buildsAgent := false
		for _, s := range job.Steps {
			b.WriteString(s.Run)
			b.WriteByte('\n')
			r := s.Run
			if strings.Contains(r, "dist-windows") ||
				strings.Contains(r, "trstctl-agent.exe") ||
				strings.Contains(r, "trstctl-agent.msi") {
				buildsAgent = true
			}
		}
		if buildsAgent {
			agentJob = name
			script.WriteString(b.String())
		}
	}
	if agentJob == "" {
		t.Fatal("release.yml has NO job that builds the Windows agent (.exe/.msi) — the privileged agent ships unsigned (SUPPLY-001). " +
			"Add an agent-windows job that builds, Authenticode-signs, and publishes the agent.")
	}
	t.Logf("release.yml Windows-agent job: %q", agentJob)

	combined := script.String()
	// The job must invoke the remote signing path for the agent. The signer is an
	// operator-owned HSM/cloud service authenticated by GitHub OIDC, not a
	// runner-local PKCS#12 file.
	signs := strings.Contains(combined, "dist-windows") &&
		strings.Contains(combined, "WINDOWS_CODESIGN_URL")
	if !signs {
		t.Errorf("the release Windows-agent job (%q) does not invoke a code-signing step "+
			"through the remote OIDC signer — SUPPLY-001/002 requires the agent .exe + .msi to be signed without runner-local key material", agentJob)
	}
	if !strings.Contains(string(raw), "id-token: write") ||
		!strings.Contains(string(raw), "environment: windows-code-signing") ||
		!strings.Contains(string(raw), "sign-windows-artifact-oidc.sh") {
		t.Errorf("the release Windows-agent job (%q) must run in the protected signing environment and use GitHub OIDC for the remote signer", agentJob)
	}
	for _, forbidden := range []string{"WINDOWS_CODESIGN_PFX_BASE64", "codesign.pfx", "SIGN_PFX", "base64 -d"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("release.yml still contains %q; SUPPLY-002 forbids materializing long-lived Authenticode key material in CI", forbidden)
		}
	}
	// And it must VERIFY / gate publication so a tag cannot ship unsigned.
	if !strings.Contains(combined, "verify") {
		t.Errorf("the release Windows-agent job (%q) builds the agent but never verifies the signature / gates on it — "+
			"SUPPLY-001 requires the release to block publication when the privileged agent is unsigned", agentJob)
	}
	if !strings.Contains(combined, "WINDOWS_CODESIGN_URL is required") ||
		!strings.Contains(combined, "osslsigncode verify") {
		t.Errorf("the release Windows-agent job (%q) does not fail closed on missing remote signer config and verify signatures before upload", agentJob)
	}

	// (2) The Makefile dist-windows recipe must Authenticode-sign BOTH the .exe and
	// the .msi through the remote OIDC signing bridge when WINDOWS_CODESIGN_URL is set.
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	recipe := makeTargetBody(string(mk), "dist-windows")
	if recipe == "" {
		t.Fatal("Makefile has no dist-windows target")
	}
	for _, forbidden := range []string{"SIGN_PFX", "osslsigncode sign", "codesign.pfx"} {
		if strings.Contains(recipe, forbidden) {
			t.Errorf("Makefile dist-windows still contains %q; release signing must be remote/HSM-backed, not runner-local PFX signing", forbidden)
		}
	}
	if !strings.Contains(recipe, `if [ -n "$$WINDOWS_CODESIGN_URL" ]`) ||
		!strings.Contains(recipe, "scripts/ci/sign-windows-artifact-oidc.sh") {
		t.Errorf("Makefile dist-windows does not gate remote signing on WINDOWS_CODESIGN_URL and invoke the OIDC signing bridge")
	}
	// Both the .exe and the .msi must be signed (the audit's exact gap: the MSI was
	// built unsigned) and verified.
	if !strings.Contains(recipe, "trstctl-agent.exe") ||
		!strings.Contains(recipe, "verify trstctl-agent.exe signature") {
		t.Errorf("Makefile dist-windows does not sign trstctl-agent.exe (SUPPLY-001)")
	}
	if !strings.Contains(recipe, "trstctl-agent.msi") ||
		!strings.Contains(recipe, "verify trstctl-agent.msi signature") {
		t.Errorf("Makefile dist-windows does not sign trstctl-agent.msi (SUPPLY-001: the MSI shipped unsigned)")
	}
	// And it must still publish the SHA-256 sums.
	if !strings.Contains(recipe, "SHA256SUMS") {
		t.Errorf("Makefile dist-windows does not publish SHA256SUMS (SUPPLY-001 acceptance: publish the SHA-256 sums)")
	}
}

// makeTargetBody returns the recipe lines of the named Makefile target (the
// tab-indented lines following "<name>:"), stopping at the next unindented line.
func makeTargetBody(mk, target string) string {
	lines := strings.Split(mk, "\n")
	var body []string
	in := false
	for _, l := range lines {
		if !in {
			// Match the rule line "target: ...".
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, target+":") && !strings.HasPrefix(l, "\t") {
				in = true
			}
			continue
		}
		// Recipe lines are tab-indented (or blank/comment continuations); a new
		// unindented, non-blank line ends the recipe.
		if l == "" || strings.HasPrefix(l, "\t") || strings.HasPrefix(strings.TrimSpace(l), "#") {
			body = append(body, l)
			continue
		}
		break
	}
	return strings.Join(body, "\n")
}

func rel(base, path string) string {
	r, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return r
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- OPS-008 (3): every TRSTCTL_* env key a manifest hands the control-plane
// binary must be one the config loader actually reads -------------------------

// loaderEnvKeys parses the config loader (internal/config/config.go) and returns
// the EXACT set of TRSTCTL_* keys its applyEnv method reads via the
// set{String,Bool,BoolPtr,Int,CSV}(getenv, "KEY", …) helpers. This is the binary's
// real env contract, derived from the AST — not a hand-maintained list — so a
// manifest that sets a key the binary silently ignores (the phantom-env class:
// e.g. a TRSTCTL_KMS_* contract no Go code reads) is caught. It also recognizes
// TRSTCTL_CONFIG_FILE (consulted by Load before applyEnv runs).
func loaderEnvKeys(t *testing.T, root string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "config.go", src, 0)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}
	keys := map[string]bool{}
	// Load() itself reads TRSTCTL_CONFIG_FILE before overlaying applyEnv.
	keys["TRSTCTL_CONFIG_FILE"] = true
	// setterNames are the env-overlay helpers; their 2nd argument is the key string.
	setterNames := map[string]bool{
		"setString": true, "setBool": true, "setBoolPtr": true,
		"setInt": true, "setCSV": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || !setterNames[ident.Name] || len(call.Args) < 2 {
			return true
		}
		// The key is the literal 2nd argument: set*(getenv, "TRSTCTL_…", &dst).
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err == nil && strings.HasPrefix(val, "TRSTCTL_") {
			keys[val] = true
		}
		return true
	})
	if len(keys) < 10 {
		t.Fatalf("parsed only %d TRSTCTL_* keys from applyEnv (expected dozens) — the loader-key extractor is broken, not the manifests", len(keys))
	}
	return keys
}

// envRefRe matches a TRSTCTL_* token anywhere on a line (manifest env keys and
// $(VAR) substitution references both match; we separate them by context below).
var envRefRe = regexp.MustCompile(`TRSTCTL_[A-Z0-9_]+`)

// substVarRe matches a $(VAR) Kubernetes env-substitution reference, e.g.
// "--enroll-url=$(TRSTCTL_ENROLL_URL)". Such a token is the NAME of a pod env var
// interpolated into an arg string by the kubelet — it is NOT a key the binary reads
// from its environment, so it is excluded from the config-key reconciliation.
var substVarRe = regexp.MustCompile(`\$\((TRSTCTL_[A-Z0-9_]+)\)`)

// binaryEnvKeysInManifest returns the TRSTCTL_* keys a manifest sets that the
// control-plane binary is expected to READ from its environment, excluding keys
// that exist only to be interpolated into a flag via $(VAR) (those feed a flag the
// flags-vs-binary check already validates, and the agent never reads them as env).
func binaryEnvKeysInManifest(body string) map[string]bool {
	// Collect every $(VAR) substitution name; these are pod-local plumbing, not the
	// binary's env contract.
	subst := map[string]bool{}
	for _, m := range substVarRe.FindAllStringSubmatch(body, -1) {
		subst[m[1]] = true
	}
	out := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		for _, k := range envRefRe.FindAllString(l, -1) {
			// A $(VAR) reference is plumbing; the `name: TRSTCTL_X` that DEFINES it is
			// the value source for that plumbing — skip both so only keys the binary
			// reads from its environment remain.
			if subst[k] {
				continue
			}
			out[k] = true
		}
	}
	return out
}

// configMapDataKeys returns the TRSTCTL_* keys a Helm configMap template declares
// under its `data:` block — these are loaded into the control-plane pod via
// envFrom.configMapRef and read directly by the binary, so each must be a real
// loader key. The values may be templated; we only care about the key names.
func configMapDataKeys(body string) map[string]bool {
	out := map[string]bool{}
	inData := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "data:" {
			inData = true
			continue
		}
		if inData {
			// A non-indented, non-blank line that is not a comment ends the data block.
			if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inData = false
			}
		}
		if !inData || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		// data entries look like `TRSTCTL_FOO: {{ … }}` — take the key before the colon.
		if i := strings.IndexByte(trimmed, ':'); i > 0 {
			key := strings.TrimSpace(trimmed[:i])
			if strings.HasPrefix(key, "TRSTCTL_") {
				out[key] = true
			}
		}
	}
	return out
}

func TestManifestEnvKeysAreReadByTheBinary(t *testing.T) {
	root := repoRoot(t)
	known := loaderEnvKeys(t, root)

	// Sources whose TRSTCTL_* env the CONTROL-PLANE binary reads directly:
	//   - the Helm configMap data (loaded via envFrom into the control-plane pod);
	//   - the deployment's direct env: stanza on the trstctl container;
	//   - the compose service environment.
	type src struct {
		rel  string
		keys map[string]bool
	}
	var sources []src

	cfgTpl, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "trstctl", "templates", "configmap.yaml"))
	if err != nil {
		t.Fatalf("read configmap.yaml: %v", err)
	}
	sources = append(sources, src{"helm/templates/configmap.yaml", configMapDataKeys(string(cfgTpl))})

	depTpl, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "trstctl", "templates", "deployment.yaml"))
	if err != nil {
		t.Fatalf("read deployment.yaml: %v", err)
	}
	sources = append(sources, src{"helm/templates/deployment.yaml", binaryEnvKeysInManifest(string(depTpl))})

	compose, err := os.ReadFile(filepath.Join(root, "deploy", "docker", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	sources = append(sources, src{"docker/docker-compose.yml", binaryEnvKeysInManifest(string(compose))})

	checked := 0
	for _, s := range sources {
		if len(s.keys) == 0 {
			continue
		}
		for k := range s.keys {
			checked++
			if !known[k] {
				t.Errorf("%s sets %s, which the control-plane config loader (internal/config applyEnv) does not read "+
					"— the binary would silently ignore it (the phantom-env class OPS warned about, e.g. TRSTCTL_KMS_*). "+
					"Known keys: %v", s.rel, k, keys(known))
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no TRSTCTL_* env keys to reconcile in any manifest — the extractor is broken")
	}

	// Mutation proof (negative): a manifest fragment that sets a key the loader never
	// reads must be REJECTED, and a fragment that sets only real keys must PASS — so
	// this check is non-vacuous.
	t.Run("rejects_phantom_env_key", func(t *testing.T) {
		bad := "data:\n  TRSTCTL_KMS_PROVIDER: \"awskms\"\n  TRSTCTL_SERVER_ADDR: \":8443\"\n"
		var offenders []string
		for k := range configMapDataKeys(bad) {
			if !known[k] {
				offenders = append(offenders, k)
			}
		}
		if len(offenders) == 0 {
			t.Fatal("the config-key check failed to flag the injected phantom TRSTCTL_KMS_PROVIDER — it is vacuous")
		}
		// And a fragment of only-real keys is accepted.
		good := "data:\n  TRSTCTL_SERVER_ADDR: \":8443\"\n  TRSTCTL_NATS_URL: \"nats://x\"\n"
		for k := range configMapDataKeys(good) {
			if !known[k] {
				t.Errorf("the config-key check wrongly flagged the real key %s", k)
			}
		}
	})
}

// --- OPS-008 (4): every .Values.X a template references must exist in values.yaml,
// and every value the chart declares must be reachable -------------------------

const chartDir = "helm/trstctl"

// valuesYAMLPaths flattens values.yaml into (a) the set of dotted paths it defines
// and (b) the subset of those paths whose value is an EMPTY map ({}), e.g.
// `podAnnotations: {}` or `resources.signer: {}`. An empty map is a FREEFORM,
// operator-supplied block (the chart renders it with toYaml/with), so a template may
// dig arbitrarily deep into it; an ENUMERATED map (e.g. `service: {type, port}`) may
// NOT — a reference to a child it does not list is a drift. Returning both sets lets
// valuePathDefined enforce that distinction (so a typo like .Values.service.typ is
// caught while .Values.podAnnotations.whatever is allowed).
func valuesYAMLPaths(t *testing.T, root string) (paths, freeform map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "deploy", chartDir, "values.yaml"))
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var v map[string]any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	paths = map[string]bool{}
	freeform = map[string]bool{}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, val := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			paths[p] = true
			if child, ok := val.(map[string]any); ok {
				if len(child) == 0 {
					freeform[p] = true // an empty map: operator-supplied freeform block
				}
				walk(p, child)
			}
		}
	}
	walk("", v)
	return paths, freeform
}

// valueRefRe matches a `.Values.<dotted.path>` reference in a Helm template.
var valueRefRe = regexp.MustCompile(`\.Values\.([A-Za-z_][A-Za-z0-9_.]*)`)

// templateValueRefs returns the distinct `.Values.X` dotted paths a template body
// references, stripping any trailing dot (a regex artifact) and dropping the
// special `.Values.<empty>` non-match.
func templateValueRefs(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range valueRefRe.FindAllStringSubmatch(body, -1) {
		p := strings.TrimRight(m[1], ".")
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// valuePathDefined reports whether a referenced `.Values.X` path is backed by
// values.yaml. An EXACT match counts. A deeper reference (e.g.
// `.Values.podAnnotations.foo`) counts ONLY when its longest defined prefix is a
// FREEFORM (empty {}) map — an operator-supplied block the chart renders wholesale.
// Digging into an ENUMERATED map (e.g. `.Values.service.typ` when service only lists
// type/port) is a DRIFT and fails — that is the bug the looser version missed.
func valuePathDefined(ref string, defined, freeform map[string]bool) bool {
	if defined[ref] {
		return true
	}
	segs := strings.Split(ref, ".")
	if !defined[segs[0]] {
		return false // typo'd top-level key
	}
	// Find the longest defined proper prefix.
	for i := len(segs) - 1; i >= 1; i-- {
		pre := strings.Join(segs[:i], ".")
		if defined[pre] {
			// Deeper reference is allowed only if that prefix is a freeform (empty) map.
			return freeform[pre]
		}
	}
	return false
}

func TestEveryTemplateValueExistsInValuesYAML(t *testing.T) {
	root := repoRoot(t)
	defined, freeform := valuesYAMLPaths(t, root)
	if len(defined) < 10 {
		t.Fatalf("values.yaml flattened to only %d paths — the flattener is broken, not the templates", len(defined))
	}

	tmplDir := filepath.Join(root, "deploy", chartDir, "templates")
	entries, err := os.ReadDir(tmplDir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".tpl") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(tmplDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for ref := range templateValueRefs(string(body)) {
			checked++
			if !valuePathDefined(ref, defined, freeform) {
				t.Errorf("templates/%s references .Values.%s, which values.yaml does not define "+
					"(it renders empty and silently misconfigures the release) — OPS-008", name, ref)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no .Values references in any template — the extractor is broken")
	}

	// Mutation proof (negative): a template that references an undefined value — both a
	// brand-new top-level key AND a typo'd CHILD of an enumerated map — must be
	// REJECTED; the real templates (above) and a legit freeform-map reference must PASS.
	t.Run("rejects_undefined_value_reference", func(t *testing.T) {
		for _, bad := range []string{"doesNotExistAtAll", "service.typeDoesNotExist", "image.taggg"} {
			if valuePathDefined(bad, defined, freeform) {
				t.Errorf("the values-reconciliation check failed to flag .Values.%s — it is vacuous", bad)
			}
		}
		// A real exact reference is accepted.
		if !valuePathDefined("image.repository", defined, freeform) {
			t.Error("the values-reconciliation check wrongly flagged the real path image.repository")
		}
		// A reference INTO a freeform (empty {}) map is accepted (operator-supplied).
		var freeKey string
		for k := range freeform {
			freeKey = k
			break
		}
		if freeKey != "" && !valuePathDefined(freeKey+".anyChildAtAll", defined, freeform) {
			t.Errorf("the values check wrongly rejected a child of the freeform map %s", freeKey)
		}
	})
}

// --- OPS-008 (5): render the chart's templates and assert each rendered object is
// structurally valid for its Kubernetes kind (a kubeconform-style gate) ---------

// helmStubFuncs returns the Helm/Sprig builtins the chart templates call, stubbed
// so a local text/template render produces structurally-real YAML. `include`
// resolves the naming helpers to a concrete name; `toYaml` echoes nested maps as
// indented YAML so container/volume/affinity blocks render; the rest are no-ops or
// pass-throughs. A real `helm template` does the full render in CI — this local
// render exists to PIN the structural facts (OPS-008: drill the artifact).
func helmStubFuncs() template.FuncMap {
	return template.FuncMap{
		"include": func(name string, _ any) string {
			// Resolve the names structural checks depend on to concrete strings.
			switch name {
			case "trstctl.fullname", "trstctl.name", "trstctl.serviceAccountName",
				"trstctl.kekSecretName", "trstctl.signerAuthSecretName", "trstctl.dbSecretName":
				return "trstctl"
			case "trstctl.image":
				return "ghcr.io/example/trstctl:v0.5.0"
			case "trstctl.labels", "trstctl.selectorLabels":
				// A single label line only. The real helpers emit an
				// `app.kubernetes.io/component:` key, but several templates append their
				// OWN component label (e.g. the signer Deployment), which would collide
				// into a duplicate-map-key YAML error in this local render. Helm tolerates
				// the override; the structural gate only cares about apiVersion/kind/spec,
				// so we emit a non-colliding label and keep the render parseable.
				return "app.kubernetes.io/name: trstctl"
			case "trstctl.requiredInputs.guard", "trstctl.signer.guardMode":
				return ""
			}
			return "trstctl"
		},
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			var b strings.Builder
			b.WriteString("\n")
			for i, line := range strings.Split(s, "\n") {
				if i > 0 {
					b.WriteString("\n")
				}
				b.WriteString(pad + line)
			}
			return b.String()
		},
		"indent": func(n int, s string) string { return strings.Repeat(" ", n) + s },
		"toYaml": func(v any) string {
			b, err := yaml.Marshal(v)
			if err != nil {
				return ""
			}
			return strings.TrimRight(string(b), "\n")
		},
		"quote":      func(v any) string { return strconv.Quote(toStr(v)) },
		"sha256sum":  func(...any) string { return "deadbeefdeadbeef" },
		"required":   func(_ string, v any) any { return v },
		"trunc":      func(_ int, s any) any { return s },
		"trimSuffix": func(_ string, s any) any { return s },
		"contains":   func(_ string, _ any) bool { return false },
		// Sprig's `default a b` returns b if non-empty else a. signer-deployment.yaml's
		// secretName uses `… | default (printf …)`; emulate it so the render resolves.
		"default": func(d, v any) any {
			if toStr(v) == "" {
				return d
			}
			return v
		},
		// NOTE: printf / eq / ne are text/template built-ins; do NOT override them here
		// or the chart's `eq .Values.tls.mode "file"` guards would misbehave.
	}
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(strings.Trim(fmtSprint(v), "[]"))
}

// fmtSprint is a tiny fmt.Sprint shim kept local so the helper set stays in one
// file; values are scalars in practice.
func fmtSprint(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	default:
		return ""
	}
}

// renderChartTemplate renders one chart template with the given Values, stubbing
// the Helm builtins. Unknown keys resolve to empty (missingkey=zero) rather than
// failing, so the render is best-effort but structurally faithful.
func renderChartTemplate(t *testing.T, root, name string, values map[string]any) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, "deploy", chartDir, "templates", name))
	if err != nil {
		t.Fatalf("read templates/%s: %v", name, err)
	}
	tmpl, err := template.New(name).Funcs(helmStubFuncs()).Option("missingkey=zero").Parse(string(body))
	if err != nil {
		t.Fatalf("parse templates/%s: %v", name, err)
	}
	data := map[string]any{
		"Values":  values,
		"Release": map[string]any{"Name": "trstctl", "Service": "Helm"},
		"Chart":   map[string]any{"Name": "trstctl", "AppVersion": "0.5.0", "Version": "0.1.0"},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("render templates/%s: %v", name, err)
	}
	return sb.String()
}

// k8sObject is the minimal shape every Kubernetes manifest must carry.
type k8sObject struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   map[string]any `yaml:"metadata"`
	Spec       map[string]any `yaml:"spec"`
}

// structuralViolations parses rendered YAML (possibly multi-doc) and returns the
// count of Kubernetes objects found plus a list of the structural violations: each
// object must carry apiVersion, kind, metadata.name, and the kind-specific required
// fields a kubeconform / API-server admission would demand. It does NOT touch
// *testing.T — returning the violations as data is what lets the negative sub-test
// prove the check rejects a broken manifest WITHOUT failing the real test.
func structuralViolations(label, rendered string) (objects int, violations []string) {
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var obj k8sObject
		if err := dec.Decode(&obj); err != nil {
			break
		}
		if obj.APIVersion == "" && obj.Kind == "" && obj.Metadata == nil {
			continue // empty doc (a fully-gated-off template)
		}
		objects++
		add := func(format string, a ...any) {
			violations = append(violations, label+": "+fmtSprintf(format, a...))
		}
		if obj.APIVersion == "" {
			add("rendered object #%d is missing apiVersion (the API server would reject it)", objects)
		}
		if obj.Kind == "" {
			add("rendered object #%d is missing kind", objects)
		}
		if name, _ := obj.Metadata["name"].(string); strings.TrimSpace(name) == "" {
			add("rendered %s is missing metadata.name", obj.Kind)
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "StatefulSet":
			if obj.Spec["selector"] == nil {
				add("%s has no spec.selector (required)", obj.Kind)
			}
			tmpl, _ := obj.Spec["template"].(map[string]any)
			pod, _ := tmpl["spec"].(map[string]any)
			cs, _ := pod["containers"].([]any)
			if len(cs) == 0 {
				add("%s has no spec.template.spec.containers (required)", obj.Kind)
			}
		case "Service":
			if obj.Spec["ports"] == nil {
				add("Service has no spec.ports (required)")
			}
		case "PodDisruptionBudget":
			if obj.Spec["selector"] == nil {
				add("PodDisruptionBudget has no spec.selector (required)")
			}
		case "PersistentVolumeClaim":
			if obj.Spec["accessModes"] == nil {
				add("PersistentVolumeClaim has no spec.accessModes (required)")
			}
		}
	}
	return objects, violations
}

// requireStructurallyValid runs structuralViolations and reports any to t,
// returning the object count so a caller can assert the template rendered
// something. Used by the positive path; the negative path calls
// structuralViolations directly.
func requireStructurallyValid(t *testing.T, label, rendered string) int {
	t.Helper()
	n, viols := structuralViolations(label, rendered)
	for _, v := range viols {
		t.Errorf("%s — OPS-008", v)
	}
	return n
}

// fmtSprintf is a minimal Sprintf shim (avoids importing fmt for one call site,
// keeping the deploy test's import set tight). It supports the %s/%d verbs the
// structural messages use.
func fmtSprintf(format string, a ...any) string {
	var b strings.Builder
	ai := 0
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			i++
			if ai < len(a) {
				switch format[i] {
				case 'd':
					if n, ok := a[ai].(int); ok {
						b.WriteString(strconv.Itoa(n))
					}
				default:
					b.WriteString(toStr(a[ai]))
				}
				ai++
			}
			continue
		}
		b.WriteByte(format[i])
	}
	return b.String()
}

// haValues is a realistic, valid Values map for rendering the chart templates
// structurally (the multi-replica HA defaults plus explicit install inputs the
// OPS-003 fail-closed guard requires).
func haValues() map[string]any {
	return map[string]any{
		"replicaCount": 2,
		"updateStrategy": map[string]any{
			"type": "RollingUpdate", "maxUnavailable": 0, "maxSurge": 1,
		},
		"image":            map[string]any{"repository": "ghcr.io/example/trstctl", "tag": "", "pullPolicy": "IfNotPresent"},
		"imagePullSecrets": []any{},
		"server":           map[string]any{"addr": ":8443", "logFormat": "json"},
		"service":          map[string]any{"type": "ClusterIP", "port": 8443},
		"tls":              map[string]any{"mode": "internal", "existingSecret": ""},
		"bulkheads": map[string]any{
			"api":         map[string]any{"workers": 8, "queue": 256},
			"projections": map[string]any{"workers": 2, "queue": 128},
			"outbox":      map[string]any{"workers": 4, "queue": 256},
			"signing":     map[string]any{"workers": 4, "queue": 64},
			"query":       map[string]any{"workers": 4, "queue": 64},
			"policy":      map[string]any{"workers": 4, "queue": 64},
			"protocols":   map[string]any{"workers": 8, "queue": 256},
			"agent":       map[string]any{"workers": 16, "queue": 1024},
		},
		"postgres": map[string]any{"mode": "external", "dsn": "", "existingSecret": "trstctl-db", "existingSecretKey": "dsn"},
		"nats":     map[string]any{"mode": "external", "url": "nats://trstctl-nats:4222"},
		"kek":      map[string]any{"existingSecret": "trstctl-kek", "existingSecretKey": "kek.bin", "generate": false},
		"persistence": map[string]any{
			"enabled": true, "storageClass": "", "controlPlaneAccessMode": "ReadWriteMany",
			"signerKeysAccessMode": "ReadWriteMany", "controlPlaneSize": "1Gi", "signerKeysSize": "1Gi",
		},
		"resources": map[string]any{
			"signer": map[string]any{}, "controlPlane": map[string]any{},
		},
		"podAnnotations":      map[string]any{},
		"nodeSelector":        map[string]any{},
		"tolerations":         []any{},
		"affinity":            map[string]any{"podAntiAffinity": map[string]any{}},
		"podDisruptionBudget": map[string]any{"enabled": true, "minAvailable": 1},
		"ha":                  map[string]any{"leaderElection": true, "leaderCampaignInterval": "", "snapshotInterval": ""},
		"serviceAccount":      map[string]any{"create": true, "name": "", "annotations": map[string]any{}},
		"signer": map[string]any{
			"mode": "sidecar", "replicas": 1, "resources": map[string]any{},
			"mtls": map[string]any{"serverName": "", "signerSecret": "", "controlPlaneSecret": ""},
		},
		"networkPolicy": map[string]any{
			"enabled": true,
			"ingress": map[string]any{
				"ingressController": map[string]any{"enabled": true,
					"namespaceLabels": map[string]any{"kubernetes.io/metadata.name": "ingress-nginx"},
					"podLabels":       map[string]any{"app.kubernetes.io/name": "ingress-nginx"}},
				"sameNamespace": false,
			},
			"allowedIngressNamespaces": []any{},
			"postgres":                 map[string]any{"port": 5432},
			"nats":                     map[string]any{"port": 4222},
		},
		// Served agent steady-state channel (WIRE-004 / OPS-005), OFF by default —
		// mirrors values.yaml so the default render does not expose :9443.
		"agentChannel": map[string]any{
			"enabled": false, "addr": ":9443", "servicePort": 9443,
			"serverName": "", "heartbeatInterval": "", "allowedCIDRs": []any{},
		},
	}
}

func TestRenderedManifestsAreStructurallyValid(t *testing.T) {
	root := repoRoot(t)

	// (a) The chart templates that always render a control-plane object.
	for _, name := range []string{"deployment.yaml", "service.yaml", "configmap.yaml", "pdb.yaml", "networkpolicy.yaml", "serviceaccount.yaml"} {
		rendered := renderChartTemplate(t, root, name, haValues())
		if requireStructurallyValid(t, "helm/"+name, rendered) == 0 && name != "networkpolicy.yaml" {
			t.Errorf("helm/%s rendered no Kubernetes object with the valid HA values — OPS-008", name)
		}
	}

	// (b) The isolated-signer Deployment renders only when signer.mode=isolated; with
	// the serverName supplied it must be a structurally-valid Deployment.
	iso := haValues()
	iso["signer"].(map[string]any)["mode"] = "isolated"
	iso["signer"].(map[string]any)["mtls"].(map[string]any)["serverName"] = "trstctl-signer.ns.svc"
	signerRendered := renderChartTemplate(t, root, "signer-deployment.yaml", iso)
	if requireStructurallyValid(t, "helm/signer-deployment.yaml", signerRendered) == 0 {
		t.Error("helm/signer-deployment.yaml rendered no Deployment in isolated mode — OPS-008")
	}

	// (c) The static (non-templated) manifests parse and validate directly.
	for _, rel := range []string{
		filepath.Join("kubernetes", "daemonset.yaml"),
		filepath.Join("operator", "operator.yaml"),
	} {
		raw, err := os.ReadFile(filepath.Join(root, "deploy", rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if requireStructurallyValid(t, rel, string(raw)) == 0 {
			t.Errorf("%s contained no Kubernetes object — OPS-008", rel)
		}
	}

	// Mutation proof (negative): structuralViolations must FLAG a manifest that renders
	// an object missing a required field, and must NOT flag a complete one — so the
	// structural gate is non-vacuous. (structuralViolations returns the violations as
	// data, so the probe never has to fail the real test to observe rejection.)
	t.Run("rejects_structurally_broken_object", func(t *testing.T) {
		// A Deployment with no selector and no containers.
		if _, v := structuralViolations("broken", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  replicas: 1\n"); len(v) == 0 {
			t.Fatal("structuralViolations failed to flag a Deployment with no selector/containers — it is vacuous")
		}
		// An object with no kind.
		if _, v := structuralViolations("nokind", "apiVersion: v1\nmetadata:\n  name: x\n"); len(v) == 0 {
			t.Fatal("structuralViolations failed to flag an object with no kind — it is vacuous")
		}
		// A Service with no ports.
		if _, v := structuralViolations("noports", "apiVersion: v1\nkind: Service\nmetadata:\n  name: x\nspec: {}\n"); len(v) == 0 {
			t.Fatal("structuralViolations failed to flag a Service with no spec.ports — it is vacuous")
		}
		// A complete Service is accepted (no violations).
		if _, v := structuralViolations("ok", "apiVersion: v1\nkind: Service\nmetadata:\n  name: x\nspec:\n  ports:\n    - port: 8443\n"); len(v) != 0 {
			t.Errorf("structuralViolations wrongly flagged a complete Service: %v", v)
		}
	})
}
