package deploy_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests are the behavioural counterpart to the static deploy/ string-match
// suite (OPS-008). They drill the real artifacts:
//
//   - TestManifestFlagsAreDefinedByTheBinary parses the actual flag set out of
//     each trustctl binary's --help and asserts every flag a manifest passes is
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

// repoRoot returns the repository root (this package lives at <root>/deploy).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd) // strip the trailing /deploy
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

// binaryForContainer decides which trustctl binary a container runs, from its
// command (entrypoint override) or its image name. Returns "" if it does not run
// one of our flag-bearing binaries.
func binaryForContainer(c container) string {
	joined := strings.Join(c.Command, " ")
	switch {
	case strings.Contains(joined, "trustctl-signer"):
		return "trustctl-signer"
	case strings.Contains(joined, "trustctl-agent"):
		return "trustctl-agent"
	case strings.Contains(joined, "trustctl-cli"):
		return "trustctl-cli"
	case strings.Contains(joined, "trustctl"):
		return "trustctl"
	}
	// No command override: fall back to the image's binary suffix.
	switch {
	case strings.Contains(c.Image, "trustctl-signer"):
		return "trustctl-signer"
	case strings.Contains(c.Image, "trustctl-agent"):
		return "trustctl-agent"
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
			for _, c := range containersOf(doc) {
				out = append(out, c)
			}
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
			continue // not a trustctl binary container (e.g. the planned operator)
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
	signerTpl, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "trustctl", "templates", "signer-deployment.yaml"))
	if err != nil {
		t.Fatalf("read signer-deployment.yaml: %v", err)
	}
	signerFlags := getFlags("trustctl-signer")
	for _, fl := range literalFlagTokens(string(signerTpl)) {
		if !signerFlags[fl] {
			t.Errorf("helm signer-deployment.yaml passes --%s to trustctl-signer, which it does not define "+
				"(real flags: %v) — the OPS-001 crash-loop (e.g. --mtls-listen)", fl, keys(signerFlags))
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
	// builds exactly one multi-binary image: ghcr.io/<repo>/trustctl (+ a Docker
	// Hub mirror of the same name). The agent and signer ride inside it; there is
	// no -agent/-signer/-operator image.
	builtSuffixes := []string{"/trustctl"} // matches ghcr.io/<owner>/trustctl and docker.io/<org>/trustctl

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
			// Only police trustctl-family images. Third-party base images
			// (postgres, nats, distroless, …) are built upstream and are out of
			// scope for the "we must build what we reference" check (OPS-002).
			if !strings.Contains(strings.ToLower(ref), "trustctl") {
				continue
			}
			// Helm-templated images resolve to the built control-plane image via
			// the trustctl.image helper / .Values.image.repository; treat any
			// reference that flows from those as built.
			if strings.Contains(ref, "{{") {
				if strings.Contains(ref, "trustctl.image") || strings.Contains(ref, ".Values.image.repository") {
					continue
				}
				// A templated image we don't recognize: flag it.
				offenders = append(offenders, rel(deployDir, path)+": "+ref+" (unrecognized templated image)")
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

// --- SUPPLY-001: the privileged Windows agent .exe + .msi must be code-signed
// in the release pipeline, and the Makefile must sign when an identity is set ---

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
// Windows-agent code-signing path for BOTH the agent .exe and .msi, and gates the
// release on the signature (SUPPLY-001). It drills the real release.yml (parsed as
// YAML, not grepped loosely) and the real Makefile dist-windows recipe.
//
// It FAILS on the pre-fix tree — release.yml signed only the control-plane image
// and had no agent job, so the privileged agent shipped unsigned — and PASSES once
// the agent-windows job + the Makefile osslsigncode path are wired.
func TestReleaseSignsTheWindowsAgent(t *testing.T) {
	root := repoRoot(t)

	// (1) release.yml must carry a job that builds + signs + checksum-publishes the
	// Windows agent, and verifies/gates the signature.
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	var wf ghaWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	// Find the job whose steps build the Windows agent (it runs `make dist-windows`
	// or builds trustctl-agent.exe). Collect that job's combined step scripts.
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
				strings.Contains(r, "trustctl-agent.exe") ||
				strings.Contains(r, "trustctl-agent.msi") {
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
	// The job must invoke a real signing path for the agent. `make dist-windows`
	// signs both artifacts when SIGN_PFX is set; an inline osslsigncode/signtool
	// call is equally acceptable.
	signs := strings.Contains(combined, "dist-windows") ||
		strings.Contains(combined, "osslsigncode") ||
		strings.Contains(combined, "signtool")
	if !signs {
		t.Errorf("the release Windows-agent job (%q) does not invoke a code-signing step "+
			"(make dist-windows / osslsigncode / signtool) — SUPPLY-001 requires the agent .exe + .msi to be signed", agentJob)
	}
	// And it must consume a signing identity from secrets (so signing is real in
	// CI, not merely possible locally).
	if !strings.Contains(string(raw), "WINDOWS_CODESIGN_PFX_BASE64") {
		t.Errorf("the release pipeline never references a Windows code-signing secret (WINDOWS_CODESIGN_PFX_BASE64) — " +
			"SUPPLY-001 requires the signing identity to be provisioned in CI, not just supported by the Makefile")
	}
	// And it must VERIFY / gate the signature so a tag cannot ship unsigned.
	if !strings.Contains(combined, "verify") {
		t.Errorf("the release Windows-agent job (%q) builds the agent but never verifies the signature / gates on it — "+
			"SUPPLY-001 requires the release to fail when the privileged agent is unsigned", agentJob)
	}

	// (2) The Makefile dist-windows recipe must Authenticode-sign BOTH the .exe and
	// the .msi when SIGN_PFX is set.
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	recipe := makeTargetBody(string(mk), "dist-windows")
	if recipe == "" {
		t.Fatal("Makefile has no dist-windows target")
	}
	if !strings.Contains(recipe, `if [ -n "$$SIGN_PFX" ]`) {
		t.Errorf("Makefile dist-windows does not gate signing on SIGN_PFX — SUPPLY-001 expects `osslsigncode` signing when SIGN_PFX is set")
	}
	if !strings.Contains(recipe, "osslsigncode sign") {
		t.Errorf("Makefile dist-windows never calls `osslsigncode sign` — SUPPLY-001 requires real Authenticode signing of the agent")
	}
	// Both the .exe and the .msi must be signed (the audit's exact gap: the MSI was
	// built unsigned). Count the sign invocations and the targets.
	if !strings.Contains(recipe, "trustctl-agent.exe -out") {
		t.Errorf("Makefile dist-windows does not sign trustctl-agent.exe (SUPPLY-001)")
	}
	if !strings.Contains(recipe, "trustctl-agent.msi -out") {
		t.Errorf("Makefile dist-windows does not sign trustctl-agent.msi (SUPPLY-001: the MSI shipped unsigned)")
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
	return out
}
