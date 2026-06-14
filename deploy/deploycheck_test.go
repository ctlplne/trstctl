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
//     one that binary really defines. This FAILS on the pre-fix tree, where the
//     isolated signer manifest passed `--mtls-listen` — a flag the signer does not
//     define — so it would crash-loop (OPS-001).
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
	// the signer are LITERAL — and the whole reason for this test is OPS-008's
	// requirement that "the new flag-vs-binary test fails on the current
	// --mtls-listen manifest until OPS-001 is fixed". So scan the template's
	// literal flag tokens directly against the signer's real flag set.
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
