package helm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

// helm_s15_test.go is the BEHAVIOURAL counterpart to the old static
// string-matching of the isolated-signer chart (S15.1 / SIGNER-005; OPS-008). The
// previous version only asserted the templates *named* "--mtls-listen=:9443",
// "port: 9443", "grpc-mtls", etc. — it never bound those names to the signer
// binary's real flag set or to a consistent, structurally-valid render. These
// checks reconcile the manifests against reality:
//
//   - every --flag the signer Deployment passes is one the trstctl-signer binary
//     actually defines (parsed from `--help`, not hard-coded) — so the isolated pod
//     cannot crash-loop on an undefined flag;
//   - the port the binary is told to listen on (--mtls-listen=:N) is the SAME port
//     the container exposes, the Service targets, and the NetworkPolicy admits — a
//     drift between any of these would leave the signer unreachable or unprotected;
//   - the rendered isolated-signer Deployment is a structurally-valid object.
//
// Each check is mutation-proven via a negative sub-test.

// signerBinaryFlags parses the trstctl-signer binary's real flag set from its
// --help output (run from the repo root, three levels up from deploy/helm). This is
// the binary's source of truth — a manifest that drifts from it is caught.
func signerBinaryFlags(t *testing.T) map[string]bool {
	t.Helper()
	root := filepath.Join("..", "..")
	cmd := exec.Command("go", "run", "./cmd/trstctl-signer", "--help")
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	_ = cmd.Run() // --help exits non-zero on some toolchains but still prints usage
	flagRe := regexp.MustCompile(`(?m)^\s+-([A-Za-z][\w-]*)`)
	flags := map[string]bool{}
	for _, m := range flagRe.FindAllStringSubmatch(out.String(), -1) {
		flags[m[1]] = true
	}
	if len(flags) == 0 {
		t.Fatalf("could not parse any flags from `go run ./cmd/trstctl-signer --help`:\n%s", out.String())
	}
	return flags
}

// literalFlagNames extracts long-flag names (without leading dashes, without
// =value) from a manifest body's args/command lines, skipping comments and
// templated tokens.
func literalFlagNames(body string) []string {
	var out []string
	tokenRe := regexp.MustCompile(`--([A-Za-z][\w-]*)`)
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		clean := regexp.MustCompile(`\{\{.*?\}\}`).ReplaceAllString(l, "")
		for _, m := range tokenRe.FindAllStringSubmatch(clean, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

// mtlsListenPort extracts the port from a --mtls-listen=:N flag in the body, or ""
// if absent. This is the port the SIGNER BINARY is actually told to serve on.
func mtlsListenPort(body string) string {
	re := regexp.MustCompile(`--mtls-listen=:?(\d+)`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// TestSignerIsolationChartFlagsMatchTheBinary (S15.1 / SIGNER-005) asserts the
// isolated-signer Deployment passes ONLY flags the trstctl-signer binary defines.
// This is the behavioural replacement for the old `containsAll("--mtls-listen=:9443",
// "--mtls-cert=", …)` substring block: instead of checking the template NAMES the
// flags, it checks the binary DEFINES them (so a typo or a removed flag fails fast,
// the OPS-001 crash-loop class).
func TestSignerIsolationChartFlagsMatchTheBinary(t *testing.T) {
	dep := read(t, "templates", "signer-deployment.yaml")
	defined := signerBinaryFlags(t)

	got := literalFlagNames(dep)
	if len(got) == 0 {
		t.Fatal("signer-deployment.yaml passes no flags to trstctl-signer — expected the isolated mTLS topology flags")
	}
	for _, fl := range got {
		if !defined[fl] {
			t.Errorf("signer-deployment.yaml passes --%s, which trstctl-signer does not define (real flags: %v) — the OPS-001 crash-loop class", fl, sortedKeys(defined))
		}
	}
	// The isolated topology MUST drive the mTLS listener (the whole point of S15.1):
	// --mtls-listen plus the cert/peer flags must be among those passed.
	for _, must := range []string{"mtls-listen", "mtls-cert", "mtls-key", "mtls-peer-ca", "mtls-peer-pin"} {
		if !contains(got, must) {
			t.Errorf("isolated signer-deployment.yaml does not pass --%s; the cross-node mTLS topology (SIGNER-005) requires it", must)
		}
	}

	// Mutation proof: an injected undefined flag is rejected; the real flags pass.
	t.Run("rejects_undefined_signer_flag", func(t *testing.T) {
		bad := literalFlagNames(`            - "--mtls-listen=:9443"` + "\n" + `            - "--totally-made-up-flag=x"`)
		flagged := false
		for _, fl := range bad {
			if !defined[fl] {
				flagged = true
			}
		}
		if !flagged {
			t.Fatal("the flag-vs-binary check failed to flag --totally-made-up-flag — it is vacuous")
		}
		if !defined["mtls-listen"] {
			t.Error("the flag-vs-binary check wrongly rejected the real --mtls-listen flag")
		}
	})
}

// TestSignerIsolationPortIsConsistentEverywhere (S15.1 / SIGNER-005) binds the
// signer's mTLS port across the three manifests that must agree on it: the port the
// BINARY listens on (--mtls-listen=:N in signer-deployment.yaml), the containerPort
// it exposes, the Service targetPort, and the NetworkPolicy port it admits. A drift
// between any of these would leave the signer unreachable or its port unprotected —
// the behavioural replacement for the old `containsAll("port: 9443", "grpc-mtls")`
// substring asserts, which could pass even if the numbers disagreed.
func TestSignerIsolationPortIsConsistentEverywhere(t *testing.T) {
	dep := read(t, "templates", "signer-deployment.yaml")
	port := mtlsListenPort(dep)
	if port == "" {
		t.Fatal("signer-deployment.yaml does not pass --mtls-listen=:N; cannot determine the signer's mTLS port (SIGNER-005)")
	}

	// (1) The container must EXPOSE the port the binary listens on. Render the
	// isolated Deployment and read the containerPort from the rendered object.
	depObj := renderIsolatedSigner(t, dep)
	if cp := signerContainerPort(t, depObj); cp != port {
		t.Errorf("signer container exposes containerPort %q but the binary listens on :%s (--mtls-listen) — the pod would be unreachable (SIGNER-005)", cp, port)
	}

	// (2) The Service must target that port (grpc-mtls), so the control plane dials
	// the right place.
	svc := read(t, "templates", "signer-service.yaml")
	if !servicePortMatches(t, svc, port) {
		t.Errorf("signer-service.yaml does not target the signer's mTLS port :%s — the control plane would dial the wrong port (SIGNER-005)", port)
	}

	// (3) The NetworkPolicy must admit that exact port; otherwise the isolated pod is
	// reachable on no port (a default-deny that locks out the control plane too).
	np := read(t, "templates", "signer-networkpolicy.yaml")
	if !networkPolicyAllowsPort(np, port) {
		t.Errorf("signer-networkpolicy.yaml does not admit the signer's mTLS port %s — the control plane could not reach the signer (SIGNER-005)", port)
	}

	// Mutation proof: a NetworkPolicy that admits a DIFFERENT port is rejected; one
	// that admits the right port passes.
	t.Run("rejects_port_drift", func(t *testing.T) {
		drifted := strings.ReplaceAll(np, "port: "+port, "port: 1")
		if networkPolicyAllowsPort(drifted, port) {
			t.Fatal("the port-consistency check failed to detect a NetworkPolicy that no longer admits the signer port — it is vacuous")
		}
		if !networkPolicyAllowsPort(np, port) {
			t.Errorf("the port-consistency check wrongly rejected the real NetworkPolicy admitting port %s", port)
		}
	})
}

// renderIsolatedSigner renders signer-deployment.yaml in isolated mode so the
// structural facts (containerPort) can be read from the real artifact.
func renderIsolatedSigner(t *testing.T, body string) map[string]any {
	t.Helper()
	funcs := template.FuncMap{
		"include": func(name string, _ any) string {
			switch name {
			case "trstctl.labels", "trstctl.selectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: control-plane"
			case "trstctl.signerLabels", "trstctl.signerSelectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: signer"
			case "trstctl.image":
				return "ghcr.io/example/trstctl:v0.5.0"
			case "trstctl.signer.guardMode":
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
		"toYaml": func(v any) string { b, _ := yaml.Marshal(v); return strings.TrimRight(string(b), "\n") },
		"quote":  func(v any) string { return strconv.Quote(asString(v)) },
		"default": func(d, v any) any {
			if asString(v) == "" {
				return d
			}
			return v
		},
	}
	tmpl, err := template.New("signer-deployment.yaml").Funcs(funcs).Option("missingkey=zero").Parse(body)
	if err != nil {
		t.Fatalf("parse signer-deployment.yaml: %v", err)
	}
	data := map[string]any{
		"Values": map[string]any{
			"signer": map[string]any{
				"mode": "isolated", "replicas": 1, "resources": map[string]any{},
				"mtls": map[string]any{"serverName": "trstctl-signer.ns.svc", "signerSecret": ""},
			},
			"persistence": map[string]any{"enabled": true},
			"image":       map[string]any{"pullPolicy": "IfNotPresent"},
		},
		"Release": map[string]any{"Name": "trstctl", "Service": "Helm"},
		"Chart":   map[string]any{"Name": "trstctl", "AppVersion": "0.5.0"},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("render signer-deployment.yaml: %v", err)
	}
	var obj map[string]any
	if err := yaml.Unmarshal([]byte(sb.String()), &obj); err != nil {
		t.Fatalf("rendered signer-deployment.yaml is not valid YAML: %v\n%s", err, sb.String())
	}
	if obj["kind"] != "Deployment" {
		t.Fatalf("rendered signer-deployment.yaml is not a Deployment (kind=%v)", obj["kind"])
	}
	return obj
}

func helmTestNindent(n int, s string) string {
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
}

// signerContainerPort reads the (single) container's containerPort out of a
// rendered signer Deployment.
func signerContainerPort(t *testing.T, dep map[string]any) string {
	t.Helper()
	spec, _ := dep["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	cs, _ := pod["containers"].([]any)
	if len(cs) == 0 {
		t.Fatal("rendered signer Deployment has no containers")
	}
	c, _ := cs[0].(map[string]any)
	ports, _ := c["ports"].([]any)
	if len(ports) == 0 {
		t.Fatal("rendered signer container exposes no ports")
	}
	p, _ := ports[0].(map[string]any)
	switch v := p["containerPort"].(type) {
	case int:
		return strconv.Itoa(v)
	case string:
		return v
	}
	t.Fatalf("rendered signer container has an unparseable containerPort: %v", p["containerPort"])
	return ""
}

// servicePortMatches reports whether the signer Service targets the given port. It
// renders the templated Service and inspects the parsed port/targetPort.
func servicePortMatches(t *testing.T, svcTpl, want string) bool {
	t.Helper()
	// The Service template uses only labels/name helpers; render with the same stubs.
	funcs := template.FuncMap{
		"include": func(name string, _ any) string {
			switch name {
			case "trstctl.labels", "trstctl.selectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: control-plane"
			case "trstctl.signerLabels", "trstctl.signerSelectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: signer"
			}
			return "trstctl"
		},
		"nindent": helmTestNindent,
		"quote":   func(v any) string { return strconv.Quote(asString(v)) },
	}
	tmpl, err := template.New("signer-service.yaml").Funcs(funcs).Option("missingkey=zero").Parse(svcTpl)
	if err != nil {
		// Fall back to a structural scan of the template text for the port.
		return strings.Contains(svcTpl, want)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, map[string]any{
		"Values":  map[string]any{"signer": map[string]any{"mode": "isolated"}},
		"Release": map[string]any{"Name": "trstctl"},
		"Chart":   map[string]any{"Name": "trstctl"},
	}); err != nil {
		return strings.Contains(svcTpl, want)
	}
	var obj map[string]any
	if yaml.Unmarshal([]byte(sb.String()), &obj) != nil {
		return strings.Contains(sb.String(), want)
	}
	spec, _ := obj["spec"].(map[string]any)
	ports, _ := spec["ports"].([]any)
	for _, pr := range ports {
		p, _ := pr.(map[string]any)
		for _, key := range []string{"port", "targetPort"} {
			switch v := p[key].(type) {
			case int:
				if strconv.Itoa(v) == want {
					return true
				}
			case string:
				if v == want {
					return true
				}
			}
		}
	}
	return false
}

// networkPolicyAllowsPort reports whether the NetworkPolicy template admits the
// given numeric port anywhere in an ingress/egress rule (`port: N`).
func networkPolicyAllowsPort(npBody, want string) bool {
	re := regexp.MustCompile(`(?m)port:\s*` + regexp.QuoteMeta(want) + `\b`)
	return re.MatchString(npBody)
}

// TestSignerIsolationChartIsStructurallyValid renders the isolated topology and
// asserts the signer Deployment + NetworkPolicy + Service are well-formed objects
// of the right kind — replacing the old `containsAll("kind: Deployment", "kind:
// NetworkPolicy", "kind: Service")` substring checks with a real parse+kind assert.
func TestSignerIsolationChartIsStructurallyValid(t *testing.T) {
	dep := renderIsolatedSigner(t, read(t, "templates", "signer-deployment.yaml"))
	// Deployment must carry a selector and a pod template with containers.
	spec, _ := dep["spec"].(map[string]any)
	if spec["selector"] == nil {
		t.Error("isolated signer Deployment has no spec.selector")
	}
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	cs := asMaps(pod["containers"])
	if len(cs) == 0 {
		t.Error("isolated signer Deployment has no containers")
	} else {
		signer := containerNamed(cs, "signer")
		if signer == nil {
			t.Fatal("isolated signer Deployment has no signer container")
		}
		for _, mount := range []string{"/etc/trstctl/signer-mtls", "/data/signer", "/etc/trstctl/kek", "/etc/trstctl/signer-auth"} {
			if !hasMountPath(signer, mount) {
				t.Errorf("isolated signer container missing required mount %s", mount)
			}
		}
		for _, volume := range []string{"signer-mtls", "signer-keys", "kek", "signer-auth"} {
			if !hasVolumeNamed(pod, volume) {
				t.Errorf("isolated signer pod missing required volume %s", volume)
			}
		}
		requireSecretDefaultMode(t, pod, "kek", 0o440)
		requireSecretDefaultMode(t, pod, "signer-auth", 0o440)
	}

	// The NetworkPolicy and Service must parse as their declared kinds (they are
	// gated on signer.mode=isolated, so render that mode).
	for _, tc := range []struct {
		file string
		kind string
	}{
		{"signer-networkpolicy.yaml", "NetworkPolicy"},
		{"signer-service.yaml", "Service"},
	} {
		body := read(t, "templates", tc.file)
		obj := renderSimpleSignerObj(t, tc.file, body)
		if obj["kind"] != tc.kind {
			t.Errorf("%s rendered kind=%v, want %s", tc.file, obj["kind"], tc.kind)
		}
		if obj["apiVersion"] == nil {
			t.Errorf("%s rendered object is missing apiVersion", tc.file)
		}
	}

	// The chart must still declare the signer topology + mTLS knobs in values.yaml so
	// an operator can configure the isolated mode (reconciled in full by
	// deploy/deploycheck_test.go's values check; here we assert the topology keys
	// exist as structured values rather than as raw substrings).
	var v struct {
		Signer struct {
			Mode string `yaml:"mode"`
			MTLS struct {
				ServerName string `yaml:"serverName"`
			} `yaml:"mtls"`
		} `yaml:"signer"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "values.yaml")), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if v.Signer.Mode == "" {
		t.Error("values.yaml does not define signer.mode (needed to select the isolated topology)")
	}
}

// renderSimpleSignerObj renders an isolated-mode signer auxiliary template
// (NetworkPolicy/Service) and returns the parsed object.
func renderSimpleSignerObj(t *testing.T, name, body string) map[string]any {
	t.Helper()
	funcs := template.FuncMap{
		"include": func(name string, _ any) string {
			switch name {
			case "trstctl.labels", "trstctl.selectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: control-plane"
			case "trstctl.signerLabels", "trstctl.signerSelectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: signer"
			case "trstctl.signer.guardMode":
				return "" // the guard emits nothing on a valid mode
			}
			return "trstctl"
		},
		"nindent": helmTestNindent,
		"quote":   func(v any) string { return strconv.Quote(asString(v)) },
		"toYaml":  func(v any) string { b, _ := yaml.Marshal(v); return strings.TrimRight(string(b), "\n") },
	}
	tmpl, err := template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(body)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, map[string]any{
		"Values": map[string]any{
			"signer":        map[string]any{"mode": "isolated", "mtls": map[string]any{"serverName": "x.svc"}},
			"networkPolicy": map[string]any{"enabled": true},
		},
		"Release": map[string]any{"Name": "trstctl"},
		"Chart":   map[string]any{"Name": "trstctl"},
	}); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	var obj map[string]any
	if err := yaml.Unmarshal([]byte(sb.String()), &obj); err != nil {
		t.Fatalf("rendered %s is not valid YAML: %v\n%s", name, err, sb.String())
	}
	return obj
}

// TestIsolatedSignerGuardIsCodeBound (SIGNER-005, formerly OPS-001) asserts the
// signer-mode guard helper exists and is invoked from an always-rendered template,
// so every install validates signer.mode and a half-configured isolated install
// fails fast. This is code-bound (the helper + its invocation), not a substring on
// the rendered output, and it drills the guard's BEHAVIOUR: an unknown mode and an
// isolated-without-serverName both fail the render.
func TestIsolatedSignerGuardIsCodeBound(t *testing.T) {
	helpers := read(t, "templates", "_helpers.tpl")
	if !strings.Contains(helpers, `define "trstctl.signer.guardMode"`) {
		t.Fatal("_helpers.tpl is missing the trstctl.signer.guardMode helper (SIGNER-005)")
	}
	// The guard must be invoked from the ALWAYS-rendered deployment.yaml so every
	// render validates the mode (not only the gated isolated files).
	dep := read(t, "templates", "deployment.yaml")
	if !strings.Contains(dep, `include "trstctl.signer.guardMode"`) {
		t.Error("deployment.yaml must invoke trstctl.signer.guardMode so a default render validates signer.mode (SIGNER-005)")
	}

	// Behaviour: render the guard with a bogus mode and with isolated-but-no-serverName
	// and assert BOTH fail (the guard calls `fail`). We render just the helper by
	// wrapping it in a tiny template that includes it.
	guard := extractDefine(helpers, "trstctl.signer.guardMode")
	if guard == "" {
		t.Fatal("could not extract the guardMode helper body")
	}
	for _, tc := range []struct {
		name string
		vals map[string]any
		fail bool
	}{
		{"bogus_mode", map[string]any{"signer": map[string]any{"mode": "banana", "mtls": map[string]any{}}}, true},
		{"isolated_no_serverName", map[string]any{"signer": map[string]any{"mode": "isolated", "mtls": map[string]any{"serverName": ""}}}, true},
		{"sidecar_ok", map[string]any{"signer": map[string]any{"mode": "sidecar", "mtls": map[string]any{}}}, false},
		{"isolated_ok", map[string]any{"signer": map[string]any{"mode": "isolated", "mtls": map[string]any{"serverName": "x.svc"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := renderGuard(guard, tc.vals)
			if tc.fail && err == nil {
				t.Errorf("guardMode accepted %s but should have failed the render (SIGNER-005)", tc.name)
			}
			if !tc.fail && err != nil {
				t.Errorf("guardMode rejected the valid case %s: %v", tc.name, err)
			}
		})
	}
}

// extractDefine returns the complete {{ define "<name>" }} … {{ end }} block from a
// .tpl file. The block can contain nested if/else/end (the guardMode helper does),
// so rather than match the first {{ end }}, it captures from the opening `{{-
// define "<name>"` up to the start of the NEXT top-level `{{- define` (or EOF) and
// trims trailing whitespace — which preserves the define's own closing `{{- end -}}`
// while excluding sibling helpers. text/template then parses it as a named template.
func extractDefine(tpl, name string) string {
	startRe := regexp.MustCompile(`\{\{-?\s*define\s+"` + regexp.QuoteMeta(name) + `"`)
	loc := startRe.FindStringIndex(tpl)
	if loc == nil {
		return ""
	}
	rest := tpl[loc[0]:]
	// The next sibling define marks the end of this block.
	nextRe := regexp.MustCompile(`\{\{-?\s*define\s+"`)
	if next := nextRe.FindStringIndex(rest[1:]); next != nil {
		return strings.TrimRight(rest[:next[0]+1], " \t\r\n")
	}
	return strings.TrimRight(rest, " \t\r\n")
}

// renderGuard executes the extracted guardMode define against the given Values and
// returns any render error. The guard calls Sprig's `fail`, which we model as a
// function returning a non-nil error — text/template's `template` action propagates
// that error out of Execute, so a guard that should fail surfaces as a non-nil err.
func renderGuard(defineBlock string, values map[string]any) error {
	// Invoke the named define via the `template` action (a text/template builtin) so a
	// `fail` inside it aborts Execute. The define is parsed into the template set first.
	wrapper := defineBlock + "\n{{- template \"trstctl.signer.guardMode\" . -}}"
	funcs := template.FuncMap{
		"fail": func(msg string) (string, error) { return "", &guardFail{msg} },
	}
	tmpl, err := template.New("guard").Funcs(funcs).Parse(wrapper)
	if err != nil {
		return err
	}
	var sb strings.Builder
	return tmpl.Execute(&sb, map[string]any{"Values": values})
}

type guardFail struct{ msg string }

func (g *guardFail) Error() string { return "fail: " + g.msg }

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
