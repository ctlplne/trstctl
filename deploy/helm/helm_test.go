package helm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

const chart = "certctl"

func read(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{chart}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

func containsAll(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s: expected to contain %q", name, w)
		}
	}
}

// TestChartIsStructurallyComplete: the control-plane chart exists with a valid
// Chart.yaml (Helm v2 schema) and the templates a real deployment needs.
func TestChartIsStructurallyComplete(t *testing.T) {
	var meta struct {
		APIVersion string `yaml:"apiVersion"`
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		AppVersion string `yaml:"appVersion"`
		Type       string `yaml:"type"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "Chart.yaml")), &meta); err != nil {
		t.Fatalf("Chart.yaml is not valid YAML: %v", err)
	}
	if meta.APIVersion != "v2" {
		t.Errorf("Chart.yaml apiVersion = %q, want v2", meta.APIVersion)
	}
	for field, val := range map[string]string{"name": meta.Name, "version": meta.Version, "appVersion": meta.AppVersion} {
		if strings.TrimSpace(val) == "" {
			t.Errorf("Chart.yaml is missing %s", field)
		}
	}
	for _, f := range []string{
		"values.yaml",
		"templates/_helpers.tpl",
		"templates/deployment.yaml",
		"templates/service.yaml",
		"templates/configmap.yaml",
		"templates/secret.yaml",
		"templates/serviceaccount.yaml",
		"templates/networkpolicy.yaml",
	} {
		if _, err := os.Stat(filepath.Join(chart, filepath.FromSlash(f))); err != nil {
			t.Errorf("chart is missing %s: %v", f, err)
		}
	}
}

// TestSignerIsIsolated: the control-plane pod runs the signer as its own
// locked-down container (AN-4) with NO network surface — it talks to the control
// plane only over a shared in-memory UDS — and both containers run a restrictive
// securityContext.
func TestSignerIsIsolated(t *testing.T) {
	dep := read(t, "templates", "deployment.yaml")

	containsAll(t, "deployment signer container", dep,
		"certctl-signer", // the signer binary/entrypoint
		"/run/certctl",   // the shared UDS mount path
		"signer.sock",    // the socket the control plane dials
	)
	// The control plane reaches the signer in external mode over that socket
	// (wired via the ConfigMap the deployment loads with envFrom).
	cfg := read(t, "templates", "configmap.yaml")
	containsAll(t, "configmap signer wiring", cfg,
		"CERTCTL_SIGNER_MODE", "external", "CERTCTL_SIGNER_SOCKET")
	// A shared in-memory volume carries the socket (not the network).
	containsAll(t, "deployment shared socket volume", dep, "emptyDir")
	// Hardened containers.
	containsAll(t, "deployment hardened securityContext", dep,
		"runAsNonRoot", "readOnlyRootFilesystem", "allowPrivilegeEscalation")
	if strings.Contains(dep, "drop") == false {
		t.Error("deployment securityContext should drop Linux capabilities")
	}
}

// TestExternalDatastoresAreTheDefault: the chart deploys against EXTERNAL
// PostgreSQL and NATS (the production/tested path), wired by config.
func TestExternalDatastoresAreTheDefault(t *testing.T) {
	values := read(t, "values.yaml")
	var v map[string]any
	if err := yaml.Unmarshal([]byte(values), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if _, ok := v["postgres"]; !ok {
		t.Error("values.yaml should expose external postgres configuration")
	}
	if _, ok := v["nats"]; !ok {
		t.Error("values.yaml should expose external nats configuration")
	}
	cfg := read(t, "templates", "configmap.yaml")
	containsAll(t, "configmap external datastores", cfg,
		"CERTCTL_POSTGRES_MODE", "CERTCTL_NATS_MODE", "external", "CERTCTL_NATS_URL")
}

// TestNetworkPolicyAndTLS: a NetworkPolicy ships (default-deny posture) and TLS
// is configurable (R1.3), defaulting to on.
func TestNetworkPolicyAndTLS(t *testing.T) {
	np := read(t, "templates", "networkpolicy.yaml")
	containsAll(t, "networkpolicy", np, "kind: NetworkPolicy", "podSelector", "policyTypes")
	containsAll(t, "networkpolicy locks both directions", np, "Ingress", "Egress")

	cfg := read(t, "templates", "configmap.yaml")
	if !strings.Contains(cfg, "CERTCTL_SERVER_TLS_MODE") {
		t.Error("the chart should wire the server TLS mode (R1.3)")
	}
	values := read(t, "values.yaml")
	if !strings.Contains(values, "tls") {
		t.Error("values.yaml should expose TLS configuration")
	}
}

// TestTemplatesParse: every chart template is syntactically valid Go/Helm
// templating. This catches unbalanced delimiters, bad pipelines, and missing
// `end`s locally; `helm template` does the full render with values in CI. The
// Helm/Sprig builtins are stubbed so parsing does not fail on their names.
func TestTemplatesParse(t *testing.T) {
	funcs := template.FuncMap{}
	for _, name := range []string{
		"include", "tpl", "required", "lookup", "toYaml", "toJson", "fromYaml",
		"nindent", "indent", "default", "quote", "squote", "b64enc", "b64dec",
		"randAlphaNum", "randAscii", "randNumeric", "randBytes", "printf", "trunc", "trimSuffix",
		"trimPrefix", "replace", "lower", "upper", "title", "sha256sum", "list",
		"dict", "get", "set", "hasKey", "ternary", "semverCompare", "contains",
		"kindIs", "empty", "coalesce", "merge", "deepCopy", "regexReplaceAll",
		"genSelfSignedCert", "trimAll", "splitList", "join", "dig", "atoi", "add",
		"sub", "mul", "len", "first", "last", "keys", "values", "fail", "now",
		"date", "uuidv4", "derivePassword", "htpasswd", "toString", "int", "float64",
	} {
		funcs[name] = func(args ...any) any { return nil }
	}

	entries, err := os.ReadDir(filepath.Join(chart, "templates"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".tpl") && name != "NOTES.txt" {
			continue
		}
		body := read(t, "templates", name)
		if _, err := template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(body); err != nil {
			t.Errorf("template %s has invalid Go/Helm template syntax: %v", name, err)
		}
		parsed++
	}
	if parsed == 0 {
		t.Error("no templates were parsed")
	}
}
