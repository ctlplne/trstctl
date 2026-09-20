// SPDX-License-Identifier: BUSL-1.1

package iac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"gopkg.in/yaml.v3"
)

type resourcePlan struct {
	ProfileName           string `json:"profileName"`
	CertificateCommonName string `json:"certificateCommonName"`
	SecretName            string `json:"secretName"`
}

func TestGitOpsAndPulumiExamplesProvisionTrstctlResources(t *testing.T) {
	root := repoRoot(t)
	gitopsPlan := parseGitOpsTerraformPlan(t, filepath.Join(root, "deploy/iac/gitops/base/trstctl-terraform-config.yaml"))
	pulumiPlan := parsePulumiPlan(t, filepath.Join(root, "deploy/iac/pulumi/trstctl-resources/trstctl.resources.json"))
	if gitopsPlan != pulumiPlan {
		t.Fatalf("GitOps and Pulumi examples should provision the same resources:\nGitOps: %+v\nPulumi: %+v", gitopsPlan, pulumiPlan)
	}

	api := newFakeTrstctlAPI()
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	applyPlan(t, srv.URL, "gitops", gitopsPlan)
	applyPlan(t, srv.URL, "pulumi", pulumiPlan)
	api.assertProvisioned(t)
}

func TestGitOpsControllersAndGitLabTemplateAreWired(t *testing.T) {
	root := repoRoot(t)
	assertYAMLContains(t, filepath.Join(root, "deploy/iac/gitops/argocd/application.yaml"), "kind", "Application")
	assertYAMLContains(t, filepath.Join(root, "deploy/iac/gitops/argocd/application.yaml"), "path", "deploy/iac/gitops/base")
	assertYAMLContains(t, filepath.Join(root, "deploy/iac/gitops/flux/kustomization.yaml"), "kind", "Kustomization")
	assertYAMLContains(t, filepath.Join(root, "deploy/iac/gitops/flux/kustomization.yaml"), "path", "./deploy/iac/gitops/base")

	gitlab := read(t, filepath.Join(root, "deploy/iac/gitlab/trstctl-iac.gitlab-ci.yml"))
	for _, want := range []string{
		"trstctl:terraform:plan",
		"trstctl:terraform:apply",
		"deploy/iac/gitops/base",
		"TRSTCTL_ENDPOINT",
		"TRSTCTL_TOKEN",
	} {
		if !strings.Contains(gitlab, want) {
			t.Fatalf("GitLab CI template missing %q", want)
		}
	}

	pulumiIndex := read(t, filepath.Join(root, "deploy/iac/pulumi/trstctl-resources/index.ts"))
	for _, want := range []string{"ProfileResource", "PkiCertificateResource", "SecretResource", "trstctl.resources.json"} {
		if !strings.Contains(pulumiIndex, want) {
			t.Fatalf("Pulumi example missing %q", want)
		}
	}
}

func parseGitOpsTerraformPlan(t *testing.T, configMapPath string) resourcePlan {
	t.Helper()
	var cm struct {
		Kind string            `yaml:"kind"`
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(read(t, configMapPath)), &cm); err != nil {
		t.Fatalf("parse %s: %v", configMapPath, err)
	}
	if cm.Kind != "ConfigMap" {
		t.Fatalf("%s kind = %q, want ConfigMap", configMapPath, cm.Kind)
	}
	mainTF := cm.Data["main.tf"]
	if strings.TrimSpace(mainTF) == "" {
		t.Fatalf("%s does not carry data.main.tf", configMapPath)
	}
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL([]byte(mainTF), "main.tf")
	if diags.HasErrors() {
		t.Fatalf("parse main.tf: %s", diags.Error())
	}
	content, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "resource", LabelNames: []string{"type", "name"}}},
	})
	if diags.HasErrors() {
		t.Fatalf("read main.tf resources: %s", diags.Error())
	}
	var plan resourcePlan
	for _, block := range content.Blocks {
		attrs, diags := block.Body.JustAttributes()
		if diags.HasErrors() {
			t.Fatalf("read %s.%s attributes: %s", block.Labels[0], block.Labels[1], diags.Error())
		}
		switch block.Labels[0] {
		case "trstctl_profile":
			plan.ProfileName = hclString(t, attrs, "name")
		case "trstctl_pki_certificate":
			plan.CertificateCommonName = hclString(t, attrs, "common_name")
		case "trstctl_secret":
			plan.SecretName = hclString(t, attrs, "name")
		}
	}
	if plan.ProfileName == "" || plan.CertificateCommonName == "" || plan.SecretName == "" {
		t.Fatalf("main.tf does not define profile, PKI certificate, and secret resources: %+v", plan)
	}
	return plan
}

func parsePulumiPlan(t *testing.T, path string) resourcePlan {
	t.Helper()
	var plan resourcePlan
	if err := json.Unmarshal([]byte(read(t, path)), &plan); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if plan.ProfileName == "" || plan.CertificateCommonName == "" || plan.SecretName == "" {
		t.Fatalf("Pulumi resource plan incomplete: %+v", plan)
	}
	return plan
}

func hclString(t *testing.T, attrs hcl.Attributes, name string) string {
	t.Helper()
	attr, ok := attrs[name]
	if !ok {
		return ""
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		t.Fatalf("evaluate %s: %s", name, diags.Error())
	}
	return value.AsString()
}

func applyPlan(t *testing.T, endpoint, source string, plan resourcePlan) {
	t.Helper()
	postJSON(t, endpoint+"/api/v1/profiles", source, map[string]any{
		"name":       plan.ProfileName,
		"version":    1,
		"created_by": source,
		"spec":       map[string]any{"allowed_key_algorithms": []string{"ECDSA-P256"}, "max_validity": "1h"},
	})
	postJSON(t, endpoint+"/api/v1/secrets/pki", source, map[string]any{
		"common_name": plan.CertificateCommonName,
		"ttl_seconds": 900,
	})
	postJSON(t, endpoint+"/api/v1/secrets/store", source, map[string]any{
		"name":      plan.SecretName,
		"plaintext": "example-value",
	})
}

func postJSON(t *testing.T, url, source string, body map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Idempotency-Key", source+"-"+strings.TrimPrefix(strings.ReplaceAll(req.URL.Path, "/", "-"), "-"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IaC-Source", source)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("POST %s status %d: %s", req.URL.Path, res.StatusCode, string(b))
	}
}

type fakeTrstctlAPI struct {
	mu    sync.Mutex
	paths map[string]int
}

func newFakeTrstctlAPI() *fakeTrstctlAPI {
	return &fakeTrstctlAPI{paths: map[string]int{}}
}

func (f *fakeTrstctlAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "missing auth or idempotency", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/api/v1/profiles", "/api/v1/secrets/pki", "/api/v1/secrets/store":
			f.mu.Lock()
			f.paths[r.URL.Path]++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	})
}

func (f *fakeTrstctlAPI) assertProvisioned(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/api/v1/profiles", "/api/v1/secrets/pki", "/api/v1/secrets/store"} {
		if got := f.paths[path]; got != 2 {
			t.Fatalf("%s called %d times, want twice (GitOps + Pulumi)", path, got)
		}
	}
}

func assertYAMLContains(t *testing.T, path, key, value string) {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(read(t, path)))
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if yamlTreeContains(doc, key, value) {
			return
		}
	}
	t.Fatalf("%s does not contain %s=%q", path, key, value)
}

func yamlTreeContains(v any, key, value string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == key {
				if s, ok := child.(string); ok && s == value {
					return true
				}
			}
			if yamlTreeContains(child, key, value) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if yamlTreeContains(child, key, value) {
				return true
			}
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "../.."))
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
