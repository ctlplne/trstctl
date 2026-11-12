// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ciCommand finds the template's trstctl-cli line for a subcommand.
func ciCommand(t *testing.T, template []byte, sub string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*(?:run:\s*|-\s*)?(trstctl-cli cbom ` + sub + ` .+)$`)
	m := re.FindSubmatch(template)
	if m == nil {
		t.Fatalf("the template runs no trstctl-cli cbom %s", sub)
	}
	return strings.TrimSpace(string(m[1]))
}

// shellWords expands $VAR, ${VAR} and ${VAR:-default} from vars and splits
// the line into words, honoring double quotes, as the runner's shell does
// for these lines.
func shellWords(line string, vars map[string]string) []string {
	defaulted := regexp.MustCompile(`\$\{([A-Z_]+):-([^}]*)\}`)
	line = defaulted.ReplaceAllStringFunc(line, func(m string) string {
		parts := defaulted.FindStringSubmatch(m)
		if v := vars[parts[1]]; v != "" {
			return v
		}
		return os.Expand(parts[2], func(k string) string { return vars[k] })
	})
	line = os.Expand(line, func(k string) string { return vars[k] })
	var words []string
	var cur strings.Builder
	inQuote, started := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote, started = !inQuote, true
		case r == ' ' && !inQuote:
			if started {
				words = append(words, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		words = append(words, cur.String())
	}
	return words
}

// X6-L7: the GitHub Actions and GitLab CI templates run the CLI's own
// commands: scan-source writes a CycloneDX CBOM of the repository's crypto
// uses, and import posts it to the control plane with the CI's token, under
// source:<repository> unless the pipeline names another source.
func TestCITemplatesRunScanSourceAndImportX6L7(t *testing.T) {
	templates, err := filepath.Abs(filepath.Join("..", "..", "deploy", "ci"))
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	code := "package main\n\nimport (\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\nfunc main() { _, _ = rsa.GenerateKey(rand.Reader, 1024) }\n"
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	type imported struct {
		source, auth, key string
		bom               map[string]any
	}
	var got []imported
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/cbom/imports" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var bom map[string]any
		_ = json.Unmarshal(raw, &bom)
		got = append(got, imported{source: r.URL.Query().Get("source"), auth: r.Header.Get("Authorization"), key: r.Header.Get("Idempotency-Key"), bom: bom})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"source": r.URL.Query().Get("source"), "run_id": "r1", "components": 1, "findings": 1, "asset_ids": []string{}})
	}))
	t.Cleanup(stub.Close)

	for _, tc := range []struct {
		file, wantSource string
		vars             map[string]string
	}{
		{"github/trstctl-cbom.yml", "source:acme/payments", map[string]string{"SCAN_DIR": repo, "REPOSITORY": "acme/payments"}},
		{"github/trstctl-cbom.yml", "vendor:acme-hsm", map[string]string{"SCAN_DIR": repo, "REPOSITORY": "acme/payments", "CBOM_SOURCE": "vendor:acme-hsm"}},
		{"gitlab/trstctl-cbom.gitlab-ci.yml", "source:acme/platform/payments", map[string]string{"SCAN_DIR": repo, "CI_PROJECT_PATH": "acme/platform/payments"}},
	} {
		template, err := os.ReadFile(filepath.Join(templates, tc.file)) // #nosec G304 -- test reads the repo's own shipped templates (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		work := t.TempDir()
		tc.vars["RUNNER_TEMP"] = work
		chdir(t, work)
		env := Env{Server: stub.URL, Token: "ci-scoped-token"} // #nosec G101 -- a stand-in's test token, not a credential (CWE-798)
		for _, sub := range []string{"scan-source", "import"} {
			words := shellWords(ciCommand(t, template, sub), tc.vars)
			if words[0] != "trstctl-cli" {
				t.Fatalf("%s: %v", tc.file, words)
			}
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), words[1:], env, strings.NewReader(""), &stdout, &stderr); code != 0 {
				t.Fatalf("%s: trstctl-cli %v exited %d: %s", tc.file, words[1:], code, stderr.String())
			}
		}
		last := got[len(got)-1]
		components, _ := last.bom["components"].([]any)
		if last.source != tc.wantSource || last.auth != "Bearer ci-scoped-token" || last.key == "" ||
			last.bom["bomFormat"] != "CycloneDX" || len(components) == 0 {
			t.Fatalf("%s imported %+v", tc.file, last)
		}
	}
	if len(got) != 3 {
		t.Fatalf("%d imports, want 3", len(got))
	}
}

// chdir moves the test into dir for a template's relative paths.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}
