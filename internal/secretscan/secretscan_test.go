// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
)

func TestParseGitleaksDropsValueAndIngests(t *testing.T) {
	// A gitleaks report carrying a real-looking secret value.
	report := []byte(`[{"RuleID":"aws-access-token","File":"config.yaml","StartLine":12,"Secret":"AKIASECRETLEAKEDVALUE","Match":"key=AKIASECRETLEAKEDVALUE"}]`)
	findings, err := ParseGitleaks(report)
	if err != nil || len(findings) != 1 {
		t.Fatalf("parse = %d (err %v)", len(findings), err)
	}
	g := graph.New()
	rec := &auditsink.Recorder{}
	triggered := ""
	ing := New("t1", g, rec, func(_ context.Context, ref string) error { triggered = ref; return nil })
	if _, err := ing.Ingest(context.Background(), findings, true); err != nil {
		t.Fatal(err)
	}
	// Finding appears in the graph with provenance.
	if _, ok := g.Node("leak:gitleaks:config.yaml:12"); !ok {
		t.Error("finding not merged into the graph")
	}
	// Drove the compromise workflow.
	if triggered != "aws-access-token@config.yaml" {
		t.Errorf("compromise trigger = %q", triggered)
	}
	// The defining safety test: the secret value never appears anywhere we persist.
	for _, r := range rec.Records() {
		if bytes.Contains(r.Data, []byte("AKIASECRETLEAKEDVALUE")) {
			t.Fatal("leaked secret value persisted into the audit log")
		}
	}
	for _, n := range g.Nodes() {
		for _, v := range n.Attrs {
			if v == "AKIASECRETLEAKEDVALUE" || bytes.Contains([]byte(v), []byte("AKIASECRETLEAKED")) {
				t.Fatal("leaked secret value persisted into the graph")
			}
		}
	}
}

func TestParseGitleaksInstallerProvisioningPinned(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	installer := readRepoFile(t, root, "tools/gitleaks/install.sh")
	workflow := readRepoFile(t, root, ".github/workflows/security.yml")
	docs := readRepoFile(t, root, "docs/configuration.md")

	if strings.Contains(installer, "go install ") {
		t.Fatal("Gitleaks provisioning must use the checksum-verified release tarball, not the unsupported Go package path")
	}
	for _, want := range []string{
		`supported_version="v8.27.2"`,
		`gitleaks_8.27.2_linux_x64.tar.gz`,
		`141c3b2dede46d8b3a53b47116da756bd223decc0374797559a6b50ecba5590c`,
		`gitleaks_8.27.2_darwin_arm64.tar.gz`,
		`ae969ca6b04c8621bae4dbb707cb4293264904c0e890901f0643c266d5e02bea`,
		`verify_checksum`,
	} {
		if !strings.Contains(installer, want) {
			t.Fatalf("installer missing %q", want)
		}
	}
	if !strings.Contains(workflow, `GITLEAKS_VERSION: "v8.27.2"`) {
		t.Fatal("security workflow must pin the same Gitleaks version as the served scanner")
	}
	for _, want := range []string{
		"tools/gitleaks/install.sh",
		"Served Gitleaks scan smoke",
		"TRSTCTL_GITLEAKS_BIN",
		"Test(ServedGitleaksScanDetectsPlantedSecret|ServedDeepSecretScanCAPSCAN03UsesHistoryAndCustomRules|ParseGitleaks)",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("security workflow missing %q", want)
		}
	}
	for _, want := range []string{"Gitleaks `v8.27.2`", "checksum-verified", "tools/gitleaks/install.sh"} {
		if !strings.Contains(docs, want) {
			t.Fatalf("configuration docs missing %q", want)
		}
	}
}

func TestRepositoryGitleaksHistoryExceptionsPinProvenNonSecrets(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	ignore := readRepoFile(t, root, ".gitleaksignore")
	labName := strings.Join([]string{"p", "q", "c"}, "") + "lab"
	for _, fingerprint := range []string{
		"5492dd461025416c8519ec266324de743d8d1207:tools/" + labName + "/main.go:private-key:858",
		"97c94bab72b2d632ae803ddf984a4b0b39acd2ea:internal/webui/dist/assets/Journeys-CgL9FFZL.js:generic-api-key:8",
		"97c94bab72b2d632ae803ddf984a4b0b39acd2ea:internal/webui/dist/assets/Journeys-CgL9FFZL.js:generic-api-key:13",
		"89b00febd786690475ccd4b2beede7ad1a444505:web/src/i18n/catalog.en-US.runtime.gen.ts:generic-api-key:3056",
	} {
		if got := strings.Count(ignore, fingerprint); got != 1 {
			t.Errorf("history exception %q occurs %d times, want exactly once", fingerprint, got)
		}
	}
}

func TestParseTrufflehog(t *testing.T) {
	jsonl := []byte(`{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"main.tf","line":7}}},"Raw":"AKIALEAK"}`)
	findings, err := ParseTrufflehog(jsonl)
	if err != nil || len(findings) != 1 {
		t.Fatalf("parse = %d (err %v)", len(findings), err)
	}
	if findings[0].RuleID != "AWS" || findings[0].File != "main.tf" {
		t.Errorf("finding = %+v", findings[0])
	}
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}
