// SPDX-License-Identifier: MPL-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/license"
)

func TestLicensedStagesAreTheThreeShippedPQCProofs(t *testing.T) {
	got := make([]string, 0, len(licensedStages))
	for _, stage := range licensedStages {
		got = append(got, stage.ID)
	}
	want := []string{
		"pqc_end_to_end.pure_mldsa_leaf_stock_clients",
		"pqc_end_to_end.multikey_spiffe_hybrid_svid",
		"pqc_end_to_end.automated_rollout_tls_findings",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("licensed stages = %v, want %v", got, want)
	}
}

func TestCoreEditionReceiptRequiresCommunityPQCOff(t *testing.T) {
	info := license.Community().Info()
	receipt, err := coreEditionReceipt(info)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != statusUnavailableByEdition {
		t.Fatalf("status = %q, want %q", receipt.Status, statusUnavailableByEdition)
	}
	if receipt.MutationAttempted {
		t.Fatal("core receipt claims the unavailable proprietary mutation was attempted")
	}

	info.Features = append([]license.FeatureInfo(nil), info.Features...)
	for i := range info.Features {
		if info.Features[i].Name == license.FeaturePQC {
			info.Features[i].Licensed = true
			info.Features[i].Mode = license.ModeEnabled
		}
	}
	if _, err := coreEditionReceipt(info); err == nil {
		t.Fatal("licensed PQC was accepted as an honest Community unavailable state")
	}
}

func TestWriteArchiveIsDeterministicChecksummedAndSecretFree(t *testing.T) {
	files := map[string][]byte{
		"manifest.json":         []byte("{\"schema_version\":1,\"mode\":\"core\"}\n"),
		"reports/core.json":     []byte("{\"status\":\"unavailable_by_edition\"}\n"),
		"transcripts/core.json": []byte("{\"mutation_attempted\":false}\n"),
	}
	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	if err := writeArchive(first, files); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(second, files); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same rehearsal evidence produced different archive bytes")
	}

	entries := readArchive(t, firstBytes)
	if _, ok := entries["SHA256SUMS"]; !ok {
		t.Fatal("archive has no SHA256SUMS")
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	wantNames := []string{"SHA256SUMS", "manifest.json", "reports/core.json", "transcripts/core.json"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("archive entries = %v, want %v", names, wantNames)
	}
	if err := verifyChecksums(entries); err != nil {
		t.Fatal(err)
	}
}

func TestWriteArchiveRejectsSecretMaterial(t *testing.T) {
	cases := map[string][]byte{
		"private key":   []byte("-----BEGIN PRIVATE KEY-----\nnot-for-an-archive\n"),
		"API token":     []byte("{\"token\":\"trst_this-is-a-secret-value\"}\n"),
		"bearer":        []byte("Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"),
		"password":      []byte("{\"password\":\"correct horse battery staple\"}\n"),
		"client secret": []byte("{\"client_secret\":\"not-for-an-archive\"}\n"),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			err := writeArchive(filepath.Join(t.TempDir(), "bad.tar.gz"), map[string][]byte{
				"transcripts/bad.json": payload,
			})
			if err == nil {
				t.Fatal("secret-shaped evidence was archived")
			}
		})
	}
}

func TestArchiveAllowsCapabilityTaxonomyContainingSecret(t *testing.T) {
	err := writeArchive(filepath.Join(t.TempDir(), "safe.tar.gz"), map[string][]byte{
		"reports/census.json": []byte(`{"capabilities":{"dynamic_secret":{"status":"unknown"}}}`),
	})
	if err != nil {
		t.Fatalf("capability taxonomy was mistaken for credential material: %v", err)
	}
}

func TestParseServedReportRequiresSelectedEntry(t *testing.T) {
	report := map[string]any{
		"entries": map[string]any{
			licensedStages[0].ID: map[string]any{"status": "served"},
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireServedReport(raw, licensedStages[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := requireServedReport(raw, licensedStages[1].ID); err == nil {
		t.Fatal("report without the selected entry was accepted")
	}
	report["entries"].(map[string]any)[licensedStages[0].ID] = map[string]any{"status": "unknown"}
	raw, _ = json.Marshal(report)
	if err := requireServedReport(raw, licensedStages[0].ID); err == nil {
		t.Fatal("non-served selected entry was accepted")
	}
}

func TestOfflineEnvironmentAndPrivateCleanup(t *testing.T) {
	env := offlineGoEnv([]string{
		"PATH=/usr/bin",
		"GOCACHE=/private/tmp/pqc-test-cache",
		"GOPROXY=https://proxy.example",
		"GOSUMDB=sum.example",
		"GOTOOLCHAIN=auto",
	})
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOCACHE=/private/tmp/pqc-test-cache",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("offline environment omitted %q: %s", want, joined)
		}
	}
	for _, forbidden := range []string{"GOPROXY=https://", "GOSUMDB=sum.example", "GOTOOLCHAIN=auto"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("offline environment retained %q: %s", forbidden, joined)
		}
	}
	privateCacheEnv := strings.Join(offlineGoEnvWithCache(env, "/private/tmp/owned-cache"), "\n")
	for _, want := range []string{
		"GOCACHE=/private/tmp/owned-cache",
		"TRSTCTL_DOD_GOCACHE=/private/tmp/owned-cache",
	} {
		var count int
		for _, line := range strings.Split(privateCacheEnv, "\n") {
			if line == want {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("private cache environment does not contain exactly one %q: %s", want, privateCacheEnv)
		}
	}
	if strings.Contains(privateCacheEnv, "GOCACHE=/private/tmp/pqc-test-cache") {
		t.Fatalf("private cache environment retained inherited cache: %s", privateCacheEnv)
	}

	parent := t.TempDir()
	unrelated := filepath.Join(parent, "unrelated")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	root, cleanup, err := privateWorkspace(parent, "owned-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime-state"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	cleanup()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("owned workspace survived cleanup: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("cleanup touched unrelated sibling: %v", err)
	}
}

func TestValidatedCommandBoundaryAllowsOnlyReviewedArgv(t *testing.T) {
	root := t.TempDir()
	repo := t.TempDir()
	report := filepath.Join(root, "report.json")
	control := filepath.Join(root, "trstctl")
	cases := []struct {
		name    string
		request commandRequest
		want    []string
	}{
		{
			name:    "git revision",
			request: commandRequest{kind: commandGitRevision, repo: repo},
			want:    []string{"git", "rev-parse", "HEAD"},
		},
		{
			name: "DoD census",
			request: commandRequest{
				kind: commandDODCensus, repo: repo, root: root, output: report, stage: licensedStages[0].ID,
			},
			want: []string{"go", "run", "./tools/dodcensus", "--repo", ".", "--manifest", "tools/dodcensus/manifest.json", "--out", report, "--capability", licensedStages[0].ID},
		},
		{
			name: "core build",
			request: commandRequest{
				kind: commandCoreBuild, repo: repo, root: root, output: control, pkg: "./cmd/trstctl",
			},
			want: []string{"go", "build", "-trimpath", "-tags", "trstctl_core", "-o", control, "./cmd/trstctl"},
		},
		{
			name:    "core token",
			request: commandRequest{kind: commandCoreToken, root: root, binary: control},
			want:    []string{control, "token", "create", "--tenant", coreTenantID, "--tenant-name", "PQC core operator rehearsal", "--subject", "pqc-core-rehearsal", "--scopes", "risk:read"},
		},
		{
			name:    "core serve",
			request: commandRequest{kind: commandCoreServe, root: root, binary: control},
			want:    []string{control},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := newValidatedCommand(context.Background(), tc.request)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cmd.Args, tc.want) {
				t.Fatalf("argv = %#v, want %#v", cmd.Args, tc.want)
			}
		})
	}

	for name, request := range map[string]commandRequest{
		"unknown kind":      {kind: 255},
		"unknown stage":     {kind: commandDODCensus, repo: repo, root: root, output: report, stage: "pqc_end_to_end.unreviewed"},
		"report escape":     {kind: commandDODCensus, repo: repo, root: root, output: filepath.Join(root, "..", "report.json"), stage: licensedStages[0].ID},
		"unknown package":   {kind: commandCoreBuild, repo: repo, root: root, output: control, pkg: "./cmd/unreviewed"},
		"build escape":      {kind: commandCoreBuild, repo: repo, root: root, output: filepath.Join(root, "..", "trstctl"), pkg: "./cmd/trstctl"},
		"ambient token bin": {kind: commandCoreToken, root: root, binary: "trstctl"},
		"ambient serve bin": {kind: commandCoreServe, root: root, binary: "trstctl"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newValidatedCommand(context.Background(), request); err == nil {
				t.Fatal("unreviewed command was accepted")
			}
		})
	}
}

func readArchive(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = body
	}
	return entries
}

func verifyChecksums(entries map[string][]byte) error {
	lines := strings.Split(strings.TrimSpace(string(entries["SHA256SUMS"])), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			return &testError{"malformed checksum line: " + line}
		}
		body, ok := entries[parts[1]]
		if !ok {
			return &testError{"checksum names missing entry: " + parts[1]}
		}
		if got := checksumHex(body); got != parts[0] {
			return &testError{"checksum mismatch for " + parts[1]}
		}
	}
	return nil
}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }
