// SPDX-License-Identifier: MPL-2.0

package supportbundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
)

func TestCreateSurvivesInvalidConfigAndRedactsCompleteArchive(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "control.log")
	const (
		secret = "password=CorrectHorseBatteryStaple42"
		email  = "alice.operator@example.test"
		tenant = "11111111-1111-1111-1111-111111111111"
	)
	logBody := strings.Join([]string{
		"startup postgres_dsn=postgres://admin:db-password@db.example.test:5432/trstctl",
		"authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signaturevalue",
		secret + " owner=" + email + " tenant=" + tenant,
		"key_file=/var/lib/trstctl/private/issuer-key.pem peer=10.20.30.40",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "cold-start.tar.gz")
	getenv := func(key string) string {
		switch key {
		case "TRSTCTL_POSTGRES_MODE":
			return "external"
		case "TRSTCTL_POSTGRES_DSN":
			return ""
		default:
			return ""
		}
	}
	got, err := Create(context.Background(), Options{
		Getenv: getenv, Output: output, LogFile: logPath,
		Now: func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != output {
		t.Fatalf("output = %q, want %q", got, output)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %o, want 600", info.Mode().Perm())
	}
	entries := readBundle(t, output)
	for _, name := range []string{
		"manifest.json", "build.json", "config-posture.json", "dependencies.json",
		"migrations.json", "queues.json", "logs/recent.log",
	} {
		if _, ok := entries[name]; !ok {
			t.Errorf("bundle missing %s", name)
		}
	}
	if !strings.Contains(string(entries["config-posture.json"]), `"status": "validation_failed"`) {
		t.Fatalf("invalid configuration posture missing: %s", entries["config-posture.json"])
	}
	for name, body := range entries {
		text := string(body)
		for _, forbidden := range []string{secret, email, tenant, "db-password", "issuer-key.pem", "10.20.30.40", "postgres://"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s leaked %q: %s", name, forbidden, text)
			}
		}
		if aimodel.ResidualSecret(text) || aimodel.ContainsPII(text) || uuidValue.MatchString(text) {
			t.Errorf("%s failed residual privacy scan: %s", name, text)
		}
	}
	if len(entries["logs/recent.log"]) > maxLogBytes {
		t.Fatalf("sanitized log entry is unbounded: %d", len(entries["logs/recent.log"]))
	}
	second := filepath.Join(t.TempDir(), "cold-start.tar.gz")
	if _, err := Create(context.Background(), Options{
		Getenv: getenv, Output: second, LogFile: logPath,
		Now: func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(output) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("same inputs and timestamp produced different support archives")
	}
}

func TestCreateIncludesOnlyTypedRedactedEnrollmentDiagnosticAddendum(t *testing.T) {
	output := filepath.Join(t.TempDir(), "diagnostics.tar.gz")
	addendum := &EnrollmentDiagnosticsAddendum{
		SchemaVersion: 1,
		Rows: []EnrollmentDiagnosticAggregate{
			{Protocol: "est", Cause: "template_acl_denied", Actionable: true, Count: 7},
			{Protocol: "cmp", Cause: "capacity_full", Actionable: true, Count: 3},
			{Protocol: "acme", Cause: "unknown", Actionable: false, Count: 2},
		},
		UnknownCount: 2,
	}
	if _, err := Create(context.Background(), Options{
		Output: output, EnrollmentDiagnostics: addendum,
		Getenv: func(string) string { return "" },
		Now:    func() time.Time { return time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatal(err)
	}
	entries := readBundle(t, output)
	body, ok := entries["enrollment-diagnostics.json"]
	if !ok {
		t.Fatal("support archive omitted the requested diagnostics addendum")
	}
	text := string(body)
	for _, want := range []string{
		`"protocol": "est"`, `"cause": "template_acl_denied"`, `"count": 7`,
		`"protocol": "cmp"`, `"cause": "capacity_full"`, `"count": 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnostics addendum missing %s: %s", want, text)
		}
	}
	for _, forbidden := range []string{"operation_ref", "identity_ref", "endpoint_ref", "tenant_id", "observed_at", "diagnostic_id"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("diagnostics addendum leaked %q: %s", forbidden, text)
		}
	}
}

func readBundle(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close support bundle: %v", err)
		}
	}()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := zr.Close(); err != nil {
			t.Errorf("close support bundle gzip reader: %v", err)
		}
	}()
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[header.Name] = body
	}
	return out
}
