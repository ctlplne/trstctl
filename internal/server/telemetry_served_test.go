package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/telemetry"
)

// COMP-04 acceptance: the served runtime deps wire the opt-in telemetry reporter.
// Default config returns no reporter, but explicit opt-in builds one that sends the
// same anonymized/bucketed payload as internal/telemetry, without names, hostnames,
// secret values, or exact counts.
func TestRunDepsWireOptInTelemetryReporter(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit.pem")

	offDeps, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("build default deps: %v", err)
	}
	if offDeps.TelemetryReporter != nil {
		t.Fatal("default config must not wire a telemetry reporter")
	}

	var got telemetry.Payload
	var raw string
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read telemetry body: %v", err)
		}
		raw = string(body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode telemetry payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	cfg.Telemetry.Enabled = true
	cfg.Telemetry.Endpoint = receiver.URL
	cfg.Telemetry.Interval = "1h"
	cfg.Telemetry.InstanceIDFile = filepath.Join(t.TempDir(), "telemetry-instance-id")
	onDeps, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("build telemetry deps: %v", err)
	}
	if onDeps.TelemetryReporter == nil {
		t.Fatal("enabled telemetry config did not wire a reporter")
	}
	onDeps.TelemetryReporter.Post = telemetry.HTTPPoster(receiver.Client())
	if err := onDeps.TelemetryReporter.ReportOnce(context.Background()); err != nil {
		t.Fatalf("telemetry ReportOnce: %v", err)
	}
	if got.Schema != telemetry.SchemaVersion || got.InstanceID == "" || got.Version == "" || got.OS == "" || got.Arch == "" {
		t.Fatalf("bad telemetry payload: %+v", got)
	}
	for _, forbidden := range []string{"airgap-payments", "offline-secret", "password", "example.com"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("telemetry payload leaked forbidden material %q: %s", forbidden, raw)
		}
	}
	for typ, bucket := range got.CredentialBuckets {
		if bucket == "137" {
			t.Fatalf("telemetry payload leaked exact credential count for %s: %s", typ, raw)
		}
	}
}
