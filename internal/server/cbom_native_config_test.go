// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestRunConfigRetainsCBOMNativeProbe(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit.pem")
	cfg.CBOM.TLSProbeOpenSSL = "/operator/openssl"
	deps, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, testAuditSigningKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if deps.Bulkhead != nil {
		t.Cleanup(deps.Bulkhead.Close)
	}
	if deps.CBOMTLSProbeOpenSSL != cfg.CBOM.TLSProbeOpenSSL {
		t.Fatal("run configuration lost native discovery executable")
	}
}

func TestBuildRejectsInvalidCBOMNativeExecutable(t *testing.T) {
	dir := t.TempDir()
	nonexec := filepath.Join(dir, "nonexec")
	if err := os.WriteFile(nonexec, []byte("not executable"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(nonexec, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"openssl", filepath.Join(dir, "missing"), dir, nonexec, link} {
		s, err := Build(t.Context(), Deps{CBOMTLSProbeOpenSSL: path})
		if s != nil || err == nil || !strings.Contains(err.Error(), "CBOM native TLS probe") {
			t.Fatalf("invalid executable %q: server=%v err=%v", path, s, err)
		}
	}
}

func TestCBOMNativePreviewDeclaresBothAttemptsWithoutExecution(t *testing.T) {
	// This file is deliberately not a runnable program. Preview must not execute
	// it, validate its format, read a target, or require a live database/event log.
	native := filepath.Join(t.TempDir(), "operator-owned-probe")
	if err := os.WriteFile(native, []byte("preview must not execute this\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		want       int
	}{{"default", "", 2}, {"native", native, 4}} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Server).buildCBOMService(Deps{Store: new(store.Store), Log: new(events.Log), CBOMTLSProbeOpenSSL: tc.path})
			preview, err := svc.Preview(t.Context(), "tenant", api.CBOMScanRequest{TLSEndpoints: []string{"https://one.example.test", "one.example.test:443", "two.example.test:443"}})
			if err != nil {
				t.Fatal(err)
			}
			if !preview.Ready || !preview.EffectFree || preview.TLSConnectionLimit != tc.want || preview.FindingWriteLimit != 4 || preview.PerEndpointTimeoutSeconds != int(tlsprobe.DefaultTimeout.Seconds()) || preview.SignerCalls != 0 || preview.OutboxCalls != 0 {
				t.Fatalf("incorrect bounded preview: %+v", preview)
			}
			data, err := json.Marshal(preview)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), native) {
				t.Fatal("preview exposed operator executable path")
			}
		})
	}
}
