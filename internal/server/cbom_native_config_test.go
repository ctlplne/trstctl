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

func TestCR056BuildRejectsOverbroadCBOMPrivateEgressCeiling(t *testing.T) {
	s, err := Build(t.Context(), Deps{CBOMPrivateEgressCIDRs: []string{"0.0.0.0/0"}})
	if s != nil || err == nil || !strings.Contains(err.Error(), "CBOM private egress ceiling") {
		t.Fatalf("overbroad CBOM operator ceiling: server=%v err=%v", s, err)
	}
}

func TestCR056CBOMPrivateEgressMustStayWithinOperatorCeiling(t *testing.T) {
	svc := &cbomService{privateEgressCeiling: []string{"10.20.0.0/16"}}
	if _, err := svc.plan(api.CBOMScanRequest{TLSEndpoints: []string{"10.20.1.4:443"},
		AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{"10.0.0.0/8"}}); err == nil {
		t.Fatal("tenant CIDR widened the operator ceiling")
	}
	control, err := svc.tlsDialControl(api.CBOMScanRequest{AllowPrivateEndpoint: true,
		PrivateEgressCIDRs: []string{"10.20.1.0/24"}})
	if err != nil || control("tcp", "10.20.1.4:443", nil) != nil {
		t.Fatalf("narrow operator-approved private CIDR refused: %v", err)
	}
	if err := control("tcp", "10.20.2.4:443", nil); err == nil {
		t.Fatal("dial reached a private address outside the requested CIDR")
	}
	if err := control("tcp", "169.254.169.254:443", nil); err == nil {
		t.Fatal("metadata address escaped the hard block")
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
	}{{"default", "", 4}, {"native", native, 6}} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Server).buildCBOMService(Deps{Store: new(store.Store), Log: new(events.Log), CBOMTLSProbeOpenSSL: tc.path})
			preview, err := svc.Preview(t.Context(), "tenant", api.CBOMScanRequest{TLSEndpoints: []string{"https://one.example.test", "one.example.test:443", "two.example.test:443"}})
			if err != nil {
				t.Fatal(err)
			}
			if !preview.Ready || !preview.EffectFree || preview.TLSConnectionLimit != tc.want || preview.FindingWriteLimit != 6 || preview.PerEndpointTimeoutSeconds != int(tlsprobe.DefaultTimeout.Seconds()) || preview.SignerCalls != 0 || preview.OutboxCalls != 0 {
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
