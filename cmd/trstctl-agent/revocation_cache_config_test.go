// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestLoadRevocationCacheConfigBuildsMultipleIssuerCRLAndOCSPRoutesAUD39(t *testing.T) {
	dir := t.TempDir()
	issuerPath := func(name string) string {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		der, err := crypto.SelfSignedCACert(key, name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		path := filepath.Join(dir, name+".pem")
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	disk := revocationCacheFile{
		Listen: "127.0.0.1:8088", Segment: "plant-7", RefreshInterval: "5m",
		Issuers: []revocationCacheFileIssuer{
			{ID: "issuer-a", IssuerFile: issuerPath("issuer-a"),
				CRL:  &revocationCacheFileCRL{UpstreamURL: "https://cp.internal/crl/a", LocalPath: "/crl/a"},
				OCSP: &revocationCacheFileOCSP{UpstreamURL: "https://cp.internal/ocsp/a", LocalPath: "/ocsp/a"}},
			{ID: "issuer-b", IssuerFile: issuerPath("issuer-b"),
				CRL:  &revocationCacheFileCRL{UpstreamURL: "https://cp.internal/crl/b", LocalPath: "/crl/b", Grace: "30s"},
				OCSP: &revocationCacheFileOCSP{UpstreamURL: "https://cp.internal/ocsp/b", LocalPath: "/ocsp/b"}},
		},
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "revocation-cache.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	listen, refresh, cfg, err := loadRevocationCacheConfig(agentOptions{revCacheConfig: path})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if listen != disk.Listen || refresh != 5*time.Minute || cfg.Segment != "plant-7" || len(cfg.Issuers) != 2 ||
		cfg.Issuers[0].CRL == nil || cfg.Issuers[0].OCSP == nil || len(cfg.Issuers[0].IssuerDER) == 0 ||
		cfg.Issuers[1].CRL.Grace != 30*time.Second {
		t.Fatalf("loaded config listen=%q refresh=%s cfg=%+v", listen, refresh, cfg)
	}
}

func TestLegacyRevocationCacheRequiresExplicitSegmentAUD39(t *testing.T) {
	_, _, _, err := loadRevocationCacheConfig(agentOptions{
		revCacheListen: "127.0.0.1:8088", revCacheUpstream: "https://cp.internal/crl",
		revCacheIssuer: "issuer.pem",
	})
	if err == nil {
		t.Fatal("legacy single-CRL cache without a segment was accepted")
	}
}

func TestRevocationCacheHeartbeatIssuedAtIsMonotonicAcrossImmediateReconnectAUD39(t *testing.T) {
	var last atomic.Int64
	if first, second := nextMonotonicUnix(&last, 100), nextMonotonicUnix(&last, 100); first != 100 || second != 101 {
		t.Fatalf("same-second issued-at sequence = %d, %d; want 100, 101", first, second)
	}
	if regressed := nextMonotonicUnix(&last, 99); regressed != 102 {
		t.Fatalf("wall-clock regression issued-at = %d, want 102", regressed)
	}
}
