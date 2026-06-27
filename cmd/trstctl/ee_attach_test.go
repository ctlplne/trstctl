//go:build !trstctl_core

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

func TestAttachEERemediationRequiresEnterpriseLicense(t *testing.T) {
	deps := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, license.Community(), deps); err != nil {
		t.Fatalf("community attachEE: %v", err)
	}
	if deps.EnableRemediation {
		t.Fatal("community attach must not enable remediation")
	}

	deps = &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if !deps.EnableRemediation {
		t.Fatal("enterprise remediation feature did not mount the remediation surface")
	}
}

func TestAttachEEHASupportRequiresEnterpriseLicense(t *testing.T) {
	cfg := &config.Config{Federation: config.Federation{
		Enabled:   true,
		ClusterID: "west-passive",
		Region:    "us-west-2",
	}}

	deps := &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, license.Community(), deps); err != nil {
		t.Fatalf("community attachEE: %v", err)
	}
	if deps.FederationFactory != nil {
		t.Fatal("community attach must not mount the federation worker factory")
	}

	deps = &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if deps.FederationFactory == nil {
		t.Fatal("enterprise HA support feature did not mount the federation worker factory")
	}
}

func enterpriseLicense(t *testing.T) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate license key: %v", err)
	}
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_test_remediation", Customer: "Acme Robotics", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("sign license: %v", err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write license: %v", err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatalf("load license: %v", err)
	}
	return mgr
}
