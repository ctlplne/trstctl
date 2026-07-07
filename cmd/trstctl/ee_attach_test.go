// SPDX-License-Identifier: MPL-2.0

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
	if deps.EnableRemediation || deps.LicensedAPIOptionsFactory != nil || deps.LicensedOutboxFactory != nil || deps.LicensedLeafSigner != nil || deps.LicensedCSRInspector != nil {
		t.Fatal("community attach must not enable remediation or PQC")
	}

	deps = &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if !deps.EnableRemediation {
		t.Fatal("enterprise remediation feature did not mount the remediation surface")
	}
	if deps.LicensedAPIOptionsFactory == nil || deps.LicensedOutboxFactory == nil || deps.LicensedLeafSigner == nil || deps.LicensedCSRInspector == nil {
		t.Fatal("enterprise PQC feature did not mount the PQC surface")
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

func TestAttachEEBYOKRequiresEnterpriseLicense(t *testing.T) {
	cfg := &config.Config{
		ManagedKeys: config.ManagedKeys{
			Enabled:  true,
			Provider: config.ManagedKeyProviderAWS,
			AWS: config.ManagedKeysAWSKMS{
				Region:          "us-east-1",
				AccessKeyID:     "test",
				SecretAccessKey: []byte("test-secret"),
			},
		},
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled:      true,
			TenantID:     "11111111-1111-1111-1111-111111111111",
			CertFile:     "kmip-server.crt",
			KeyFile:      "kmip-server.key",
			ClientCAFile: "kmip-clients.crt",
		}},
	}

	deps := &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, license.Community(), deps); err != nil {
		t.Fatalf("community attachEE: %v", err)
	}
	if deps.ManagedKeyFactory != nil || deps.KMIPFactory != nil {
		t.Fatal("community attach must not mount BYOK factories")
	}

	deps = &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if deps.ManagedKeyFactory == nil {
		t.Fatal("enterprise BYOK feature did not mount managed-key factory")
	}
	if deps.KMIPFactory == nil {
		t.Fatal("enterprise BYOK feature did not mount KMIP factory")
	}
}

func TestAttachEEGovernanceRequiresEnterpriseLicense(t *testing.T) {
	deps := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, license.Community(), deps); err != nil {
		t.Fatalf("community attachEE: %v", err)
	}
	if deps.GovernanceFactory != nil || deps.GovernancePolicySource != nil {
		t.Fatal("community attach must not mount governance seams")
	}

	deps = &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if deps.GovernanceFactory == nil {
		t.Fatal("enterprise governance feature did not mount evidence-pack factory")
	}
	if deps.GovernancePolicySource == nil {
		t.Fatal("enterprise governance feature did not mount policy source")
	}
}

func TestAttachEEAgentDelegationRequiresEnterpriseLicense(t *testing.T) {
	// Feature absent (Community): the FeatureAgentDelegation block is skipped, so no
	// chain-bound broker issuance precondition is attached. The free single-hop
	// attested badge is unaffected because it never routes through this precondition
	// (INV-A10 zero removal): its absence here is exactly the unlicensed steady state.
	deps := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, license.Community(), deps); err != nil {
		t.Fatalf("community attachEE: %v", err)
	}
	if deps.BrokerIssuancePrecondition != nil {
		t.Fatal("community attach must not attach a chain-bound broker issuance precondition")
	}

	// Feature present (Enterprise): the single lic.Has(FeatureAgentDelegation) block
	// runs and wires the AGID broker precondition factory.
	deps = &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, enterpriseLicense(t), deps); err != nil {
		t.Fatalf("enterprise attachEE: %v", err)
	}
	if deps.BrokerIssuancePrecondition == nil {
		t.Fatal("enterprise agent-delegation feature did not attach the chain-bound broker issuance precondition")
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
