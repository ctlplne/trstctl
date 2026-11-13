// SPDX-License-Identifier: BUSL-1.1

//go:build !trstctl_core

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

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
	if hasBackgroundWorker(deps, "misuse_detector") {
		t.Fatal("community attach must not mount misuse detection (M2)")
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
	if !hasBackgroundWorker(deps, "misuse_detector") || len(deps.LicensedProjectionOptions) == 0 {
		t.Fatal("enterprise governance feature did not mount misuse detection and its findings projection (M2)")
	}
}

// M2-L1: an Enterprise license mounts GET /api/v1/misuse/findings; the
// route reaches its authenticated handler (401 here, with no principal) rather
// than 404. Community mounts no such route.
func TestAttachEEGovernanceMountsTheMisuseFindingsRouteM2L1(t *testing.T) {
	status := func(lic *license.Manager) int {
		t.Helper()
		deps := &server.Deps{}
		if err := attachEE(context.Background(), &config.Config{}, nil, lic, deps); err != nil {
			t.Fatalf("attachEE: %v", err)
		}
		var opts []api.Option
		if deps.LicensedAPIOptionsFactory != nil {
			var err error
			if opts, err = deps.LicensedAPIOptionsFactory(server.LicensedAPIOptionsDeps{}); err != nil {
				t.Fatalf("licensed API options: %v", err)
			}
		}
		rec := httptest.NewRecorder()
		api.New(nil, nil, nil, opts...).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/misuse/findings", nil))
		return rec.Code
	}
	if got := status(enterpriseLicense(t)); got != http.StatusUnauthorized {
		t.Fatalf("enterprise GET /api/v1/misuse/findings = %d, want 401 from the mounted, authenticated route", got)
	}
	if got := status(license.Community()); got != http.StatusNotFound {
		t.Fatalf("community GET /api/v1/misuse/findings = %d, want 404", got)
	}
}

func TestAttachEETenantAuthRequiresEnterpriseOrInheritedProvider(t *testing.T) {
	for _, tier := range []license.Tier{license.TierEnterprise, license.TierProvider} {
		t.Run(string(tier), func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Auth.SAML.Enabled = true
			cfg.Auth.LDAP.Enabled = true
			cfg.Auth.SCIM.Enabled = true
			deps := &server.Deps{}
			lic := commercialLicense(t, tier)
			if err := attachEE(context.Background(), cfg, nil, lic, deps); err != nil {
				t.Fatalf("licensed tenant-auth attachment: %v", err)
			}
			if deps.TenantAuthFactory == nil {
				t.Fatal("licensed tenant SAML/LDAP/SCIM implementation was not attached")
			}
		})
	}
}

func TestAttachEEProviderLicenseMountsEnterpriseAndProviderSurfaces(t *testing.T) {
	deps := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, commercialLicense(t, license.TierProvider), deps); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	if deps.GovernanceFactory == nil {
		t.Fatal("Provider license did not mount inherited Enterprise governance surface")
	}
	if deps.ProviderHandler == nil {
		t.Fatal("Provider license did not mount the Provider control-plane surface")
	}
	if deps.ProviderHandlerFactory == nil {
		t.Fatal("Provider license did not attach the mutation-spine handler factory")
	}
	if _, err := deps.ProviderHandlerFactory(nil, nil); err == nil {
		t.Fatal("Provider command surface accepted a missing mutation spine")
	}
}

func TestAUD60AttachEEProviderMountsCustomerHealthRoute(t *testing.T) {
	deps := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, commercialLicense(t, license.TierProvider), deps); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/customer-a/health", nil)
	rec := httptest.NewRecorder()
	deps.ProviderHandler.ServeHTTP(rec, req)
	// No Provider authenticator is configured in this assembly fixture, so the
	// route must reach the real handler and refuse 401. A missing route would be
	// 404 and would reproduce AUD-60's unreachable service method.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("assembled Provider health route = %d body=%s, want authenticated handler refusal 401", rec.Code, rec.Body.String())
	}
}

func TestOneShotRecoveryProjectionAttachIsProviderGated(t *testing.T) {
	t.Parallel()
	options, err := attachEEProjectionOptions(context.Background(), &config.Config{}, license.Community(), nil, nil)
	if err != nil || len(options) != 0 {
		t.Fatalf("community recovery projection options = %d/%v, want none", len(options), err)
	}
	if _, err := attachEEProjectionOptions(context.Background(), &config.Config{},
		commercialLicense(t, license.TierProvider), nil, nil); err == nil {
		t.Fatal("provider recovery projection accepted missing PostgreSQL/JetStream; a restore would silently omit authority state")
	}
}

func enterpriseLicense(t *testing.T) *license.Manager {
	return commercialLicense(t, license.TierEnterprise)
}

func commercialLicense(t *testing.T, tier license.Tier) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate license key: %v", err)
	}
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_test_" + string(tier), Customer: "Acme Robotics", Tier: tier,
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

func TestAttachEEAuditComplianceOwnsAnchoringRetentionAndPacks(t *testing.T) {
	for _, tier := range []license.Tier{license.TierCommunity, license.TierEnterprise, license.TierProvider} {
		t.Run(string(tier), func(t *testing.T) {
			lic := license.Community()
			if tier != license.TierCommunity {
				lic = commercialLicense(t, tier)
			}
			deps := &server.Deps{}
			if err := attachEE(context.Background(), &config.Config{}, nil, lic, deps); err != nil {
				t.Fatal(err)
			}
			want := tier != license.TierCommunity
			if (deps.AuditComplianceFactory != nil) != want || (deps.GovernanceFactory != nil) != want {
				t.Fatalf("audit factory=%t packs=%t want=%t", deps.AuditComplianceFactory != nil, deps.GovernanceFactory != nil, want)
			}
		})
	}
}

// MSP-3: a Provider deployment with a PSA target that opens tickets attaches
// the ticket observer ahead of the alert channels and the close sweep as a
// licensed leader worker; without such a target, neither is attached.
func TestAttachEEProviderAttachesPSATicketsMSP3(t *testing.T) {
	withTickets := &config.Config{}
	withTickets.Provider.BillingSync.Targets = []config.ProviderBillingTarget{{ID: "cw", Type: "connectwise",
		ConnectWise: &config.ConnectWiseBillingTarget{Tickets: &config.ConnectWiseTickets{Board: "Managed PKI", ClosedStatus: ">Closed"}}}}
	deps := &server.Deps{}
	if err := attachEE(context.Background(), withTickets, nil, commercialLicense(t, license.TierProvider), deps); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	if len(deps.AlertObservers) != 1 {
		t.Fatalf("alert observers = %d, want the ticket observer", len(deps.AlertObservers))
	}
	closer := false
	for _, worker := range deps.LicensedBackgroundWorkers {
		closer = closer || worker.Name() == "provider.psa_ticket.close_sweep"
	}
	if !closer {
		t.Fatal("the ticket close sweep is not a licensed background worker")
	}
	plain := &server.Deps{}
	if err := attachEE(context.Background(), &config.Config{}, nil, commercialLicense(t, license.TierProvider), plain); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	if len(plain.AlertObservers) != 0 {
		t.Fatal("a deployment with no ticket target attached a ticket observer")
	}
}

// MSP-9: a Provider deployment with an RMM target attaches the inventory
// sweep as a licensed leader worker, and the Provider view marks the target
// as an RMM.
func TestAttachEEProviderAttachesRMMSweepMSP9(t *testing.T) {
	cfg := &config.Config{}
	cfg.Provider.BillingSync.Targets = []config.ProviderBillingTarget{{ID: "ninja", Type: "ninjaone", NinjaOne: &config.NinjaOneTarget{}}}
	deps := &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, commercialLicense(t, license.TierProvider), deps); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	sweep := false
	for _, worker := range deps.LicensedBackgroundWorkers {
		sweep = sweep || worker.Name() == "provider.rmm.inventory_sweep"
	}
	if !sweep {
		t.Fatal("the RMM inventory sweep is not a licensed background worker")
	}
	if targets := providerBillingTargets(cfg.Provider.BillingSync); len(targets) != 1 || !targets[0].RMM || targets[0].Tickets {
		t.Fatalf("Provider view of the RMM target = %+v", targets)
	}
}

// MSP-14: a documentation target attaches the documentation record sweep
// and is marked as documentation (not an RMM, no tickets) for the console.
func TestAttachEEProviderAttachesDocRecordSweepMSP14(t *testing.T) {
	cfg := &config.Config{}
	cfg.Provider.BillingSync.Targets = []config.ProviderBillingTarget{{ID: "itglue", Type: "itglue", ITGlue: &config.ITGlueTarget{}}}
	deps := &server.Deps{}
	if err := attachEE(context.Background(), cfg, nil, commercialLicense(t, license.TierProvider), deps); err != nil {
		t.Fatalf("provider attachEE: %v", err)
	}
	sweep := false
	for _, worker := range deps.LicensedBackgroundWorkers {
		sweep = sweep || worker.Name() == "provider.doc_record.sweep"
	}
	if !sweep {
		t.Fatal("the documentation record sweep is not a licensed background worker")
	}
	if targets := providerBillingTargets(cfg.Provider.BillingSync); len(targets) != 1 || !targets[0].Documentation || targets[0].RMM || targets[0].Tickets {
		t.Fatalf("Provider view of the documentation target = %+v", targets)
	}
}
