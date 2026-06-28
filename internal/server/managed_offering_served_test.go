package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedManagedOfferingCAPMODEL02EndToEnd(t *testing.T) {
	community := newServedHarness(t, config.Protocols{})
	communityToken := seedScopedToken(t, community.store, community.tenant, "access:read", "access:write")
	status, body := doBearer(t, community.ts, http.MethodGet, "/api/v1/managed-offering/status", communityToken, "", nil)
	if status != http.StatusOK {
		t.Fatalf("community status = %d body %s", status, body)
	}
	var communityStatus struct {
		Served            bool   `json:"served"`
		DeploymentModel   string `json:"deployment_model"`
		ProviderPlaneMode string `json:"provider_plane_mode"`
	}
	if err := json.Unmarshal(body, &communityStatus); err != nil {
		t.Fatalf("decode community managed offering status: %v", err)
	}
	if !communityStatus.Served || communityStatus.DeploymentModel != orchestrator.ManagedOfferingDeploymentModel || communityStatus.ProviderPlaneMode != string(license.ModeOff) {
		t.Fatalf("community managed offering status = %+v", communityStatus)
	}
	status, body = doBearer(t, community.ts, http.MethodPost, "/api/v1/managed-offering/tenants", communityToken, "cap-model-02-community-deny", map[string]any{
		"tenant_id": "22222222-2222-4222-8222-222222222222",
		"name":      "Denied Hosted Tenant",
	})
	if status != http.StatusForbidden {
		t.Fatalf("community provision = %d body %s, want 403", status, body)
	}

	provider := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.License = testManagedOfferingLicenseManager(t)
	})
	providerToken := seedScopedTokenSubject(t, provider.store, provider.tenant, "provider-admin", "access:read", "access:write")

	status, body = doBearer(t, provider.ts, http.MethodGet, "/api/v1/managed-offering/status", providerToken, "", nil)
	if status != http.StatusOK {
		t.Fatalf("provider status = %d body %s", status, body)
	}
	var providerStatus struct {
		Served              bool   `json:"served"`
		DeploymentModel     string `json:"deployment_model"`
		Tier                string `json:"tier"`
		LicenseState        string `json:"license_state"`
		ProviderPlaneMode   string `json:"provider_plane_mode"`
		IdempotencyRequired bool   `json:"idempotency_required"`
		EventType           string `json:"event_type"`
		MutationPath        string `json:"mutation_path"`
	}
	if err := json.Unmarshal(body, &providerStatus); err != nil {
		t.Fatalf("decode provider managed offering status: %v", err)
	}
	if !providerStatus.Served || providerStatus.DeploymentModel != orchestrator.ManagedOfferingDeploymentModel ||
		providerStatus.Tier != string(license.TierProvider) || providerStatus.LicenseState != string(license.StateActive) ||
		providerStatus.ProviderPlaneMode != string(license.ModeEnabled) || !providerStatus.IdempotencyRequired ||
		providerStatus.EventType != projections.EventTenantRegistered || providerStatus.MutationPath != "/api/v1/managed-offering/tenants" {
		t.Fatalf("provider managed offering status = %+v", providerStatus)
	}

	hostedTenantID := "33333333-3333-4333-8333-333333333333"
	request := map[string]any{
		"tenant_id":      hostedTenantID,
		"name":           "Acme Hosted",
		"region":         "us-east-1",
		"data_residency": "US",
		"plan":           "enterprise",
		"support_tier":   "24x7",
		"slo_tier":       "99.95",
	}
	status, body = doBearer(t, provider.ts, http.MethodPost, "/api/v1/managed-offering/tenants", providerToken, "cap-model-02-provision", request)
	if status != http.StatusCreated {
		t.Fatalf("provider provision = %d body %s", status, body)
	}
	var created struct {
		TenantID         string `json:"tenant_id"`
		Name             string `json:"name"`
		ProviderTenantID string `json:"provider_tenant_id"`
		DeploymentModel  string `json:"deployment_model"`
		Managed          bool   `json:"managed"`
		Region           string `json:"region"`
		DataResidency    string `json:"data_residency"`
		Plan             string `json:"plan"`
		SupportTier      string `json:"support_tier"`
		SLOTier          string `json:"slo_tier"`
		ProvisionedBy    string `json:"provisioned_by"`
		EventSequence    uint64 `json:"event_sequence"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode managed tenant: %v", err)
	}
	if created.TenantID != hostedTenantID || created.Name != "Acme Hosted" || created.ProviderTenantID != provider.tenant ||
		created.DeploymentModel != orchestrator.ManagedOfferingDeploymentModel || !created.Managed || created.Region != "us-east-1" ||
		created.DataResidency != "US" || created.Plan != "enterprise" || created.SupportTier != "24x7" ||
		created.SLOTier != "99.95" || created.ProvisionedBy != "provider-admin" || created.EventSequence == 0 {
		t.Fatalf("bad managed tenant response: %+v", created)
	}
	projected, err := provider.store.GetTenant(context.Background(), hostedTenantID)
	if err != nil {
		t.Fatalf("load projected hosted tenant: %v", err)
	}
	if projected.TenantID != hostedTenantID || projected.Name != "Acme Hosted" || projected.EventSeq != created.EventSequence {
		t.Fatalf("projected hosted tenant = %+v, response sequence %d", projected, created.EventSequence)
	}

	eventsBefore := managedTenantRegisteredEvents(t, provider.log, hostedTenantID)
	if len(eventsBefore) != 1 {
		t.Fatalf("tenant.registered events before replay = %d, want 1", len(eventsBefore))
	}
	var payload struct {
		Name            string `json:"name"`
		ManagedOffering struct {
			Enabled          bool   `json:"enabled"`
			DeploymentModel  string `json:"deployment_model"`
			ProviderTenantID string `json:"provider_tenant_id"`
			Region           string `json:"region"`
			DataResidency    string `json:"data_residency"`
			Plan             string `json:"plan"`
			SupportTier      string `json:"support_tier"`
			SLOTier          string `json:"slo_tier"`
			ProvisionedBy    string `json:"provisioned_by"`
		} `json:"managed_offering"`
	}
	if err := json.Unmarshal(eventsBefore[0].Data, &payload); err != nil {
		t.Fatalf("decode tenant.registered payload: %v", err)
	}
	if payload.Name != "Acme Hosted" || !payload.ManagedOffering.Enabled ||
		payload.ManagedOffering.DeploymentModel != orchestrator.ManagedOfferingDeploymentModel ||
		payload.ManagedOffering.ProviderTenantID != provider.tenant ||
		payload.ManagedOffering.Region != "us-east-1" ||
		payload.ManagedOffering.DataResidency != "US" ||
		payload.ManagedOffering.Plan != "enterprise" ||
		payload.ManagedOffering.SupportTier != "24x7" ||
		payload.ManagedOffering.SLOTier != "99.95" ||
		payload.ManagedOffering.ProvisionedBy != "provider-admin" {
		t.Fatalf("managed tenant event payload = %+v", payload)
	}

	replayStatus, replayBody := doBearer(t, provider.ts, http.MethodPost, "/api/v1/managed-offering/tenants", providerToken, "cap-model-02-provision", request)
	if replayStatus != http.StatusCreated {
		t.Fatalf("provider replay = %d body %s", replayStatus, replayBody)
	}
	if string(replayBody) != string(body) {
		t.Fatalf("idempotent replay body changed\nfirst: %s\nreplay: %s", body, replayBody)
	}
	eventsAfter := managedTenantRegisteredEvents(t, provider.log, hostedTenantID)
	if len(eventsAfter) != 1 {
		t.Fatalf("tenant.registered events after replay = %d, want 1", len(eventsAfter))
	}
}

func managedTenantRegisteredEvents(t *testing.T, log *events.Log, tenantID string) []events.Event {
	t.Helper()
	var out []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == projections.EventTenantRegistered && e.TenantID == tenantID {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	return out
}

func testManagedOfferingLicenseManager(t *testing.T) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate license key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V:          1,
		ID:         "lic_test_managed_offering",
		Customer:   "Managed Provider",
		Tier:       license.TierProvider,
		TenantBand: 100,
		IssuedAt:   now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("sign provider license: %v", err)
	}
	path := filepath.Join(t.TempDir(), "provider-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write provider license: %v", err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatalf("load provider license: %v", err)
	}
	return mgr
}
