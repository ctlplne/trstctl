// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24: a tenant already using control-plane key
// generation keeps it on, and every other tenant that predates the switch is
// turned off. Each pre-switch tenant is decided once, from its own use: its
// certificates whose custody (recorded or derived) says the control plane made
// the key, its retained records of a generator run, and the compatibility
// socket. An operator's decision always stands, and a second pass decides
// nothing.
func TestServedPreSwitchTenantsAreDecidedOnceFromTheirOwnUse(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	const (
		usedCertificate = "77777777-7777-4777-8777-777777777771"
		usedGeneration  = "77777777-7777-4777-8777-777777777772"
		neverUsed       = "77777777-7777-4777-8777-777777777773"
		operatorDecided = "77777777-7777-4777-8777-777777777774"
	)
	for tenantID, name := range map[string]string{
		usedCertificate: "holds a control-plane key", usedGeneration: "recorded a key generation",
		neverUsed: "never generated one", operatorDecided: "decided by an operator",
	} {
		registerServedTenantID(t, h, tenantID, name)
	}
	notBefore, notAfter := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(24*time.Hour)
	if _, err := h.srv.orch.RecordCertificate(ctx, usedCertificate, store.Certificate{
		Subject: "CN=cp.example.test", Fingerprint: strings.Repeat("ab", 32), Source: "issued",
		NotBefore: &notBefore, NotAfter: &notAfter, KeyOrigin: "control_plane", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	keygen, err := json.Marshal(map[string]string{"identity_id": "", "name": "legacy.example.test",
		"detail": "the control plane generated this identity's subject key", "successor": "supply subject_csr_pem"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(ctx, events.Event{Type: "issuance.server_side_keygen", TenantID: usedGeneration, Data: keygen}); err != nil {
		t.Fatal(err)
	}
	operator := events.ContextWithActor(ctx, events.Actor{Subject: "ops@example.test"})
	if _, err := h.srv.orch.SetControlPlaneKeygen(operator, operatorDecided, projections.ControlPlaneKeygenSet{
		Enabled: true, Source: store.ControlPlaneKeygenSourceOperator, Reason: "kept on deliberately", SetBy: "ops@example.test",
	}); err != nil {
		t.Fatal(err)
	}

	decided, err := h.srv.DecideControlPlaneKeygenForPreSwitchTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if decided < 3 {
		t.Fatalf("decided %d pre-switch tenants, want at least the three undecided fixtures", decided)
	}
	want := map[string]struct {
		enabled bool
		source  string
	}{
		usedCertificate: {true, store.ControlPlaneKeygenSourceUpgrade},
		usedGeneration:  {true, store.ControlPlaneKeygenSourceUpgrade},
		neverUsed:       {false, store.ControlPlaneKeygenSourceUpgrade},
		operatorDecided: {true, store.ControlPlaneKeygenSourceOperator},
	}
	for tenantID, expect := range want {
		policy, found, err := h.store.ControlPlaneKeygenFor(ctx, tenantID)
		if err != nil || !found || policy.Enabled != expect.enabled || policy.Source != expect.source {
			t.Fatalf("tenant %s decision = %+v found=%v err=%v, want enabled=%v source=%s", tenantID, policy, found, err, expect.enabled, expect.source)
		}
	}
	if policy, _, _ := h.store.ControlPlaneKeygenFor(ctx, usedCertificate); policy.Evidence == nil || policy.Evidence.ControlPlaneCertificates != 1 {
		t.Fatalf("control-plane custody evidence = %+v", policy.Evidence)
	}
	if policy, _, _ := h.store.ControlPlaneKeygenFor(ctx, usedGeneration); policy.Evidence == nil || policy.Evidence.DeprecationEvents != 1 {
		t.Fatalf("recorded key generation evidence = %+v", policy.Evidence)
	}
	if again, err := h.srv.DecideControlPlaneKeygenForPreSwitchTenants(ctx); err != nil || again != 0 {
		t.Fatalf("a second pass decided %d tenants (err %v), want none", again, err)
	}
	if n := eventCount(t, h.log, neverUsed, projections.EventControlPlaneKeygenSet); n != 1 {
		t.Fatalf("the never-used tenant has %d decision events, want exactly one", n)
	}

	// The decided-off tenant refuses an issuance that would generate the key.
	tok := seedScopedTokenSubject(t, h.store, neverUsed, "alice@never.test", "owners:read", "owners:write", "identities:read", "identities:write", "certs:issue")
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: neverUsed, Kind: store.OwnerWorkload, Name: "upgrade-off"})
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{"owner_id": owner.ID, "kind": "x509", "name": "off.example.test"})
	var ident struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
		t.Fatalf("create identity = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, "upgrade-off-issue",
		map[string]any{"to": "issued", "reason": "no csr"})
	if status != http.StatusConflict || !strings.Contains(string(body), "control_plane_keygen_off") {
		t.Fatalf("issue without a CSR after the upgrade decided off = %d %s", status, body)
	}
}

// The upgrade fills only an empty decision: an operator's change recorded
// first, even in the same moment, stands.
func TestUpgradeDecisionNeverReplacesAnOperatorDecision(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	operator := events.ContextWithActor(ctx, events.Actor{Subject: "ops@example.test"})
	if _, err := h.srv.orch.SetControlPlaneKeygen(operator, h.tenant, projections.ControlPlaneKeygenSet{
		Enabled: false, Source: store.ControlPlaneKeygenSourceOperator, Reason: "off by policy", SetBy: "ops@example.test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyControlPlaneKeygenSetTx(ctx, tx, store.ControlPlaneKeygenPolicy{
			TenantID: h.tenant, Enabled: true, Source: store.ControlPlaneKeygenSourceUpgrade,
			Reason: "predates the switch", SetBy: "system:upgrade", SetAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	policy, found, err := h.store.ControlPlaneKeygenFor(ctx, h.tenant)
	if err != nil || !found || policy.Enabled || policy.Source != store.ControlPlaneKeygenSourceOperator {
		t.Fatalf("decision after a late upgrade = %+v found=%v err=%v, want the operator's", policy, found, err)
	}
}

// The compatibility socket configured for a pre-switch tenant keeps it on.
func TestPreSwitchTenantServedByTheCompatibilitySocketStaysOn(t *testing.T) {
	h, _, _ := servedSPIFFEWorkloadClient(t, true)
	if _, err := h.srv.DecideControlPlaneKeygenForPreSwitchTenants(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy, found, err := h.store.ControlPlaneKeygenFor(t.Context(), servedTestTenant)
	if err != nil || !found || !policy.Enabled || policy.Evidence == nil || !policy.Evidence.WorkloadAPISocket {
		t.Fatalf("socket tenant decision = %+v found=%v err=%v, want on with the socket as evidence", policy, found, err)
	}
}
