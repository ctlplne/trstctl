// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/profile"
)

func TestServedACMEPlanRejectsProfileWithoutUsableValidity(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	token := seedScopedToken(t, h.store, h.tenant, string(authz.IssuersRead))
	for _, tc := range []struct {
		name    string
		maximum time.Duration
		ready   bool
	}{
		{"too-short", 2 * time.Minute, false},
		{"equals-backdate", 5 * time.Minute, false},
		{"usable-short", 10 * time.Minute, true},
		{"unlimited", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeServerTestProfile(t, h.store, h.tenant, tc.name, profile.CertificateProfile{Name: tc.name, MaxValidity: profile.Duration(tc.maximum), AllowedProtocols: []string{"acme"}})
			h.srv.defaultProfile = tc.name
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/operator-plan", token, nil)
			var plan struct {
				Ready        bool     `json:"ready"`
				ProfileReady bool     `json:"issuing_profile_ready"`
				Blockers     []string `json:"blockers"`
				Recovery     []string `json:"recovery_steps"`
			}
			if err := json.Unmarshal(body, &plan); err != nil {
				t.Fatal(err)
			}
			if status != http.StatusOK || plan.Ready != tc.ready || plan.ProfileReady != tc.ready {
				t.Fatalf("readiness status=%d body=%s", status, body)
			}
			if !tc.ready && (!strings.Contains(strings.Join(plan.Blockers, " "), "backdate") || len(plan.Recovery) == 0) {
				t.Fatalf("missing actionable profile failure: %s", body)
			}
		})
	}
}

// F5 needs one server-owned answer to the operator's simple question: "Can an
// ACME client get a certificate from this tenant right now?" Browser probes can
// only prove that one browser reached one URL. They cannot prove the tenant
// binding, issuing profile, EAB admission, or whether asking the question changed
// durable state. This control drives the assembled binary and locks those
// promises together.
func TestServedACMEOperatorPlanIsTenantBoundSecretFreeAndEffectFree(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x5a}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{
			Required: true,
			Keys: []config.ACMEExternalAccountBindingKey{{
				KeyID: "payments-team", HMACKey: hmacKey,
				AllowedIdentifiers: []string{"*.payments.example.test"},
			}},
		},
	})
	tok := seedScopedToken(t, h.store, h.tenant, string(authz.IssuersRead))

	eventHeadBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("event head before plan: %v", err)
	}
	var outboxBefore, idempotencyBefore int
	if err := h.store.SystemPool().QueryRow(t.Context(), `
		SELECT
		  (SELECT count(*) FROM outbox WHERE tenant_id = $1),
		  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`,
		h.tenant).Scan(&outboxBefore, &idempotencyBefore); err != nil {
		t.Fatalf("durable counts before plan: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/operator-plan", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("ACME operator plan = %d, want 200; body=%s", status, body)
	}
	var plan struct {
		Ready                bool     `json:"ready"`
		Served               bool     `json:"served"`
		TenantBound          bool     `json:"tenant_bound"`
		DirectoryPath        string   `json:"directory_path"`
		ChallengeMethods     []string `json:"challenge_methods"`
		EABRequired          bool     `json:"eab_required"`
		EABConfigured        int      `json:"eab_configured"`
		EABActive            int      `json:"eab_active"`
		DNS01ProviderConfigs int      `json:"dns01_provider_configs"`
		IssuingProfileReady  bool     `json:"issuing_profile_ready"`
		ActivationMode       string   `json:"activation_mode"`
		ActivationRequired   bool     `json:"activation_required"`
		ActivationAvailable  bool     `json:"activation_available"`
		NextAction           struct {
			Kind   string `json:"kind"`
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"next_action"`
		Blockers               []string `json:"blockers"`
		RecoverySteps          []string `json:"recovery_steps"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode ACME operator plan: %v body=%s", err, body)
	}
	if !plan.Ready || !plan.Served || !plan.TenantBound || !plan.IssuingProfileReady {
		t.Fatalf("plan is not honestly ready: %+v", plan)
	}
	if plan.DirectoryPath != "/directory" || plan.ActivationMode != "startup_configuration" ||
		plan.ActivationRequired || plan.ActivationAvailable {
		t.Fatalf("production execution boundary is ambiguous: %+v", plan)
	}
	if plan.NextAction.Kind != "connect_acme_client" || plan.NextAction.Method != "GET" || plan.NextAction.Path != "/directory" {
		t.Fatalf("next action = %+v, want stock-client connection to the served directory", plan.NextAction)
	}
	if !slices.Equal(plan.ChallengeMethods, []string{"http-01", "dns-01", "tls-alpn-01"}) {
		t.Fatalf("challenge methods = %v", plan.ChallengeMethods)
	}
	if !plan.EABRequired || plan.EABConfigured != 1 || plan.EABActive != 1 {
		t.Fatalf("EAB readiness = required %v configured %d active %d", plan.EABRequired, plan.EABConfigured, plan.EABActive)
	}
	if plan.DNS01ProviderConfigs != 0 || len(plan.Blockers) != 0 || len(plan.RecoverySteps) == 0 {
		t.Fatalf("plan evidence is incomplete: %+v", plan)
	}
	if plan.PreviewWrites == nil || len(plan.PreviewWrites) != 0 ||
		plan.PreviewExternalEffects == nil || len(plan.PreviewExternalEffects) != 0 {
		t.Fatalf("operator plan does not explicitly prove an effect-free read: writes=%v external=%v", plan.PreviewWrites, plan.PreviewExternalEffects)
	}
	for _, forbidden := range [][]byte{hmacKey, []byte("WlpaWlpa"), []byte("hmac_key")} {
		if bytes.Contains(bytes.ToLower(body), bytes.ToLower(forbidden)) {
			t.Fatalf("operator plan leaks EAB secret material (%q): %s", forbidden, body)
		}
	}

	eventHeadAfter, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("event head after plan: %v", err)
	}
	var outboxAfter, idempotencyAfter int
	if err := h.store.SystemPool().QueryRow(t.Context(), `
		SELECT
		  (SELECT count(*) FROM outbox WHERE tenant_id = $1),
		  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`,
		h.tenant).Scan(&outboxAfter, &idempotencyAfter); err != nil {
		t.Fatalf("durable counts after plan: %v", err)
	}
	if eventHeadAfter != eventHeadBefore || outboxAfter != outboxBefore || idempotencyAfter != idempotencyBefore {
		t.Fatalf("read changed durable state: events %d→%d outbox %d→%d idempotency %d→%d",
			eventHeadBefore, eventHeadAfter, outboxBefore, outboxAfter, idempotencyBefore, idempotencyAfter)
	}
}

// A tenant that does not own the single served ACME mount gets a useful blocked
// answer, but none of the owning tenant's EAB counts or policy details.
func TestServedACMEOperatorPlanDoesNotDescribeAnotherTenantsMount(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{{
			KeyID: "private-tenant-kid", HMACKey: bytes.Repeat([]byte{0x21}, 32),
		}}},
	})
	otherTenant := "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, otherTenant, "Other operator-plan tenant")
	tok := seedScopedToken(t, h.store, otherTenant, string(authz.IssuersRead))
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/operator-plan", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("other-tenant plan = %d, want blocked 200; body=%s", status, body)
	}
	if bytes.Contains(body, []byte("private-tenant-kid")) || bytes.Contains(body, []byte(servedTestTenant)) {
		t.Fatalf("operator plan exposed another tenant's mount: %s", body)
	}
	var plan struct {
		Ready         bool     `json:"ready"`
		Served        bool     `json:"served"`
		TenantBound   bool     `json:"tenant_bound"`
		EABRequired   bool     `json:"eab_required"`
		EABConfigured int      `json:"eab_configured"`
		Blockers      []string `json:"blockers"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Ready || plan.Served || plan.TenantBound || plan.EABRequired || plan.EABConfigured != 0 || len(plan.Blockers) == 0 {
		t.Fatalf("cross-tenant plan was not safely blocked: %+v", plan)
	}
}

// F73's console evidence must come from an order accepted by the real served
// ACME responder, not from browser state or the effect-free DNS preflight. The
// operator plan may reveal the domain and policy result to an authorized tenant,
// but never the account URL or challenge token needed to answer the challenge.
func TestServedACMEOperatorPlanShowsSanitizedRealDomainValidationActivity(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	tok := seedScopedToken(t, h.store, h.tenant, string(authz.IssuersRead), string(authz.IssuersWrite))
	credentialRef := "secret://dns/" + t.Name()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "operator-activity-policy", "provider": "webhook", "zone": "activity.example.test",
		"credential_refs": map[string]any{
			"bearer_token_ref": credentialRef,
		},
		"config":          map[string]any{"endpoint": "https://dns.activity.invalid"},
		"allowed_methods": []string{"dns-01"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create domain-validation policy: status=%d body=%s", status, body)
	}

	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("ACME client: %v", err)
	}
	if _, err := client.Register(t.Context(), &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register ACME account: %v", err)
	}
	order, err := client.AuthorizeOrder(t.Context(), xacme.DomainIDs("api.activity.example.test"))
	if err != nil {
		t.Fatalf("create served ACME order: %v", err)
	}
	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("read served ACME authorization: %v", err)
	}
	if len(authz.Challenges) != 1 || authz.Challenges[0].Type != "dns-01" {
		t.Fatalf("served policy challenge choices = %+v, want dns-01 only", authz.Challenges)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/operator-plan", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read ACME operator plan: status=%d body=%s", status, body)
	}
	var plan struct {
		ValidationActivity []struct {
			OrderID             string   `json:"order_id"`
			Domain              string   `json:"domain"`
			OrderStatus         string   `json:"order_status"`
			AuthorizationStatus string   `json:"authorization_status"`
			ChallengeMethods    []string `json:"challenge_methods"`
			ValidatedMethod     string   `json:"validated_method"`
		} `json:"validation_activity"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode activity plan: %v body=%s", err, body)
	}
	if len(plan.ValidationActivity) != 1 {
		t.Fatalf("operator validation activity rows = %d, want 1: %s", len(plan.ValidationActivity), body)
	}
	activity := plan.ValidationActivity[0]
	if activity.OrderID == "" || activity.Domain != "api.activity.example.test" || activity.OrderStatus != "pending" ||
		activity.AuthorizationStatus != "pending" || !slices.Equal(activity.ChallengeMethods, []string{"dns-01"}) || activity.ValidatedMethod != "" {
		t.Fatalf("operator validation activity = %+v", activity)
	}
	for _, forbidden := range []string{authz.Challenges[0].Token, string(client.KID), credentialRef, "bearer_token_ref"} {
		if forbidden != "" && bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("operator validation activity leaked %q: %s", forbidden, body)
		}
	}
}
