// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestProviderStatusRefusesClaimedRemoteWork(t *testing.T) {
	for _, action := range []string{"suspend", "offboard"} {
		t.Run(action, func(t *testing.T) {
			st, log, runtimeSink := authorityReplayFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			id := CustomerID("remote-in-flight-" + action)
			runtime := NewAuthorityRuntime(st, log)
			projector := projections.New(st, runtime.ProjectionOptions...)
			idem := orchestrator.NewIdempotency(st)
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "remote-in-flight-" + action, Name: "In-flight customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
			if _, err := runtimeSink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"name":"In-flight customer"}`)
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem, orchestrator.TenantRegistrationCommand{
				TenantID: id, Name: tenant.Name, IdempotencyKey: "register-remote", RequestMaterial: payload,
				PayloadAt: func(time.Time) ([]byte, error) { return payload, nil },
			}); err != nil {
				t.Fatal(err)
			}
			provider := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
				Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: &mutableDelegations{set: fullyDelegated("op-1", id)},
				Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)})

			root := t.TempDir()
			fixture, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fixture.Close() }()
			key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			der, err := crypto.SelfSignedCACert(key, "Owned remote-work fixture", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			intent := relay.TrustDistributionIntent{RunID: "remote-proof", WaveID: "one", IdentityID: "remote-proof", Operation: relay.TrustInstall,
				AnchorPath: filepath.Join(root, "root.pem"), AnchorPEM: crypto.EncodeCertificatePEM(der), AnchorFingerprint: crypto.SHA256Hex(der)}
			payload, err = json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			const agentID = "341c576e-6ab6-4924-972d-9a179c57b149"
			outbox := orchestrator.NewOutbox(st)
			if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
				_, err := outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: id, Destination: relay.KindTrustDistribute, Payload: payload, IdempotencyKey: "remote-trust", RequiredAgentRole: "host", RequiredAgentID: agentID})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			jobs, err := st.ClaimAgentJobs(ctx, id, agentID, []string{relay.KindTrustDistribute}, []string{"host"}, 1, time.Minute, time.Now())
			if err != nil || len(jobs) != 1 {
				t.Fatalf("claim=%d err=%v", len(jobs), err)
			}
			// The claim transaction and its request have returned. The remote executor
			// now owns the payload independently of any control-plane session lock.
			r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/"+action, strings.NewReader(`{}`)).WithContext(ctx)
			r.Header.Set("Authorization", "Bearer requester")
			r.Header.Set("Idempotency-Key", "remote-transition")
			w := httptest.NewRecorder()
			provider.ServeHTTP(w, r)
			var received relay.TrustDistributionIntent
			if err := json.Unmarshal(jobs[0].Payload, &received); err != nil {
				t.Fatal(err)
			}
			if _, err := relay.ExecuteTrustDistribution(ctx, connector.LocalOpsConfig{AllowedRoots: []string{root}}, received); err != nil {
				t.Fatal(err)
			}
			actual, err := fixture.ReadFile("root.pem")
			if err != nil || crypto.SHA256Hex(actual) != crypto.SHA256Hex(intent.AnchorPEM) {
				t.Fatalf("remote trust write not observed: %v", err)
			}
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
				t.Errorf("%s returned %d before claimed remote trust write completed; want retryable refusal", action, w.Code)
			}
			if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantActive {
				t.Errorf("remote work changed tenant state: %+v %v", current, err)
			}
		})
	}
}

func TestProviderStatusRefusesUncertainControlPlaneDelivery(t *testing.T) {
	for _, action := range []string{"suspend", "offboard"} {
		t.Run(action, func(t *testing.T) {
			st, log, runtimeSink := authorityReplayFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			id := CustomerID("native-uncertain-" + action)
			runtime := NewAuthorityRuntime(st, log)
			projector := projections.New(st, runtime.ProjectionOptions...)
			idem := orchestrator.NewIdempotency(st)
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "native-uncertain-" + action, Name: "In-flight customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
			if _, err := runtimeSink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"name":"In-flight customer"}`)
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem, orchestrator.TenantRegistrationCommand{
				TenantID: id, Name: tenant.Name, IdempotencyKey: "register-remote", RequestMaterial: payload,
				PayloadAt: func(time.Time) ([]byte, error) { return payload, nil },
			}); err != nil {
				t.Fatal(err)
			}
			provider := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
				Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: &mutableDelegations{set: fullyDelegated("op-1", id)},
				Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)})

			outbox := orchestrator.NewOutbox(st)
			if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
				_, err := outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: id, Destination: "provider-unknown.probe", IdempotencyKey: "native-uncertain", Payload: []byte(`{}`)})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// The dispatcher has returned and released every live session lock.
			// This fixture models an uncertain transport result; separate native
			// HTTP/process-kill tests prove that the remote effect can continue.
			claimed, err := outbox.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
				return errors.New("receiver response lost")
			}), orchestrator.DestinationScope{IncludePrefixes: []string{"provider-unknown.probe"}})
			if err != nil || !claimed {
				t.Fatalf("dispatch=%v, %v", claimed, err)
			}
			r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/"+action, strings.NewReader(`{}`)).WithContext(ctx)
			r.Header.Set("Authorization", "Bearer requester")
			r.Header.Set("Idempotency-Key", "native-transition")
			w := httptest.NewRecorder()
			provider.ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" || !strings.Contains(w.Body.String(), "provider-unknown.probe") {
				t.Fatalf("%s failed to explain unresolved receiver: status=%d body=%s", action, w.Code, w.Body.String())
			}
			if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantActive {
				t.Fatalf("uncertain remote result changed customer state: %+v %v", current, err)
			}
		})
	}
}
