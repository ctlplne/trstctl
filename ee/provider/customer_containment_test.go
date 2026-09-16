// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// Exercise the other plane with a real hashed customer credential, rather than
// accepting the Provider registry's status as proof that service has stopped.
func TestProviderStatusContainsExistingCustomerCredential(t *testing.T) {
	for _, operation := range []string{"suspend", "offboard"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			st := openProviderStore(t)
			truncateProviderAuthority(t, st)
			log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			runtime := NewAuthorityRuntime(st, log)
			slug := "customer-containment-" + operation
			id := CustomerID(slug)
			idem := orchestrator.NewIdempotency(st)
			orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
			provider := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st),
				Mutations: runtime.Mutations, Idempotency: idem, Authenticator: authorityAuthenticator{},
				Delegations: &mutableDelegations{set: fullyDelegated("op-1", id)},
			})
			mutate := func(path, key, body string, want int) {
				t.Helper()
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer requester")
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				provider.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
				}
			}
			mutate("/provider/v1/tenants", "containment-provision-"+operation,
				`{"slug":"`+slug+`","name":"Customer containment"}`, http.StatusCreated)
			// Reproduce the documented host-local registration used by an existing
			// deployment. Provisioning must also work without that assistance.
			payload, _ := json.Marshal(map[string]string{"name": "Customer containment"})
			_, err = orchestrator.ExecuteTenantRegistration(ctx, log, st, projections.New(st), idem,
				orchestrator.TenantRegistrationCommand{TenantID: id, Name: "Customer containment",
					IdempotencyKey: "customer-bootstrap-" + operation, RequestMaterial: payload,
					PayloadAt: func(time.Time) ([]byte, error) { return payload, nil },
				})
			if err != nil {
				t.Fatal(err)
			}
			raw, hash, err := auth.GenerateAPIToken()
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(raw)
			if _, err := st.CreateAPIToken(ctx, corestore.APITokenRecord{TenantID: id, TokenHash: hash,
				Subject: "customer-automation", Scopes: []string{"owners:read", "owners:write"}}); err != nil {
				t.Fatal(err)
			}
			customer := api.New(st, idem, orch, api.WithTenantServiceCheck(NewPGStore(st).RequireCustomerService))
			probe := func(method, key string) int {
				r := httptest.NewRequest(method, "/api/v1/owners", strings.NewReader(`{"kind":"team","name":"Containment proof","email":"qa@example.test"}`))
				r.Header.Set("Authorization", "Bearer "+string(raw))
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				customer.ServeHTTP(w, r)
				return w.Code
			}
			if got := probe(http.MethodGet, ""); got != http.StatusOK {
				t.Fatalf("active read = %d", got)
			}
			if got := probe(http.MethodPost, "before"); got != http.StatusCreated {
				t.Fatalf("active write = %d", got)
			}
			outbox := orchestrator.NewOutbox(st, orchestrator.WithTenantServiceCheck(NewPGStore(st).RequireCustomerService), orchestrator.WithBackoff(func(int) time.Duration { return 0 }), orchestrator.WithRetryJitter(func(d time.Duration) time.Duration { return d }))
			var deliveryID int64
			if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
				var err error
				deliveryID, err = outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: id, Destination: "containment.probe", IdempotencyKey: "delivery-" + operation, Payload: []byte(`{}`)})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			handler := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { calls++; return nil })
			mutate("/provider/v1/tenants/"+id+"/"+operation, "containment-"+operation, `{}`, http.StatusNoContent)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				if got := probe(method, "after-"+method); got != http.StatusForbidden && got != http.StatusUnauthorized {
					t.Errorf("%s customer %s = %d; old credential must be refused", operation, method, got)
				}
			}
			if _, err := outbox.DispatchOneScoped(ctx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{"containment.probe"}}); err != nil {
				t.Fatal(err)
			}
			if calls != 0 {
				t.Fatalf("%s delivered queued work", operation)
			}
			if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
				var status string
				var attempts int
				if err := tx.QueryRow(ctx, `SELECT status, attempts FROM outbox WHERE tenant_id = $1 AND id = $2`, id, deliveryID).Scan(&status, &attempts); err != nil {
					return err
				}
				if status != "pending" || attempts != 0 {
					t.Errorf("paused delivery = %s/%d; suspension must not spend retry budget", status, attempts)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if operation == "suspend" {
				mutate("/provider/v1/tenants/"+id+"/resume", "containment-resume", `{}`, http.StatusNoContent)
				if got := probe(http.MethodGet, ""); got != http.StatusOK {
					t.Fatalf("resumed read = %d", got)
				}
				if got := probe(http.MethodPost, "resumed-write"); got != http.StatusCreated {
					t.Fatalf("resumed write = %d", got)
				}
				if _, err := outbox.DispatchOneScoped(ctx, handler, orchestrator.DestinationScope{IncludePrefixes: []string{"containment.probe"}}); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("resumed delivery calls = %d", calls)
				}
			}

		})
	}
}
