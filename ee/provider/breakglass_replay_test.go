// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

type replaySnapshotReader struct {
	calls int
}

func (r *replaySnapshotReader) TenantSnapshot(_ context.Context, tenantID string) (TenantSnapshot, error) {
	r.calls++
	return TenantSnapshot{TenantID: tenantID, Health: "healthy"}, nil
}

// Real PostgreSQL idempotency and JetStream authority events must preserve an
// authorized retry without turning its key into permanent customer access.
func TestBreakGlassCachedResultsRequireCurrentAuthority(t *testing.T) {
	for _, change := range []string{"delegation-revoked", "delegations-unavailable", "mfa-lost", "role-lost", "grant-expired", "grant-revoked"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			st := openProviderStore(t)
			truncateProviderAuthority(t, st)
			log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			runtime := NewAuthorityRuntime(st, log)
			suffix := uuid.NewString()
			slug := "replay-" + suffix
			customer := CustomerID(slug)
			now := time.Date(2026, 9, 16, 20, 0, 0, 0, time.UTC)
			delegations := append(fullyDelegated("op-1", customer),
				Delegation{OperatorID: "approver-a", CustomerID: customer, Operations: []Operation{OpBreakGlass}},
				Delegation{OperatorID: "approver-b", CustomerID: customer, Operations: []Operation{OpBreakGlass}})
			telemetry := &replaySnapshotReader{}
			h := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st),
				Mutations: runtime.Mutations, Idempotency: orchestrator.NewIdempotency(st),
				Authenticator: authorityAuthenticator{}, Delegations: delegations,
				Telemetry: telemetry, Clock: func() time.Time { return now },
			}).(*handler)
			request := func(path, actor, key, body string, want int) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+actor)
				req.Header.Set("Idempotency-Key", suffix+"-"+key)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != want {
					t.Fatalf("%s %s = %d/%s, want %d", key, path, w.Code, w.Body.String(), want)
				}
				return w
			}
			request("/provider/v1/tenants", "requester", "provision", fmt.Sprintf(`{"slug":%q,"name":"Replay customer"}`, slug), http.StatusCreated)
			created := request("/provider/v1/breakglass", "requester", "request",
				fmt.Sprintf(`{"tenant_id":%q,"reason":"incident","ttl":"15m"}`, customer), http.StatusCreated)
			var grant BreakGlassGrant
			if err := json.Unmarshal(created.Body.Bytes(), &grant); err != nil || grant.ID == "" {
				t.Fatalf("decode grant: %v", err)
			}
			base := "/provider/v1/breakglass/" + grant.ID
			request(base+"/results", "requester", "refused", `{}`, http.StatusForbidden)
			for _, approver := range []string{"approver-a", "approver-b"} {
				request(base+"/consent", approver, approver,
					fmt.Sprintf(`{"tenant_id":%q,"approve":true}`, customer), http.StatusOK)
			}
			refusal := request(base+"/results", "requester", "refused", `{}`, http.StatusForbidden)
			if refusal.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatal("the original refusal must remain bound to its key after consent")
			}
			first := request(base+"/results", "requester", "success", `{}`, http.StatusOK)
			before, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			again := request(base+"/results", "requester", "success", `{}`, http.StatusOK)
			if again.Header().Get("Idempotent-Replayed") != "true" || again.Body.String() != first.Body.String() {
				t.Fatal("authorized replay must return the original bytes with the replay marker")
			}
			request(base+"/results", "requester", "success", `{"changed":true}`, http.StatusConflict)
			request(base+"/results", "approver-a", "success", `{}`, http.StatusConflict)
			after, err := log.LastSequence(ctx)
			if err != nil || after != before || telemetry.calls != 1 {
				t.Fatalf("replay repeated snapshot/event: calls=%d sequence=%d -> %d, err=%v", telemetry.calls, before, after, err)
			}
			switch change {
			case "delegation-revoked":
				h.svc.delegations = StaticDelegations{}
			case "delegations-unavailable":
				h.svc.delegations = brokenDelegations{}
			case "mfa-lost", "role-lost":
				actor := providerOperator("op-1")
				if change == "mfa-lost" {
					actor.MFA = false
				} else {
					actor.Role = ""
				}
				h.svc.authenticator = consoleAuthorityAuth{operator: actor}
			case "grant-expired":
				now = grant.ExpiresAt
			case "grant-revoked":
				current, err := h.svc.store.BreakGlassGrant(ctx, grant.ID)
				if err != nil {
					t.Fatal(err)
				}
				current.RevokedAt = now
				if _, err := runtime.Mutations.Append(ctx, suffix+"-revoke", AuditBreakGlassDenied, customer,
					AuthorityEvent{Grant: &current, Audit: AuditEvent{Type: AuditBreakGlassDenied, TenantID: customer, GrantID: grant.ID, Subject: "approver-a", At: now}}); err != nil {
					t.Fatal(err)
				}
			}
			before, err = log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			denied := request(base+"/results", "requester", "success", `{}`, http.StatusForbidden)
			if strings.Contains(denied.Body.String(), `"health"`) || denied.Header().Get("Idempotent-Replayed") != "" {
				t.Fatal("a current authorization refusal must not expose or label the cached snapshot")
			}
			after, err = log.LastSequence(ctx)
			stored, readErr := h.svc.store.BreakGlassGrant(ctx, grant.ID)
			if err != nil || readErr != nil || after != before || telemetry.calls != 1 || stored.UseCount != 1 {
				t.Fatalf("refused replay repeated effects: calls=%d count=%d sequence=%d -> %d errors=%v/%v", telemetry.calls, stored.UseCount, before, after, err, readErr)
			}
		})
	}
}
