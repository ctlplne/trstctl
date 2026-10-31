// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type readableHTTPAuthority struct {
	mu      sync.Mutex
	ref     eventprotect.KeyRef
	request eventprotect.DestructionRequest
}

func (a *readableHTTPAuthority) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef, visit func(context.Context) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return visit(ctx)
}
func (a *readableHTTPAuthority) WithTenantEventProtection(ctx context.Context, _ string, visit func(context.Context) error) error {
	return visit(ctx)
}
func (a *readableHTTPAuthority) EventProtectionFor(_ context.Context, event events.Event) (events.EventProtectionDecision, error) {
	if event.TenantID != a.ref.TenantID {
		return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: a.ref}, nil
}
func (a *readableHTTPAuthority) AuthorizeDestruction(_ context.Context, request eventprotect.DestructionRequest) error {
	if request != a.request {
		return eventprotect.ErrContext
	}
	return nil
}

const readableHTTPEventType = "a233.audit_http_private"

func init() {
	if err := events.RegisterPrivacyEventPolicy(readableHTTPEventType, 1, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}},
		PayloadShape: events.PrivacyPayloadShapeOf[struct {
			Email string `json:"email"`
		}](),
	}); err != nil {
		panic(err)
	}
}

// Real HTTP handler/role guard, NATS, and independent file custody. Principal,
// admission/removal authority and signer are explicit local fixtures; this does
// not qualify production activation/outbox, PostgreSQL restore or signer isolation.
func TestAuditHTTPKeepsSignedRecordsAndReadableDetailsSeparateAcrossKeyRemoval(t *testing.T) {
	const tenant = "44ab0fd8-1b9f-44eb-9fbe-205e7caf71ae"
	const neighbor = "2757a521-125a-4255-85dc-55ad89fd14b2"
	base := t.TempDir()
	key, err := jose.GenerateRSASigningKey("audit-readable-http-fixture")
	if err != nil {
		t.Fatal(err)
	}
	authority := &readableHTTPAuthority{ref: eventprotect.KeyRef{TenantID: tenant, ID: "e4559bd6-750c-4c2a-8e63-647830981214"}}
	custody, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: authority, EvidenceKey: key, DestructionAuthority: authority})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	if err := custody.Provision(t.Context(), authority.ref); err != nil {
		t.Fatal(err)
	}
	creation, err := custody.CreationEvidence(t.Context(), authority.ref)
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")}, events.WithEventProtection(events.EventProtection{Admission: authority, Keys: custody}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, id := range []string{"http-protected-first", "http-protected-last"} {
		if _, err := log.Append(t.Context(), events.Event{ID: id, Type: readableHTTPEventType, TenantID: tenant, Data: []byte(`{"email":"http-person-private@example.invalid"}`), Actor: &events.Actor{Subject: "http-operator-private@example.invalid"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(t.Context(), events.Event{Type: "neighbor.public", TenantID: neighbor, Data: []byte(`{"name":"neighbor-not-for-caller"}`)}); err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, key)
	role := authz.Role{Name: "audit-reader", Permissions: []authz.Permission{authz.AuditRead}}
	principal := authz.Principal{TenantID: tenant, Subject: "reader-fixture", Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tenant}}}}
	handler := api.New(nil, nil, nil, api.WithAudit(service), api.WithRoles(role), api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }))
	get := func(path, tenantHeader string, want int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if tenantHeader != "" {
			request.Header.Set("X-Tenant-ID", tenantHeader)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("audit HTTP status=%d want=%d", response.Code, want)
		}
		return response
	}
	type responseBody struct {
		Events   []audit.Record        `json:"events"`
		Readable []audit.ReadableEvent `json:"readable_events"`
		Count    int                   `json:"count"`
	}
	decode := func(response *httptest.ResponseRecorder) responseBody {
		t.Helper()
		var result responseBody
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(response.Body.Bytes(), []byte("neighbor-not-for-caller")) {
			t.Fatal("neighbor data entered the caller response")
		}
		return result
	}
	before := decode(get("/api/v1/audit/events?limit=1&window=latest", "", http.StatusOK))
	if before.Count != 1 || len(before.Events) != 1 || len(before.Readable) != 1 {
		t.Fatalf("HTTP response did not include the exact readable view: events=%d readable=%d count=%d", len(before.Events), len(before.Readable), before.Count)
	}
	record, readable := before.Events[0], before.Readable[0]
	if record.ID != "http-protected-last" || readable.ID != record.ID || readable.Sequence != record.Sequence || readable.Actor == nil || readable.Actor.Subject != "http-operator-private@example.invalid" || readable.SensitiveErased || !bytes.Contains(readable.Data, []byte("http-person-private@example.invalid")) {
		t.Fatal("readable fields lost exact limited record binding")
	}
	if record.Actor != nil || bytes.Contains(record.Data, []byte("example.invalid")) {
		t.Fatal("HTTP signed core contains readable protected fields")
	}
	get("/api/v1/audit/events", neighbor, http.StatusForbidden)
	principal.Grants = nil
	get("/api/v1/audit/events", "", http.StatusForbidden)
	principal.Grants = []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: tenant}}}
	offboarded := time.Now().UTC()
	authority.request = eventprotect.DestructionRequest{Ref: authority.ref, OperationID: "00eb65e6-101c-4913-8f63-ef6536413c29", RegistrationIdentity: "http-fixture-registration", ActivationEventID: "http-fixture-activation", ActivationSequence: 1, CreationDigest: creation.Digest(), OffboardEventID: "http-fixture-offboard", OffboardSequence: 4, OffboardedAt: offboarded, NotBefore: offboarded.Add(2 * time.Millisecond)}
	time.Sleep(time.Until(authority.request.NotBefore))
	if _, err := custody.Destroy(t.Context(), authority.request); err != nil {
		t.Fatal(err)
	}
	after := decode(get("/api/v1/audit/events?limit=1&window=latest", "", http.StatusOK))
	if len(after.Events) != 1 || len(after.Readable) != 1 || after.Events[0].Hash != record.Hash || !bytes.Equal(after.Events[0].Data, record.Data) {
		t.Fatal("removal changed the HTTP immutable commitment")
	}
	erased := after.Readable[0]
	if !erased.SensitiveErased || len(erased.Data) != 0 || erased.Actor != nil || erased.ID != record.ID || erased.Sequence != record.Sequence {
		t.Fatal("HTTP erased details were not explicit or retained personal values")
	}
	if filtered := decode(get("/api/v1/audit/events?q=example.invalid", "", http.StatusOK)); len(filtered.Events) != 0 || len(filtered.Readable) != 0 {
		t.Fatal("erased fields still matched a private search")
	}
}
