// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventstest"
)

// TestNK14OneSubjectMatchingTwoOperatorsIsRefused (R1 verify VH42; PostgreSQL,
// the embedded event log, the served Provider SCIM handler and the OIDC bearer
// path). The IdP provisions alice with externalId S (her OIDC sub) and then bob
// with userName S. S now names two operators in two different columns.
// ResolveOperator(S) must refuse the ambiguity (or SCIM must refuse bob's
// create), and alice's IdP-signed token must never authenticate as bob, who
// matches S only through userName.
func TestNK14OneSubjectMatchingTwoOperatorsIsRefused(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	access := NewPGAccessStore(st)
	mutations := NewEventMutationSink(log, NewAuthorityProjection(st))
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	s := newA221SCIM(t, access, mutations, func() time.Time { return now })

	// Okta-shaped object IDs: alice's is her OIDC sub; bob's userName is that string.
	const subject = "00u1nk14subject"
	user := func(externalID, userName, role string) string {
		return `{"schemas":["` + scim.SchemaUser + `"],"externalId":"` + externalID + `","userName":"` + userName +
			`","roles":[{"value":"` + role + `"}],"active":true}`
	}
	idOf := func(label string, code int, body []byte) string {
		t.Helper()
		var u struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &u); err != nil || u.ID == "" {
			t.Fatalf("%s: decode %d %s: %v", label, code, body, err)
		}
		return u.ID
	}

	rec := s.call(http.MethodPost, "/provider/scim/v2/Users", user(subject, "alice@example.test", "admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create alice = %d %s", rec.Code, rec.Body.String())
	}
	aliceID := idOf("alice", rec.Code, rec.Body.Bytes())
	rec = s.call(http.MethodPost, "/provider/scim/v2/Users", user("00u9nk14bob", subject, "operator"))
	if rec.Code == http.StatusConflict {
		t.Logf("SCIM refused bob's userName %q (alice's externalId): %s", subject, rec.Body.String())
		return
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("create bob = %d %s", rec.Code, rec.Body.String())
	}
	bobID := idOf("bob", rec.Code, rec.Body.Bytes())
	t.Logf("SCIM create of bob with userName = alice's externalId %q answered %d (no uniqueness refusal); alice=%s bob=%s",
		subject, rec.Code, aliceID, bobID)

	plan := func(stage string) {
		t.Helper()
		rows, err := st.SystemPool().Query(ctx, `EXPLAIN (COSTS OFF) SELECT id FROM provider_operators
			WHERE tenant_id = $1 AND (id = $2 OR external_id = $2 OR user_name = $2)`, providerAuthorityTenant, subject)
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s plan: %s", stage, line)
		}
	}
	resolve := func(stage string) {
		t.Helper()
		plan(stage)
		got, err := access.ResolveOperator(ctx, subject)
		if err == nil {
			t.Errorf("%s: ResolveOperator(%q) matches alice (externalId) and bob (userName) but returned %s (role %q) "+
				"without refusing the ambiguity", stage, subject, got.ID, got.Role)
		}
	}
	signIn := func(stage string) {
		t.Helper()
		op, ok := s.signIn(subject)
		t.Logf("%s: alice's IdP-signed token (sub %q) -> ok=%v operator=%s role=%q", stage, subject, ok, op.ID, op.Role)
		if ok && op.ID == bobID {
			t.Errorf("%s: alice's IdP-signed token (sub %q) authenticated as bob's operator %s (role %q); "+
				"bob matches that subject only through userName", stage, subject, op.ID, op.Role)
		}
	}

	resolve("after both creates")
	signIn("after both creates")

	// A routine IdP sync of alice (a userName change, e.g. a rename) moves her
	// row; nothing about bob or the subject changed.
	rec = s.call(http.MethodPut, "/provider/scim/v2/Users/"+aliceID, user(subject, "alice.smith@example.test", "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("routine SCIM update of alice = %d %s", rec.Code, rec.Body.String())
	}
	resolve("after a routine SCIM update of alice")
	signIn("after a routine SCIM update of alice")
}

// A single userName match must not become an IdP subject match. SCIM URLs
// likewise name the canonical user id, never an externalId or userName.
func TestCR358SignedSubjectAndSCIMByIDUseDeclaredColumns(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	s := newA221SCIM(t, NewPGAccessStore(st), NewEventMutationSink(log, NewAuthorityProjection(st)), time.Now)
	const signedSubject = "cr358-subject-only-in-username"
	rec := s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+`"],"externalId":"different-subject","userName":"`+signedSubject+`","roles":[{"value":"operator"}],"active":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator = %d %s", rec.Code, rec.Body.String())
	}
	if operator, ok := s.signIn(signedSubject); ok {
		t.Errorf("signed subject matched only another operator's userName and authenticated as %s", operator.ID)
	}
	for _, alias := range []string{"different-subject", signedSubject} {
		if rec := s.call(http.MethodGet, "/provider/scim/v2/Users/"+alias, ""); rec.Code != http.StatusNotFound {
			t.Errorf("SCIM by-id accepted %q as a canonical id: HTTP %d %s", alias, rec.Code, rec.Body.String())
		}
	}
}

// POST without externalId must create a new operator or refuse a collision;
// it must not update someone whose externalId equals the new userName.
func TestCR358SCIMCreateRefusesCrossColumnTakeover(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	access := NewPGAccessStore(st)
	s := newA221SCIM(t, access, NewEventMutationSink(log, NewAuthorityProjection(st)), time.Now)
	const aliceSubject = "cr358-alice-subject"
	rec := s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+`"],"externalId":"`+aliceSubject+`","userName":"alice@example.test","roles":[{"value":"admin"}],"active":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create Alice = %d %s", rec.Code, rec.Body.String())
	}
	rec = s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+`"],"userName":"`+aliceSubject+`","roles":[{"value":"operator"}],"active":true}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("SCIM POST whose userName equals Alice's externalId = %d %s, want 409", rec.Code, rec.Body.String())
	}
	identity, err := access.ResolveOperator(ctx, aliceSubject)
	if err != nil || identity.UserName != "alice@example.test" || identity.Role != OperatorAdmin {
		t.Fatalf("Alice's identity changed after a colliding POST: userName=%q role=%q err=%v", identity.UserName, identity.Role, err)
	}
	rec = s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+`"],"externalId":"cr358-bob-subject","userName":"bob@example.test","roles":[{"value":"operator"}],"active":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create Bob = %d %s", rec.Code, rec.Body.String())
	}
	var bob struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bob); err != nil || bob.ID == "" {
		t.Fatalf("decode Bob id: %v", err)
	}
	rec = s.call(http.MethodPut, "/provider/scim/v2/Users/"+bob.ID, `{"schemas":["`+scim.SchemaUser+`"],"externalId":"alice@example.test","userName":"bob@example.test","roles":[{"value":"operator"}],"active":true}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("SCIM PUT whose externalId equals Alice's userName = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if identity, err := access.ResolveOperator(ctx, bob.ID); err != nil || identity.ExternalID != "cr358-bob-subject" {
		t.Fatalf("Bob's externalId changed after a colliding PUT: externalId=%q err=%v", identity.ExternalID, err)
	}
}

// Old event streams can already contain a cross-column collision. Their
// projected rows must refuse lookup even after new SCIM writes are fenced.
func TestCR358HistoricalAmbiguousLookupFailsClosed(t *testing.T) {
	st, _, sink := authorityReplayFixture(t)
	now := time.Now().UTC()
	const subject = "cr358-historical-subject"
	for _, identity := range []OperatorIdentity{
		{ID: "cr358-historical-alice", ExternalID: subject, UserName: "alice@example.test",
			Role: OperatorAdmin, Active: true, Source: "scim:historical", CreatedAt: now, UpdatedAt: now},
		{ID: "cr358-historical-bob", ExternalID: "bob-subject", UserName: subject,
			Role: OperatorOperator, Active: true, Source: "scim:historical", CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := sink.Append(t.Context(), "historical:"+identity.ID, EventOperatorUpserted, providerAuthorityTenant,
			AuthorityEvent{Operator: &identity, EffectiveAt: now}); err != nil {
			t.Fatalf("project historical operator %q: %v", identity.ID, err)
		}
	}
	access := NewPGAccessStore(st)
	if got, err := access.ResolveOperator(t.Context(), subject); err == nil {
		t.Fatalf("ambiguous historical subject resolved to %q instead of failing closed", got.ID)
	}
	if got, err := access.ResolveOperatorByExternalID(t.Context(), subject); err == nil {
		t.Fatalf("signed subject bound to historical collision as %q instead of failing closed", got.ID)
	}
}
