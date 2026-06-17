package projections_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func storeProfile(t *testing.T, s *store.Store, tenant, name string, p profile.CertificateProfile) store.ProfileRecord {
	t.Helper()
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.CreateProfileVersion(context.Background(), store.ProfileRecord{
		TenantID: tenant, Name: name, Spec: spec, CreatedBy: "ra@test",
	})
	if err != nil {
		t.Fatalf("CreateProfileVersion: %v", err)
	}
	return rec
}

// TestProfileVersioningAndTenantIsolation: a new edit is a new version, the prior
// version stays resolvable, the active one advances, and a cross-tenant read is
// denied (AN-1).
func TestProfileVersioningAndTenantIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "B"}); err != nil {
		t.Fatal(err)
	}

	v1 := storeProfile(t, s, tenantA, "web", profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(24 * time.Hour)})
	v2 := storeProfile(t, s, tenantA, "web", profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(48 * time.Hour)})
	if v1.Version != 1 || v2.Version != 2 {
		t.Fatalf("versions = %d, %d; want 1, 2", v1.Version, v2.Version)
	}

	active, err := s.GetActiveProfile(ctx, tenantA, "web")
	if err != nil || active.Version != 2 {
		t.Fatalf("active profile = v%d (%v); want v2", active.Version, err)
	}
	// The prior version remains resolvable.
	if prior, err := s.GetProfileVersion(ctx, tenantA, "web", 1); err != nil || prior.Version != 1 {
		t.Fatalf("prior version not resolvable: v%d (%v)", prior.Version, err)
	}
	// Cross-tenant isolation: tenant B sees no "web" profile.
	if _, err := s.GetActiveProfile(ctx, tenantB, "web"); !store.IsNotFound(err) {
		t.Errorf("cross-tenant profile read should be not-found, got %v", err)
	}
}

// TestProfileChangeEmitsAuditEventWithActor: a profile create/update is recorded
// as an AN-2 audit event attributed to the actor (S8.1 acceptance — every profile
// change appears in the audit log with an actor).
func TestProfileChangeEmitsAuditEventWithActor(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	if err := s.UpsertTenant(context.Background(), store.Tenant{TenantID: tenantA, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "ra@a", Roles: []string{"ra-officer"}})

	spec, _ := json.Marshal(profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(24 * time.Hour)})
	if _, err := orch.CreateProfile(ctx, tenantA, "web", spec); err != nil {
		t.Fatalf("CreateProfile v1: %v", err)
	}
	if _, err := orch.CreateProfile(ctx, tenantA, "web", spec); err != nil {
		t.Fatalf("CreateProfile v2: %v", err)
	}

	var created, updated int
	var actor bool
	if err := log.Replay(context.Background(), 0, func(ev events.Event) error {
		switch ev.Type {
		case projections.EventProfileCreated:
			created++
		case projections.EventProfileUpdated:
			updated++
		default:
			return nil
		}
		if ev.SchemaVersion != projections.ProfileEventSchemaVersion {
			t.Errorf("%s schema version = %d, want %d", ev.Type, ev.SchemaVersion, projections.ProfileEventSchemaVersion)
		}
		var payload projections.ProfileVersioned
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			t.Errorf("decode %s payload: %v", ev.Type, err)
			return nil
		}
		if payload.ID == "" || payload.Name != "web" || payload.Spec == nil || !payload.Active || payload.CreatedBy != "ra@a" {
			t.Errorf("profile event payload = %+v, want full active profile row with actor", payload)
		}
		if ev.Actor != nil && ev.Actor.Subject == "ra@a" {
			actor = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if created != 1 || updated != 1 {
		t.Errorf("want 1 created + 1 updated event, got %d/%d", created, updated)
	}
	if !actor {
		t.Error("profile change events must carry the actor")
	}
}

// TestProfileVersionsSurviveReadModelRebuild is SPINE-004 acceptance: profile
// state must not be PostgreSQL-only. Two served edits append full-spec events; after
// the certificate_profiles read table is erased, a log rebuild restores both
// versions and the exact active version.
func TestProfileVersionsSurviveReadModelRebuild(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "ra@a", Roles: []string{"ra-officer"}})
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	spec1 := mustProfileSpec(t, profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(24 * time.Hour)})
	spec2 := mustProfileSpec(t, profile.CertificateProfile{Name: "web", MaxValidity: profile.Duration(48 * time.Hour)})
	v1, err := orch.CreateProfile(ctx, tenantA, "web", spec1)
	if err != nil {
		t.Fatalf("CreateProfile v1: %v", err)
	}
	v2, err := orch.CreateProfile(ctx, tenantA, "web", spec2)
	if err != nil {
		t.Fatalf("CreateProfile v2: %v", err)
	}
	if v1.Version != 1 || v2.Version != 2 {
		t.Fatalf("versions = %d, %d; want 1, 2", v1.Version, v2.Version)
	}

	if _, err := s.SystemPool().Exec(context.Background(), `TRUNCATE certificate_profiles`); err != nil {
		t.Fatalf("truncate certificate_profiles: %v", err)
	}
	if _, err := s.GetActiveProfile(context.Background(), tenantA, "web"); !store.IsNotFound(err) {
		t.Fatalf("active profile after truncate = %v, want not found", err)
	}

	if err := projections.New(s).Rebuild(context.Background(), log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	got1, err := s.GetProfileVersion(context.Background(), tenantA, "web", 1)
	if err != nil {
		t.Fatalf("GetProfileVersion v1 after rebuild: %v", err)
	}
	got2, err := s.GetProfileVersion(context.Background(), tenantA, "web", 2)
	if err != nil {
		t.Fatalf("GetProfileVersion v2 after rebuild: %v", err)
	}
	active, err := s.GetActiveProfile(context.Background(), tenantA, "web")
	if err != nil {
		t.Fatalf("GetActiveProfile after rebuild: %v", err)
	}

	if got1.ID != v1.ID || got1.Active {
		t.Errorf("rebuilt v1 = id %s active %v, want id %s inactive", got1.ID, got1.Active, v1.ID)
	}
	if got2.ID != v2.ID || !got2.Active || active.ID != v2.ID {
		t.Errorf("rebuilt v2/active = v2(%s active %v) active(%s), want v2 %s active", got2.ID, got2.Active, active.ID, v2.ID)
	}
	if got1.CreatedBy != "ra@a" || got2.CreatedBy != "ra@a" {
		t.Errorf("rebuilt created_by = %q/%q, want actor ra@a", got1.CreatedBy, got2.CreatedBy)
	}
	assertJSONEqual(t, got1.Spec, spec1)
	assertJSONEqual(t, got2.Spec, spec2)
}

func mustProfileSpec(t *testing.T, p profile.CertificateProfile) json.RawMessage {
	t.Helper()
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func assertJSONEqual(t *testing.T, got, want json.RawMessage) {
	t.Helper()
	var gotAny, wantAny any
	if err := json.Unmarshal(got, &gotAny); err != nil {
		t.Fatalf("decode got JSON %s: %v", string(got), err)
	}
	if err := json.Unmarshal(want, &wantAny); err != nil {
		t.Fatalf("decode want JSON %s: %v", string(want), err)
	}
	if !reflect.DeepEqual(gotAny, wantAny) {
		t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", string(got), string(want))
	}
}

// TestProfileGatedIssuanceAndAudit is the core S8.1 acceptance: a compliant
// issuance succeeds and a violating one is rejected with a clear reason, and every
// gated decision is in the audit log with an actor.
func TestProfileGatedIssuanceAndAudit(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	if err := s.UpsertTenant(context.Background(), store.Tenant{TenantID: tenantA, Name: "A"}); err != nil {
		t.Fatal(err)
	}

	builtin, err := ca.NewBuiltin("trstctl Built-in CA")
	if err != nil {
		t.Fatal(err)
	}
	svc := ca.NewIssuanceService(builtin, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s, ca.WithAuditLog(log))
	csr := issuanceCSR(t) // an ECDSA P-256 CSR

	// The active profile: ECDSA only, 48h validity ceiling, api protocol.
	storeProfile(t, s, tenantA, "web", profile.CertificateProfile{
		Name: "web", AllowedKeyAlgorithms: []string{"ECDSA"}, MinECDSABits: 256,
		MaxValidity: profile.Duration(48 * time.Hour), AllowedProtocols: []string{"api"},
	})
	// Attribute decisions to a registration-authority actor.
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "ra@a", Roles: []string{"ra-officer"}})

	// Compliant: ECDSA, 24h, api → succeeds.
	if _, err := svc.Issue(ctx, ca.IssueRequest{
		TenantID: tenantA, CSR: csr, TTL: 24 * time.Hour, ProfileName: "web", Protocol: "api",
	}, "ok-1"); err != nil {
		t.Fatalf("compliant issuance should succeed: %v", err)
	}

	// Violating: 365-day validity exceeds the profile ceiling → rejected with reason.
	_, err = svc.Issue(ctx, ca.IssueRequest{
		TenantID: tenantA, CSR: csr, TTL: 365 * 24 * time.Hour, ProfileName: "web", Protocol: "api",
	}, "bad-1")
	if err == nil || !strings.Contains(err.Error(), "caps validity") {
		t.Fatalf("over-long validity should be rejected with a clear reason, got %v", err)
	}

	// Violating: a profile that doesn't bind / wrong protocol → rejected.
	_, err = svc.Issue(ctx, ca.IssueRequest{
		TenantID: tenantA, CSR: csr, TTL: 24 * time.Hour, ProfileName: "web", Protocol: "scep",
	}, "bad-2")
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("disallowed protocol should be rejected, got %v", err)
	}

	// The audit log carries a profile decision for each, with the actor.
	var allow, deny int
	var sawActor bool
	if err := log.Replay(context.Background(), 0, func(ev events.Event) error {
		if ev.Type != "issuance.profile_evaluated" {
			return nil
		}
		if ev.Actor != nil && ev.Actor.Subject == "ra@a" {
			sawActor = true
		}
		var d struct {
			Decision string `json:"decision"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		switch d.Decision {
		case "allow":
			allow++
		case "deny":
			deny++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if allow < 1 || deny < 2 {
		t.Errorf("audit decisions: allow=%d deny=%d; want >=1 allow and >=2 deny", allow, deny)
	}
	if !sawActor {
		t.Error("profile decision events must carry the actor (who decided)")
	}
}
