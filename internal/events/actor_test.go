package events_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

const actorTenant = "33333333-3333-3333-3333-333333333333"

// TestAppendRecordsActorFromContext is the R2.1 attribution acceptance at the
// event-log layer: the authenticated caller's identity, carried in the request
// context, is recorded on every appended event (the "who" of who-did-what) and
// survives a replay.
func TestAppendRecordsActorFromContext(t *testing.T) {
	log := openEmbedded(t)
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "alice@example.com", Roles: []string{"admin"}})

	ev, err := log.Append(ctx, events.Event{Type: "owner.created", TenantID: actorTenant, Data: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if ev.Actor == nil || ev.Actor.Subject != "alice@example.com" {
		t.Fatalf("appended event actor = %+v, want subject alice@example.com", ev.Actor)
	}

	got := collect(t, log, 0)
	if len(got) != 1 {
		t.Fatalf("replayed %d events, want 1", len(got))
	}
	if got[0].Actor == nil {
		t.Fatal("replayed event has no actor; attribution was not persisted")
	}
	if got[0].Actor.Subject != "alice@example.com" || len(got[0].Actor.Roles) != 1 || got[0].Actor.Roles[0] != "admin" {
		t.Errorf("replayed actor = %+v, want {alice@example.com [admin]}", got[0].Actor)
	}
}

// TestAppendWithoutActorIsUnattributed: a background/system append (no actor in
// context) is honestly recorded with no actor rather than a fabricated one.
func TestAppendWithoutActorIsUnattributed(t *testing.T) {
	log := openEmbedded(t)
	ev, err := log.Append(context.Background(), events.Event{Type: "certificate.recorded", TenantID: actorTenant, Data: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if ev.Actor != nil {
		t.Errorf("unattributed append got actor %+v, want nil", ev.Actor)
	}
}

// TestActorFromContextRoundTrip exercises the context carrier directly.
func TestActorFromContextRoundTrip(t *testing.T) {
	if _, ok := events.ActorFromContext(context.Background()); ok {
		t.Error("empty context reported an actor")
	}
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "svc", Roles: []string{"operator", "auditor"}})
	a, ok := events.ActorFromContext(ctx)
	if !ok || a.Subject != "svc" || len(a.Roles) != 2 {
		t.Fatalf("ActorFromContext = %+v, %v", a, ok)
	}
}
