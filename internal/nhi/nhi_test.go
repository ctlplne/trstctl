package nhi

import (
	"context"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

func TestIdentityLifecycle(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	m, _ := New(Config{TenantID: "t1", Graph: g, Audit: rec})
	ctx := context.Background()

	idt, err := m.Create(ctx, "svc-1", "team-payments", []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	if idt.State != StateActive {
		t.Errorf("created state = %q", idt.State)
	}
	if err := m.Scope(ctx, "svc-1", []string{"read", "write"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Rotate(ctx, "svc-1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Expire(ctx, "svc-1"); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get("svc-1")
	if got.State != StateRetired || got.Rotations != 1 || len(got.Scopes) != 2 {
		t.Errorf("after lifecycle: %+v", got)
	}
	// Lifecycle state is queryable in the graph.
	n, ok := g.Node(nodeID("svc-1"))
	if !ok || n.Attrs["state"] != string(StateRetired) {
		t.Errorf("graph node = %+v ok=%v, want state retired", n, ok)
	}
	// Every transition audited: created, scoped, rotated, expired.
	for _, ev := range []string{"nhi.created", "nhi.scoped", "nhi.rotated", "nhi.expired"} {
		if rec.Count(ev) != 1 {
			t.Errorf("%s audited %d times, want 1", ev, rec.Count(ev))
		}
	}
}

func TestRotateRequiresActive(t *testing.T) {
	m, _ := New(Config{TenantID: "t1"})
	ctx := context.Background()
	_, _ = m.Create(ctx, "svc", "owner", nil)
	if err := m.Disable(ctx, "svc"); err != nil {
		t.Fatal(err)
	}
	if err := m.Rotate(ctx, "svc"); err == nil {
		t.Error("rotated a disabled identity")
	}
}
