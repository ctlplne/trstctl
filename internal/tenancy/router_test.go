package tenancy

import (
	"context"
	"errors"
	"testing"
)

type fakeRouter struct {
	targets map[string]Targets
	err     error
	calls   int
}

func (f *fakeRouter) TargetsFor(_ context.Context, tenantID string) (Targets, error) {
	f.calls++
	if f.err != nil {
		return Targets{}, f.err
	}
	return f.targets[tenantID], nil
}

func (f *fakeRouter) JetStreamSubjectLanes(context.Context) ([]string, error) {
	return nil, f.err
}

func TestTenancyDefaultRouterIsPooled(t *testing.T) {
	SetRouter(nil)

	if got, err := PostgresSchema(context.Background(), "tenant-a"); err != nil || got != "" {
		t.Fatalf("default postgres schema = %q err=%v, want pooled", got, err)
	}
	if got, err := EventSubject(context.Background(), "tenant-a", "events", "certificate.recorded"); err != nil || got != "events.certificate.recorded" {
		t.Fatalf("default event subject = %q err=%v", got, err)
	}
	if got, err := ObjectPrefix(context.Background(), "tenant-a"); err != nil || got != "tenant/tenant-a/" {
		t.Fatalf("default object prefix = %q err=%v", got, err)
	}
}

func TestTenancyRouterSetterHooksFire(t *testing.T) {
	SetRouter(nil)
	t.Cleanup(func() { SetRouter(nil) })

	router := &fakeRouter{targets: map[string]Targets{
		"tenant-a": {
			Model:                IsolationSiloed,
			PostgresSchema:       "tenant_a",
			JetStreamSubjectLane: "lane-a",
			ObjectKeyPrefix:      "isolated/tenant-a/",
		},
	}}
	SetRouter(router)

	if got, err := PostgresSchema(context.Background(), "tenant-a"); err != nil || got != "tenant_a" {
		t.Fatalf("routed postgres schema = %q err=%v", got, err)
	}
	if got, err := EventSubject(context.Background(), "tenant-a", "events", "certificate.recorded"); err != nil || got != "events.lane-a.certificate.recorded" {
		t.Fatalf("routed event subject = %q err=%v", got, err)
	}
	if got, err := ObjectPrefix(context.Background(), "tenant-a"); err != nil || got != "isolated/tenant-a/" {
		t.Fatalf("routed object prefix = %q err=%v", got, err)
	}
	if router.calls == 0 {
		t.Fatal("router was not consulted")
	}
}

func TestTenancyRouterFailsClosed(t *testing.T) {
	SetRouter(nil)
	t.Cleanup(func() { SetRouter(nil) })

	SetRouter(&fakeRouter{err: errors.New("registry unavailable")})
	if _, err := PostgresSchema(context.Background(), "tenant-a"); err == nil {
		t.Fatal("routing errors must fail closed")
	}

	SetRouter(&fakeRouter{targets: map[string]Targets{
		"bad-schema": {PostgresSchema: `public";DROP`},
		"bad-lane":   {JetStreamSubjectLane: "lane.*"},
	}})
	if _, err := PostgresSchema(context.Background(), "bad-schema"); err == nil {
		t.Fatal("malformed postgres schema was accepted")
	}
	if _, err := EventSubject(context.Background(), "bad-lane", "events", "certificate.recorded"); err == nil {
		t.Fatal("malformed JetStream subject lane was accepted")
	}
}
