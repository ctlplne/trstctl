package store_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func seedAgentAt(t *testing.T, s *store.Store, id, name string, createdAt time.Time) {
	t.Helper()
	if _, err := s.Pool().Exec(context.Background(),
		`INSERT INTO agents (id, tenant_id, name, status, version, created_at)
		 VALUES ($1, $2, $3, 'online', 'test', $4)`,
		id, tenantA, name, createdAt); err != nil {
		t.Fatalf("seed agent %s: %v", id, err)
	}
}

func agentID(n int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
}

func TestListAgentsPagePaginatesByCreatedAtID(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		id int
		at time.Time
	}{
		{3, base},
		{1, base},
		{2, base},
		{4, base.Add(time.Minute)},
		{6, base.Add(2 * time.Minute)},
		{5, base.Add(2 * time.Minute)},
		{7, base.Add(3 * time.Minute)},
	} {
		seedAgentAt(t, s, agentID(row.id), fmt.Sprintf("edge-%d", row.id), row.at)
	}

	var (
		got            []string
		afterCreatedAt *time.Time
		afterID        = store.ZeroUUID
	)
	for page := 0; page < 10; page++ {
		agents, err := s.ListAgentsPage(ctx, tenantA, afterCreatedAt, afterID, 3)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(agents) == 0 {
			break
		}
		for _, ag := range agents {
			got = append(got, ag.ID)
		}
		last := agents[len(agents)-1]
		nextCreatedAt := last.CreatedAt
		afterCreatedAt = &nextCreatedAt
		afterID = last.ID
	}

	want := []string{agentID(1), agentID(2), agentID(3), agentID(4), agentID(5), agentID(6), agentID(7)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent pages = %v, want %v", got, want)
	}
}

func TestListAgentsPageStableAfterInsertBetweenPages(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		seedAgentAt(t, s, agentID(i), fmt.Sprintf("edge-%d", i), base.Add(time.Duration(i)*time.Minute))
	}

	first, err := s.ListAgentsPage(ctx, tenantA, nil, store.ZeroUUID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("first page len = %d, want 2", len(first))
	}
	cursorCreatedAt := first[len(first)-1].CreatedAt
	cursorID := first[len(first)-1].ID

	// Insert one row before the cursor and one row after it. The next page must not
	// duplicate or rewind to the earlier insert; the later insert appears in order.
	seedAgentAt(t, s, agentID(90), "too-old", base.Add(-time.Minute))
	seedAgentAt(t, s, agentID(91), "between-pages", base.Add(2500*time.Millisecond+2*time.Minute))

	second, err := s.ListAgentsPage(ctx, tenantA, &cursorCreatedAt, cursorID, 10)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ag := range second {
		names = append(names, ag.Name)
		for _, seen := range first {
			if ag.ID == seen.ID {
				t.Fatalf("agent %s repeated across pages after concurrent insert", ag.ID)
			}
		}
	}
	if strings.Contains(strings.Join(names, ","), "too-old") {
		t.Fatalf("next page rewound behind cursor after older insert: %v", names)
	}
	if !strings.Contains(strings.Join(names, ","), "between-pages") {
		t.Fatalf("next page skipped newer insert after cursor: %v", names)
	}
}

func TestListAgentsPageBoundsLargeTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 250; i++ {
		seedAgentAt(t, s, agentID(i), fmt.Sprintf("edge-%d", i), base.Add(time.Duration(i)*time.Second))
	}
	agents, err := s.ListAgentsPage(ctx, tenantA, nil, store.ZeroUUID, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 25 {
		t.Fatalf("large-tenant page len = %d, want exactly bounded page size 25", len(agents))
	}
}
