package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func newAgentAPIServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)), api.WithInsecureHeaderResolver())
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, s
}

func seedAPIAgentAt(t *testing.T, s *store.Store, n int, createdAt time.Time) string {
	t.Helper()
	id := fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
	if _, err := s.Pool().Exec(context.Background(),
		`INSERT INTO agents (id, tenant_id, name, status, version, created_at)
		 VALUES ($1, $2, $3, 'online', 'test', $4)`,
		id, tenantA, fmt.Sprintf("edge-%d", n), createdAt); err != nil {
		t.Fatalf("seed api agent %d: %v", n, err)
	}
	return id
}

type agentListJSON struct {
	Agents     []struct{ ID, Name string } `json:"agents"`
	NextCursor string                      `json:"next_cursor"`
}

func getAgentsPage(t *testing.T, srv *httptest.Server, query string) (int, agentListJSON, string) {
	t.Helper()
	code, _, body := do(t, srv, http.MethodGet, "/api/v1/agents"+query, reqOpts{tenant: tenantA})
	var out agentListJSON
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode agents page %s: %v", body, err)
		}
	}
	return code, out, string(body)
}

func TestAgentInventoryAPIPaginatesDefaultMaxAndCursor(t *testing.T) {
	srv, s := newAgentAPIServer(t)
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 105; i++ {
		seedAPIAgentAt(t, s, i, base.Add(time.Duration(i)*time.Second))
	}

	code, first, body := getAgentsPage(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("default page status = %d body=%s", code, body)
	}
	if len(first.Agents) != 20 || first.NextCursor == "" {
		t.Fatalf("default page len=%d next=%q, want 20 and next cursor", len(first.Agents), first.NextCursor)
	}

	code, maxPage, body := getAgentsPage(t, srv, "?limit=100")
	if code != http.StatusOK {
		t.Fatalf("max page status = %d body=%s", code, body)
	}
	if len(maxPage.Agents) != 100 || maxPage.NextCursor == "" {
		t.Fatalf("max page len=%d next=%q, want 100 and next cursor", len(maxPage.Agents), maxPage.NextCursor)
	}

	code, _, body = getAgentsPage(t, srv, "?limit=101")
	if code != http.StatusBadRequest || !strings.Contains(body, "limit must be an integer between 1 and 100") {
		t.Fatalf("limit=101 status=%d body=%s, want 400 limit error", code, body)
	}

	code, second, body := getAgentsPage(t, srv, "?limit=20&cursor="+first.NextCursor)
	if code != http.StatusOK {
		t.Fatalf("second page status = %d body=%s", code, body)
	}
	if len(second.Agents) != 20 {
		t.Fatalf("second page len = %d, want 20", len(second.Agents))
	}
	seen := map[string]bool{}
	for _, ag := range first.Agents {
		seen[ag.ID] = true
	}
	for _, ag := range second.Agents {
		if seen[ag.ID] {
			t.Fatalf("agent %s repeated across API pages", ag.ID)
		}
	}

	code, _, body = getAgentsPage(t, srv, "?cursor=not-base64")
	if code != http.StatusBadRequest || !strings.Contains(body, "invalid cursor") {
		t.Fatalf("invalid cursor status=%d body=%s, want 400 invalid cursor", code, body)
	}
}
