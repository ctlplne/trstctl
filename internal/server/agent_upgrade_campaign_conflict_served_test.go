// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// DP2-048: a second campaign open while one is active is refused with a 409
// problem that names the active campaign, and it is refused BEFORE anything
// reaches the event log, even when the opens arrive at the same instant. On the
// starting candidate the check ran outside any lock and before the append, so
// concurrent opens all appended events whose projection could never apply; the
// request answered 500, the durable tail wedged on the first loser, and /readyz
// went to 503.
func TestServedSecondCampaignOpenIsRefusedBeforeAppend(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	ctx := t.Context()

	countOpened := func() int {
		n := 0
		if err := h.log.Replay(ctx, 0, func(ev events.Event) error {
			if ev.TenantID == h.tenant && ev.Type == projections.EventAgentUpgradeCampaignOpened {
				n++
			}
			return nil
		}); err != nil {
			t.Fatalf("replay event log: %v", err)
		}
		return n
	}

	// Twelve opens at once from one start barrier: exactly one may win.
	const opens = 12
	statuses := make([]int, opens)
	bodies := make([]string, opens)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < opens; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			st, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
				"campaign-burst-"+strconv.Itoa(i), map[string]any{"target_version": "2.0.0"})
			statuses[i], bodies[i] = st, string(body)
		}(i)
	}
	close(start)
	wg.Wait()
	created, conflicts := 0, 0
	for i, st := range statuses {
		switch st {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
			if !strings.Contains(bodies[i], "already active") {
				t.Fatalf("conflict problem must name the active campaign rule: %s", bodies[i])
			}
		default:
			t.Fatalf("open %d: status %d (want 201 for one and 409 for the rest): %s", i, st, bodies[i])
		}
	}
	if created != 1 || conflicts != opens-1 {
		t.Fatalf("created=%d conflicts=%d, want exactly one winner and %d refusals", created, conflicts, opens-1)
	}
	if n := countOpened(); n != 1 {
		t.Fatalf("campaign-opened events in the log = %d, want exactly one: a refused open must not append", n)
	}

	// A later open while the campaign is still active: 409 naming the active id,
	// and still nothing appended.
	active := readCampaign(t, h, tok)
	st, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-later", map[string]any{"target_version": "3.0.0"})
	if st != http.StatusConflict || !strings.Contains(string(body), active.ID) {
		t.Fatalf("later open: %d %s (want 409 naming %s)", st, body, active.ID)
	}
	// Identical retry of that refused request replays the same refusal.
	if st2, body2 := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-later", map[string]any{"target_version": "3.0.0"}); st2 != http.StatusConflict || string(body2) != string(body) {
		t.Fatalf("identical retry of the refused open: %d %s (want the replayed 409)", st2, body2)
	}
	if n := countOpened(); n != 1 {
		t.Fatalf("campaign-opened events after refusals = %d, want still one", n)
	}
	// The winner is the one active campaign and the read model is intact: with
	// exactly one opened event in the log there is nothing a durable tail could
	// fail to apply.
	if again := readCampaign(t, h, tok); again.ID != active.ID || !again.Active {
		t.Fatalf("active campaign after refusals = %+v, want %s still active", again, active.ID)
	}
}
