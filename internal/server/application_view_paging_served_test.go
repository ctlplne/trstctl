// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
)

// TestServedApplicationViewPagesEveryApprovalAndAlertA244L3 is A244-L3's
// Done-when (served): the application view read the identity's newest ten
// approvals, and its alerts only among the tenant's latest two hundred
// notifications, so an older approval or alert was out of reach. The view
// now names a cursor for each, and two routes continue them: approvals by
// keyset, alerts by a bounded scan of the tenant's notifications that says
// where it stopped. With twelve approvals, twelve recent alerts, 5,100 other
// notifications and one old alert before them, the view shows the newest ten
// of each with a cursor; the approvals' next page holds the other two and
// ends; the alerts' next pages hold the other two recent alerts (the scan
// stopping at its budget) and then the old alert, and end. Every alert is
// the identity's, none twice; a bad cursor is refused; another identity's
// pages are not found.
func TestServedApplicationViewPagesEveryApprovalAndAlertA244L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	// Its own tenant: it writes thousands of notifications.
	const tenant = "a2440003-44a3-4a44-8a44-0000a2440003"
	registerServedTenantID(t, h, tenant, "A244-L3 tenant")
	tok := seedScopedTokenSubject(t, h.store, tenant, "a244l3-reader", "owners:write", "identities:read", "identities:write")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", tok, "a244l3-owner", map[string]any{"kind": "workload", "name": "a244l3-app"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &owner) != nil {
		t.Fatalf("owner = %d %s", status, raw)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", tok, "a244l3-identity", map[string]any{"owner_id": owner.ID, "kind": "x509", "name": "a244l3.app.test"})
	var identity struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &identity) != nil {
		t.Fatalf("identity = %d %s", status, raw)
	}
	id := identity.ID

	// Twelve approval requests, a minute apart.
	if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO operation_approval_requests (tenant_id, id, intent_digest, resource_kind, resource_id,
		action, requester, required_approvals, status, created_at, expires_at, updated_at)
		SELECT $1, gen_random_uuid(), 'sha256:a244l3-' || g, 'identity', $2, 'issue', 'a244l3-requester', 1, 'pending',
			now() - make_interval(mins => 20 - g), now() + interval '1 day', now()
		FROM generate_series(1, 12) g`, tenant, id); err != nil {
		t.Fatal(err)
	}
	// One old alert, 5,100 notifications for another identity, then twelve
	// recent alerts: delivered, so no worker touches them.
	notify := func(identityID, key string, n int) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, delivered_at)
			SELECT $1::uuid, 'notification.webhook', convert_to(json_build_object('kind', 'renewal_failed', 'tenant_id', ($1::uuid)::text, 'identity_id', $2::text)::text, 'UTF8'),
				'a244l3-' || $3 || '-' || g, 'delivered', now()
			FROM generate_series(1, $4) g`, tenant, identityID, key, n); err != nil {
			t.Fatal(err)
		}
	}
	notify(id, "old", 1)
	notify(uuid.NewString(), "other", 5100)
	notify(id, "recent", 12)

	type approval struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	type alert struct {
		ID string `json:"id"`
	}
	get := func(path string, out any) int {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, path, tok, nil)
		if status == http.StatusOK {
			if err := json.Unmarshal(raw, out); err != nil {
				t.Fatalf("%s: %v %s", path, err, raw)
			}
		}
		return status
	}
	var view struct {
		Approvals           []approval `json:"approvals"`
		ApprovalsNextCursor string     `json:"approvals_next_cursor"`
		Alerts              []alert    `json:"alerts"`
		AlertsNextCursor    string     `json:"alerts_next_cursor"`
	}
	if status := get("/api/v1/identities/"+id+"/application", &view); status != http.StatusOK {
		t.Fatalf("view = %d", status)
	}
	if len(view.Approvals) != 10 || view.ApprovalsNextCursor == "" || len(view.Alerts) != 10 || view.AlertsNextCursor == "" {
		t.Fatalf("view = %d approvals (cursor %q), %d alerts (cursor %q); want ten of each with cursors",
			len(view.Approvals), view.ApprovalsNextCursor, len(view.Alerts), view.AlertsNextCursor)
	}
	if !slices.IsSortedFunc(view.Approvals, func(a, b approval) int { return b.CreatedAt.Compare(a.CreatedAt) }) {
		t.Fatalf("approvals are not newest first: %+v", view.Approvals)
	}

	// Approvals: the next page holds the other two, older, and ends.
	var approvals struct {
		Items      []approval `json:"items"`
		NextCursor string     `json:"next_cursor"`
	}
	if status := get("/api/v1/identities/"+id+"/application/approvals?cursor="+url.QueryEscape(view.ApprovalsNextCursor), &approvals); status != http.StatusOK ||
		len(approvals.Items) != 2 || approvals.NextCursor != "" || !approvals.Items[0].CreatedAt.Before(view.Approvals[9].CreatedAt) {
		t.Fatalf("approvals page = %d %+v", status, approvals)
	}

	// Alerts: the scan's budget, then the old alert.
	seen := map[string]bool{}
	for _, a := range view.Alerts {
		seen[a.ID] = true
	}
	var page struct {
		Items      []alert `json:"items"`
		NextCursor string  `json:"next_cursor"`
	}
	cursor, pages := view.AlertsNextCursor, 0
	var sizes []int
	for cursor != "" {
		page.Items, page.NextCursor = nil, ""
		if status := get("/api/v1/identities/"+id+"/application/alerts?cursor="+url.QueryEscape(cursor), &page); status != http.StatusOK {
			t.Fatalf("alerts page %d = %d", pages+1, status)
		}
		for _, a := range page.Items {
			if seen[a.ID] {
				t.Fatalf("alert %s listed twice", a.ID)
			}
			seen[a.ID] = true
		}
		sizes = append(sizes, len(page.Items))
		cursor = page.NextCursor
		if pages++; pages > 5 {
			t.Fatal("the alerts never end")
		}
	}
	if len(seen) != 13 || !slices.Equal(sizes, []int{2, 1}) {
		t.Fatalf("alerts read %d over pages of %v; want 13 (ten, two as the scan's budget ends, then the old one)", len(seen), sizes)
	}
	var rows int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND id = ANY($2::bigint[])
		AND convert_from(payload, 'UTF8')::jsonb->>'identity_id' = $3`, tenant, a244l3OutboxIDs(t, seen), id).Scan(&rows); err != nil || rows != 13 {
		t.Fatalf("%d of the listed alerts are the identity's (%v)", rows, err)
	}

	// A bad cursor is refused; another identity's pages are not found.
	for _, path := range []string{"/approvals?cursor=not-a-cursor", "/alerts?cursor=not-a-cursor"} {
		if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/application"+path, tok, nil); status != http.StatusBadRequest {
			t.Fatalf("%s = %d %s; want 400", path, status, raw)
		}
	}
	for _, path := range []string{"/approvals", "/alerts"} {
		if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+uuid.NewString()+"/application"+path, tok, nil); status != http.StatusNotFound {
			t.Fatalf("another identity's %s = %d %s; want 404", path, status, raw)
		}
	}
	t.Log("A244L3_OK")
}

// a244l3OutboxIDs are the listed alerts' outbox row IDs.
func a244l3OutboxIDs(t *testing.T, m map[string]bool) []int64 {
	t.Helper()
	out := make([]int64, 0, len(m))
	for k := range m {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			t.Fatalf("alert id %q: %v", k, err)
		}
		out = append(out, id)
	}
	return out
}
