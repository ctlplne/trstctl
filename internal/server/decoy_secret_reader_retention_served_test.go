// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/outboxgc"
)

// Q6-L1: a decoy secret alerts once per reader for good. The decoy keeps its
// readers, so after the delivered alert leaves the outbox (the sweep reclaims
// a delivered row a day after delivery) the same reader reading again raises
// nothing, while a reader new to the decoy still alerts once. The decoy counts
// its readers and their reads, and a rebuild reaches the same counts.
func TestServedDecoySecretAlertsOncePerReaderPastOutboxRetentionQ6L1(t *testing.T) {
	receiver := &approvalNotificationProbe{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.NotificationChannels = append(d.NotificationChannels, receiver)
	})
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "q6l1-planter", "secrets:read", "secrets:write")
	thief := seedScopedTokenSubject(t, h.store, h.tenant, "q6l1-runner", "secrets:read")
	insider := seedScopedTokenSubject(t, h.store, h.tenant, "q6l1-contractor", "secrets:read")
	latecomer := seedScopedTokenSubject(t, h.store, h.tenant, "q6l1-latecomer", "secrets:read")
	const bait = "q6l1/payments/db-password"
	if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", planter, "q6l1-bait",
		map[string]any{"name": bait, "value": "pg-q6l1-decoy-shaped-like-a-password"}); status != http.StatusCreated {
		t.Fatalf("store the bait: HTTP %d %s", status, out)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", planter, "q6l1-register",
		map[string]any{"secret_name": bait, "name": "q6l1 bait", "placement": "payments repo .env.example"})
	type decoyView struct {
		ID         string     `json:"id"`
		State      string     `json:"state"`
		Readers    int64      `json:"readers"`
		Reads      int64      `json:"reads"`
		LastReadAt *time.Time `json:"last_read_at"`
	}
	var decoy decoyView
	if status != http.StatusCreated || json.Unmarshal(body, &decoy) != nil || decoy.ID == "" {
		t.Fatalf("register the decoy: HTTP %d %s", status, body)
	}
	alertKeys := "honeytoken.secret_read:" + decoy.ID + ":%"
	alerts := func() []string {
		t.Helper()
		rows, err := h.store.SystemPool().Query(t.Context(),
			`SELECT convert_from(payload, 'UTF8')::jsonb->>'detail' FROM outbox
			  WHERE tenant_id = $1 AND destination = 'notification.honeytoken' AND idempotency_key LIKE $2 ORDER BY id`,
			h.tenant, alertKeys)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var detail string
			if err := rows.Scan(&detail); err != nil {
				t.Fatal(err)
			}
			out = append(out, detail)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	read := func(token string) {
		t.Helper()
		if status, out := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+bait, token, nil); status != http.StatusOK {
			t.Fatalf("read the bait: HTTP %d %s", status, out)
		}
	}
	view := func() decoyView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/secrets/"+decoy.ID, planter, nil)
		var v decoyView
		if status != http.StatusOK || json.Unmarshal(body, &v) != nil {
			t.Fatalf("the decoy: HTTP %d %s", status, body)
		}
		return v
	}

	read(thief)
	read(thief)
	read(insider)
	if got := alerts(); len(got) != 2 || !strings.Contains(got[0], "read by q6l1-runner") || !strings.Contains(got[1], "read by q6l1-contractor") {
		t.Fatalf("alerts after two readers = %q, want one for each", got)
	}
	// The counts are checked without stopping, so a missing count does not
	// hide whether the reader is alerted again below.
	if v := view(); v.State != "triggered" || v.Readers != 2 || v.Reads != 3 || v.LastReadAt == nil {
		t.Errorf("the decoy after two readers' three reads = %+v", v)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := alerts(); len(got) != 2 {
		t.Fatalf("a rebuild changed the alerts to %q", got)
	}
	if v := view(); v.Readers != 2 || v.Reads != 3 {
		t.Errorf("after a rebuild the decoy = %+v", v)
	}

	// The thief's alert is delivered and, a day later, reclaimed by the
	// outbox sweep.
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if delivered, _ := receiver.snapshot(); delivered < 2 {
		t.Fatalf("the receiver got %d alerts, want both readers'", delivered)
	}
	tag, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET delivered_at = now() - interval '25 hours'
		  WHERE tenant_id = $1 AND destination = 'notification.honeytoken' AND idempotency_key LIKE $2
		    AND status = 'delivered' AND convert_from(payload, 'UTF8')::jsonb->>'detail' LIKE '%read by q6l1-runner (%'`,
		h.tenant, alertKeys)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("the thief's alert was not delivered: %v (%d rows)", err, tag.RowsAffected())
	}
	if _, err := outboxgc.New(h.store, outboxgc.DefaultRetention).Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if got := alerts(); len(got) != 1 || !strings.Contains(got[0], "read by q6l1-contractor") {
		t.Fatalf("after the sweep the alerts = %q, want only the contractor's", got)
	}

	// The same reader reading again, past the alert's retention, raises
	// nothing; a reader new to the decoy alerts once.
	before := time.Now().UTC().Add(-time.Second)
	read(thief)
	if got := alerts(); len(got) != 1 {
		t.Fatalf("the thief reading again re-alerted: %q", got)
	}
	read(latecomer)
	read(latecomer)
	if got := alerts(); len(got) != 2 || !strings.Contains(got[1], "read by q6l1-latecomer") {
		t.Fatalf("a new reader's alerts = %q, want one", got)
	}
	if v := view(); v.Readers != 3 || v.Reads != 6 || v.LastReadAt == nil || v.LastReadAt.Before(before) {
		t.Errorf("the decoy after six reads by three readers = %+v", v)
	}
}
