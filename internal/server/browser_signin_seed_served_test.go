// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSignInsAreSeededFromTheSessionStoreM1L4 is M1-L4's Done-when
// (served): usage that began at an upgrade is seeded with what trstctl
// already held — each active member's latest browser sign-in in the session
// store (sessions are keyed by the same tenant-bound subject reference). dana
// signed in 20 and 3 days before usage began: one seeded use at the later
// sign-in, source kind seeded (session_store), and the members list shows it
// with no network. erin never signed in: nothing. gus's sign-in was already
// recorded from a network: not seeded, his recorded sign-in stands. Seeding
// again records nothing.
func TestServedSignInsAreSeededFromTheSessionStoreM1L4(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	// Its own tenant: the seeded usage must not stay behind in the shared
	// served tenant, whose usage other tests rebuild and compare.
	const tenant = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e814"
	registerServedTenantID(t, h, tenant, "M1-L4 tenant")
	admin := seedScopedTokenSubject(t, h.store, tenant, "m1l4-admin", "*")
	for _, subject := range []string{"dana-m1l4", "erin-m1l4", "gus-m1l4"} {
		if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/members/"+subject, admin, "m1l4-member-"+subject,
			map[string]any{"display_name": subject, "roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
			t.Fatalf("member %s = %d %s", subject, code, body)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	session := func(subject string, created time.Time) {
		t.Helper()
		id := uuid.New()
		if err := h.store.CreateBrowserSession(ctx, store.BrowserSession{TenantID: tenant, SessionHash: hex.EncodeToString(append(id[:], id[:]...)),
			SubjectHash: privacy.SubjectRef(tenant, subject), CreatedAt: created, LastSeenAt: created, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	session("dana-m1l4", now.Add(-20*24*time.Hour))
	session("dana-m1l4", now.Add(-3*24*time.Hour))
	session("gus-m1l4", now.Add(-2*24*time.Hour))
	// gus's sign-in an hour ago was recorded from his network.
	recorded := now.Add(-time.Hour)
	if err := h.srv.orch.RecordCredentialUse(ctx, tenant, uuid.NewString(), projections.CredentialUsed{
		Kind: store.CredentialUsageBrowserSession, CredentialID: privacy.SubjectRef(tenant, "gus-m1l4"), Principal: "gus-m1l4",
		SourceKind: store.CredentialUsageSourceNetwork, Source: "198.51.100.0/24", Action: projections.CredentialActionSignIn,
		WindowStart: recorded.Truncate(time.Hour), UsedAt: recorded, Count: 1}); err != nil {
		t.Fatal(err)
	}

	seeded := func() []projections.CredentialUsed {
		t.Helper()
		var out []projections.CredentialUsed
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID != tenant || e.Type != projections.EventCredentialUsed {
				return nil
			}
			var pl projections.CredentialUsed
			if err := json.Unmarshal(e.Data, &pl); err != nil {
				return err
			}
			if pl.SourceKind == store.CredentialUsageSourceSeeded {
				out = append(out, pl)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if err := h.srv.SeedBrowserSignIns(ctx); err != nil {
		t.Fatal(err)
	}
	got := seeded()
	if len(got) != 1 || got[0].Principal != "dana-m1l4" || got[0].CredentialID != privacy.SubjectRef(tenant, "dana-m1l4") ||
		got[0].Source != store.CredentialUsageSeedSessionStore || !got[0].UsedAt.Equal(now.Add(-3*24*time.Hour)) ||
		got[0].Kind != store.CredentialUsageBrowserSession || got[0].Action != projections.CredentialActionSignIn {
		t.Fatalf("seeded %+v; want one use for dana at her latest stored sign-in", got)
	}

	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/members", admin, nil)
	var members struct {
		Items []struct {
			Subject           string     `json:"subject"`
			LastSignInAt      *time.Time `json:"last_sign_in_at"`
			LastSignInNetwork string     `json:"last_sign_in_network"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &members) != nil {
		t.Fatalf("members = %d %s", code, body)
	}
	for _, m := range members.Items {
		switch m.Subject {
		case "dana-m1l4":
			if m.LastSignInAt == nil || !m.LastSignInAt.Equal(now.Add(-3*24*time.Hour)) || m.LastSignInNetwork != "" {
				t.Fatalf("dana reads %v from %q; want her seeded sign-in with no network", m.LastSignInAt, m.LastSignInNetwork)
			}
		case "erin-m1l4":
			if m.LastSignInAt != nil {
				t.Fatalf("erin never signed in but reads %v", m.LastSignInAt)
			}
		case "gus-m1l4":
			if m.LastSignInAt == nil || !m.LastSignInAt.Equal(recorded) || m.LastSignInNetwork != "198.51.100.0/24" {
				t.Fatalf("gus reads %v from %q; want his recorded sign-in", m.LastSignInAt, m.LastSignInNetwork)
			}
		}
	}
	if !strings.Contains(string(body), "dana-m1l4") || !strings.Contains(string(body), "gus-m1l4") {
		t.Fatalf("members: %s", body)
	}

	if err := h.srv.SeedBrowserSignIns(ctx); err != nil {
		t.Fatal(err)
	}
	if again := seeded(); len(again) != 1 {
		t.Fatalf("seeding again recorded %d seeded uses, want still 1", len(again))
	}
	t.Logf("M1L4_OK seeded=%s at=%s", got[0].Principal, got[0].UsedAt.Format(time.RFC3339))
}
