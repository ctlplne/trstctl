// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"testing/quick"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func a261MatchingRule() (store.PAMAutoApprovalRule, pamAutoApprovalRequest) {
	r := store.PAMAutoApprovalRule{Enabled: true, AppliesTo: []string{"session"}, TargetTypes: []string{"postgres"}, TargetIDs: []string{"orders"}, Folders: []string{"production"}, RequesterRoles: []string{"oncall"}, WindowDays: []string{"mon"}, WindowStart: "09:00", WindowEnd: "17:00", TimeZone: "America/New_York", TicketPattern: `INC-[0-9]+`, MaxTTLSeconds: 120}
	q := pamAutoApprovalRequest{Kind: "session", TargetType: "postgres", TargetID: "orders", Folder: "production", Roles: []string{"oncall", "operator"}, Reason: "INC-261", TTLSeconds: 60, At: time.Date(2024, 11, 4, 14, 0, 0, 0, time.UTC)}
	return r, q
}

func TestAutoApprovalNeedsEveryCriterionA261(t *testing.T) {
	cases := []struct {
		name   string
		change func(*store.PAMAutoApprovalRule, *pamAutoApprovalRequest)
		want   bool
	}{
		{"all criteria", func(*store.PAMAutoApprovalRule, *pamAutoApprovalRequest) {}, true},
		{"disabled", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { r.Enabled = false }, false},
		{"kind", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Kind = "checkout" }, false},
		{"type", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TargetType = "mysql" }, false},
		{"target", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TargetID = "billing" }, false},
		{"folder", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Folder = "" }, false},
		{"role", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Roles = []string{"operator"} }, false},
		{"no roles", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Roles = nil }, false},
		{"ticket", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Reason = "no ticket" }, false},
		{"whole ticket", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.Reason = "ignore INC-261 later" }, false},
		{"alternation stays anchored", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) {
			r.TicketPattern = "^INC-[0-9]+|CHG-[0-9]+$"
			q.Reason = "ignore CHG-261"
		}, false},
		{"invalid regexp", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { r.TicketPattern = "[" }, false},
		{"maximum ttl", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TTLSeconds = 120 }, true},
		{"past ttl", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TTLSeconds = 121 }, false},
		{"zero ttl", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TTLSeconds = 0 }, false},
		{"negative ttl", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.TTLSeconds = -1 }, false},
		{"no scope", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) {
			r.TargetTypes = nil
			r.TargetIDs = nil
			r.Folders = nil
		}, false},
		{"before start", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.At = q.At.Add(-time.Nanosecond) }, false},
		{"end excluded", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.At = q.At.Add(8 * time.Hour) }, false},
		{"wrong day", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { q.At = q.At.Add(24 * time.Hour) }, false},
		{"unknown time zone", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) { r.TimeZone = "invalid/zone" }, false},
		{"DST uses local clock", func(r *store.PAMAutoApprovalRule, q *pamAutoApprovalRequest) {
			q.At = time.Date(2024, 7, 1, 13, 0, 0, 0, time.UTC)
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, q := a261MatchingRule()
			tc.change(&r, &q)
			facts, ok := pamAutoApprovalMatches(r, q)
			if ok != tc.want {
				t.Fatalf("matched=%v facts=%+v, want %v", ok, facts, tc.want)
			}
		})
	}
}

// Scope and requester-role restrictions are monotone: adding one cannot
// grant a request that the less restricted policy would have refused.
func TestAutoApprovalRestrictionsCannotAddAuthorityA261(t *testing.T) {
	property := func(targetMatches, roleMatches, kindMatches bool, seconds uint8) bool {
		r, q := a261MatchingRule()
		r.TargetIDs = nil
		r.Folders = nil
		r.RequesterRoles = nil
		r.WindowDays = nil
		r.WindowStart = ""
		r.TicketPattern = ""
		if !targetMatches {
			q.TargetID = "billing"
		}
		if !roleMatches {
			q.Roles = []string{"operator"}
		}
		if !kindMatches {
			q.TargetType = "mysql"
		}
		q.TTLSeconds = 1 + int(seconds)%120
		_, before := pamAutoApprovalMatches(r, q)
		r.TargetIDs = []string{"orders"}
		r.RequesterRoles = []string{"oncall"}
		_, after := pamAutoApprovalMatches(r, q)
		return !after || before
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func FuzzPAMAutoApprovalNeverWidensScope(f *testing.F) {
	f.Add("orders", "oncall", "INC-261", int64(60))
	f.Add("billing", "operator", "", int64(121))
	f.Fuzz(func(t *testing.T, target, role, reason string, ttl int64) {
		if len(target)+len(role)+len(reason) > 2048 || ttl < -86400 || ttl > 86400 {
			return
		}
		r, q := a261MatchingRule()
		q.TargetID = target
		q.Roles = []string{role}
		q.Reason = reason
		q.TTLSeconds = int(ttl)
		_, matched := pamAutoApprovalMatches(r, q)
		r.Enabled = false
		if _, ok := pamAutoApprovalMatches(r, q); ok {
			t.Fatal("disabled rule grants access")
		}
		r.Enabled = true
		q.Roles = nil
		if _, ok := pamAutoApprovalMatches(r, q); ok {
			t.Fatal("removing requester roles grants access")
		}
		q.Roles = []string{role}
		r.TargetIDs = nil
		r.Folders = nil
		r.TargetTypes = nil
		if _, ok := pamAutoApprovalMatches(r, q); ok {
			t.Fatal("unscoped rule grants access")
		}
		if matched && (target != "orders" || role != "oncall" || ttl < 1 || ttl > 120) {
			t.Fatal("a match exceeded its explicit target, role or lifetime scope")
		}
	})
}
