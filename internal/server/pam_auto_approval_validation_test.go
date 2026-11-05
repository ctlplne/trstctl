// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/api"
)

// Reject invalid policy before consulting storage or emitting an event.
func TestAutoApprovalRuleRejectsInvalidCriteriaA261(t *testing.T) {
	cases := []struct {
		name   string
		change func(*api.PAMAutoApprovalRule)
	}{
		{"no scope", func(r *api.PAMAutoApprovalRule) { r.TargetIDs = nil }},
		{"wrong kind", func(r *api.PAMAutoApprovalRule) { r.AppliesTo = []string{"emergency"} }},
		{"wrong type", func(r *api.PAMAutoApprovalRule) { r.TargetTypes = []string{"unknown"} }},
		{"wrong folder", func(r *api.PAMAutoApprovalRule) { r.Folders = []string{"../prod"} }},
		{"blank role", func(r *api.PAMAutoApprovalRule) { r.RequesterRoles = []string{" "} }},
		{"control role", func(r *api.PAMAutoApprovalRule) { r.RequesterRoles = []string{"oncall\nadmin"} }},
		{"too many roles", func(r *api.PAMAutoApprovalRule) {
			for i := 0; i < 65; i++ {
				r.RequesterRoles = append(r.RequesterRoles, fmt.Sprint(i))
			}
		}},
		{"long target", func(r *api.PAMAutoApprovalRule) { r.TargetIDs = []string{strings.Repeat("x", 257)} }},
		{"invalid pattern", func(r *api.PAMAutoApprovalRule) { r.TicketPattern = "[" }},
		{"long pattern", func(r *api.PAMAutoApprovalRule) { r.TicketPattern = strings.Repeat("x", 1025) }},
		{"zero lifetime", func(r *api.PAMAutoApprovalRule) { r.MaxTTLSeconds = 0 }},
		{"too long lifetime", func(r *api.PAMAutoApprovalRule) { r.MaxTTLSeconds = 86401 }},
		{"overnight window", func(r *api.PAMAutoApprovalRule) {
			r.Window = &api.PAMAutoApprovalWindow{Start: "23:00", End: "01:00", TimeZone: "UTC"}
		}},
		{"host local zone", func(r *api.PAMAutoApprovalRule) {
			r.Window = &api.PAMAutoApprovalWindow{Start: "09:00", End: "17:00", TimeZone: "Local"}
		}},
		{"unknown zone", func(r *api.PAMAutoApprovalRule) {
			r.Window = &api.PAMAutoApprovalWindow{Start: "09:00", End: "17:00", TimeZone: "Unknown/Zone"}
		}},
		{"unknown weekday", func(r *api.PAMAutoApprovalRule) {
			r.Window = &api.PAMAutoApprovalWindow{Start: "09:00", End: "17:00", TimeZone: "UTC", Days: []string{"monday"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := api.PAMAutoApprovalRule{ID: "11111111-1111-4111-8111-111111111111", Name: "Routine access", AppliesTo: []string{"session"}, TargetIDs: []string{"orders"}, MaxTTLSeconds: 120, Enabled: true}
			tc.change(&rule)
			_, err := (&pamService{}).SavePAMAutoApprovalRule(context.Background(), "tenant", "admin", rule)
			if !errors.Is(err, api.ErrPAMInvalid) {
				t.Fatalf("invalid rule error=%v", err)
			}
		})
	}
}
