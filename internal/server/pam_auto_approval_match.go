// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// pamAutoApprovalRequest is what an auto-approval rule is matched against: a
// session request or a check-out, as its review is about to be requested.
type pamAutoApprovalRequest struct {
	Kind                 string // "session" or "checkout"
	TargetType, TargetID string
	Folder               string
	Roles                []string
	Reason               string
	TTLSeconds           int
	At                   time.Time
}

// pamAutoApprovalMatch is what a rule matched; it is recorded with the
// approval the rule made.
type pamAutoApprovalMatch struct {
	Target string   `json:"target"`
	Folder string   `json:"folder,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Window string   `json:"window,omitempty"`
	Ticket string   `json:"ticket,omitempty"`
}

var pamWeekdays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// pamAutoApprovalMatches reports whether rule r approves req: every condition
// the rule sets holds. A condition the rule leaves empty is not checked; the
// target scope never is empty (the broker refuses such a rule).
func pamAutoApprovalMatches(r store.PAMAutoApprovalRule, req pamAutoApprovalRequest) (pamAutoApprovalMatch, bool) {
	if !r.Enabled || !slices.Contains(r.AppliesTo, req.Kind) || req.TTLSeconds <= 0 || req.TTLSeconds > r.MaxTTLSeconds {
		return pamAutoApprovalMatch{}, false
	}
	if len(r.TargetTypes) == 0 && len(r.TargetIDs) == 0 && len(r.Folders) == 0 {
		return pamAutoApprovalMatch{}, false
	}
	if (len(r.TargetTypes) > 0 && !slices.Contains(r.TargetTypes, req.TargetType)) ||
		(len(r.TargetIDs) > 0 && !slices.Contains(r.TargetIDs, req.TargetID)) ||
		(len(r.Folders) > 0 && (req.Folder == "" || !slices.Contains(r.Folders, req.Folder))) {
		return pamAutoApprovalMatch{}, false
	}
	m := pamAutoApprovalMatch{Target: req.TargetType + "/" + req.TargetID, Folder: req.Folder}
	if len(r.RequesterRoles) > 0 {
		for _, role := range req.Roles {
			if slices.Contains(r.RequesterRoles, role) && !slices.Contains(m.Roles, role) {
				m.Roles = append(m.Roles, role)
			}
		}
		if len(m.Roles) == 0 {
			return pamAutoApprovalMatch{}, false
		}
		slices.Sort(m.Roles)
	}
	if len(r.WindowDays) > 0 || r.WindowStart != "" {
		loc, err := time.LoadLocation(r.TimeZone)
		if err != nil {
			return pamAutoApprovalMatch{}, false
		}
		local := req.At.In(loc)
		if len(r.WindowDays) > 0 && !slices.Contains(r.WindowDays, pamWeekdays[local.Weekday()]) {
			return pamAutoApprovalMatch{}, false
		}
		if clock := local.Format("15:04"); r.WindowStart != "" && (clock < r.WindowStart || clock >= r.WindowEnd) {
			return pamAutoApprovalMatch{}, false
		}
		m.Window = local.Format("Mon 2006-01-02 15:04 MST")
	}
	if r.TicketPattern != "" {
		re, err := regexp.Compile(`\A(?:` + r.TicketPattern + `)\z`)
		if err != nil {
			return pamAutoApprovalMatch{}, false
		}
		if m.Ticket = re.FindString(req.Reason); m.Ticket == "" {
			return pamAutoApprovalMatch{}, false
		}
	}
	return m, true
}

// pamValidWindowClock is an "HH:MM" wall-clock time.
func pamValidWindowClock(s string) bool {
	t, err := time.Parse("15:04", s)
	return err == nil && t.Format("15:04") == s && !strings.HasPrefix(s, "24")
}
