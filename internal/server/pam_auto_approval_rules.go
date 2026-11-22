// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func pamAutoApprovalRuleView(r store.PAMAutoApprovalRule) api.PAMAutoApprovalRule {
	out := api.PAMAutoApprovalRule{ID: r.ID, Name: r.Name, AppliesTo: r.AppliesTo, TargetTypes: r.TargetTypes, TargetIDs: r.TargetIDs, Folders: r.Folders, RequesterRoles: r.RequesterRoles, TicketPattern: r.TicketPattern, MaxTTLSeconds: r.MaxTTLSeconds, Enabled: r.Enabled, Revision: r.Revision, SavedBy: r.SavedBy, SavedAt: r.SavedAt.UTC()}
	if r.WindowStart != "" {
		out.Window = &api.PAMAutoApprovalWindow{Days: r.WindowDays, Start: r.WindowStart, End: r.WindowEnd, TimeZone: r.TimeZone}
	}
	return out
}

// pamAutoApprovalList bounds the policy's work and canonicalizes set-like
// criteria. Human-facing metadata may contain Unicode, never control bytes.
func pamAutoApprovalList(values []string) ([]string, error) {
	if len(values) > 64 {
		return nil, fmt.Errorf("%w: each criterion may contain at most 64 values", api.ErrPAMInvalid)
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 256 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%w: criterion values must be 1–256 bytes without control characters", api.ErrPAMInvalid)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *pamService) SavePAMAutoApprovalRule(ctx context.Context, tenantID, actor string, in api.PAMAutoApprovalRule) (api.PAMAutoApprovalRule, error) {
	in.Name = strings.TrimSpace(in.Name)
	if actor == "" || !validUUID(in.ID) || in.Name == "" || utf8.RuneCountInString(in.Name) > 120 || strings.IndexFunc(in.Name, unicode.IsControl) >= 0 {
		return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: author, rule UUID and a name up to 120 characters are required", api.ErrPAMInvalid)
	}
	r := store.PAMAutoApprovalRule{ID: in.ID, Name: in.Name, TicketPattern: in.TicketPattern, MaxTTLSeconds: in.MaxTTLSeconds, Enabled: in.Enabled}
	lists := []struct {
		src []string
		dst *[]string
	}{{in.AppliesTo, &r.AppliesTo}, {in.TargetTypes, &r.TargetTypes}, {in.TargetIDs, &r.TargetIDs}, {in.Folders, &r.Folders}, {in.RequesterRoles, &r.RequesterRoles}}
	for _, list := range lists {
		var err error
		*list.dst, err = pamAutoApprovalList(list.src)
		if err != nil {
			return api.PAMAutoApprovalRule{}, err
		}
	}
	if len(r.AppliesTo) == 0 || r.MaxTTLSeconds < 1 || r.MaxTTLSeconds > 86400 || len(r.TargetTypes)+len(r.TargetIDs)+len(r.Folders) == 0 {
		return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: applies_to, an explicit target scope and max_ttl_seconds of 1–86400 are required", api.ErrPAMInvalid)
	}
	for _, kind := range r.AppliesTo {
		if kind != "session" && kind != "checkout" {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: applies_to is session or checkout", api.ErrPAMInvalid)
		}
	}
	for _, kind := range r.TargetTypes {
		if !isPAMDatabaseType(kind) && kind != pamTargetSSH {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: target_types must name supported access types", api.ErrPAMInvalid)
		}
	}
	for _, folder := range r.Folders {
		if !pamTemplateName.MatchString(folder) {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: folder names use 1–64 lowercase letters, digits, - or _", api.ErrPAMInvalid)
		}
	}
	if len(r.TicketPattern) > 1024 {
		return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: ticket_pattern is limited to 1024 bytes", api.ErrPAMInvalid)
	}
	if r.TicketPattern != "" {
		if _, err := regexp.Compile(`\A(?:` + r.TicketPattern + `)\z`); err != nil {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: ticket_pattern must be an RE2 expression: %v", api.ErrPAMInvalid, err)
		}
	}
	if w := in.Window; w != nil {
		if !pamValidWindowClock(w.Start) || !pamValidWindowClock(w.End) || w.Start >= w.End {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: window start/end use HH:MM, start before end; use two rules for an overnight window", api.ErrPAMInvalid)
		}
		if len(w.TimeZone) > 100 {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: window time_zone must be an IANA name", api.ErrPAMInvalid)
		}
		if _, err := time.LoadLocation(w.TimeZone); err != nil || w.TimeZone == "" || w.TimeZone == "Local" {
			return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: window time_zone must be an explicit IANA name", api.ErrPAMInvalid)
		}
		days, err := pamAutoApprovalList(w.Days)
		if err != nil {
			return api.PAMAutoApprovalRule{}, err
		}
		for _, day := range days {
			if !slices.Contains(pamWeekdays, day) {
				return api.PAMAutoApprovalRule{}, fmt.Errorf("%w: window days use mon through sun", api.ErrPAMInvalid)
			}
		}
		r.WindowDays, r.WindowStart, r.WindowEnd, r.TimeZone = days, w.Start, w.End, w.TimeZone
	}
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		revision := int64(1)
		old, err := s.store.GetPAMAutoApprovalRuleAnyState(ctx, tenantID, r.ID)
		switch {
		case err == nil:
			if old.DeletedAt != nil || old.Revision != in.Revision {
				return fmt.Errorf("%w: the rule changed or was deleted; read it again", orchestrator.ErrIdempotencyConflict)
			}
			revision = old.Revision + 1
		case !errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound):
			return err
		case in.Revision != 0:
			return fmt.Errorf("%w: a new rule has revision 0", orchestrator.ErrIdempotencyConflict)
		}
		if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
			live, err := s.store.ListPAMAutoApprovalRules(ctx, tenantID)
			if err != nil {
				return err
			}
			if len(live) >= 256 {
				return fmt.Errorf("%w: a tenant may keep at most 256 live automatic review rules; delete unused rules first", api.ErrPAMInvalid)
			}
		}
		r.Revision, r.SavedBy, r.SavedAt = revision, actor, s.clock().UTC()
		return s.appendProject(ctx, tenantID, projections.EventPAMAutoApprovalRuleSaved, projections.PAMAutoApprovalRuleSaved{Rule: r})
	})
	if err != nil {
		return api.PAMAutoApprovalRule{}, err
	}
	saved, err := s.store.GetPAMAutoApprovalRule(ctx, tenantID, r.ID)
	return pamAutoApprovalRuleView(saved), err
}
func (s *pamService) ListPAMAutoApprovalRules(ctx context.Context, tenantID string) ([]api.PAMAutoApprovalRule, error) {
	rows, err := s.store.ListPAMAutoApprovalRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMAutoApprovalRule, 0, len(rows))
	for _, r := range rows {
		out = append(out, pamAutoApprovalRuleView(r))
	}
	return out, nil
}
func (s *pamService) DeletePAMAutoApprovalRule(ctx context.Context, tenantID, actor, id string, revision int64) error {
	if actor == "" || !validUUID(id) {
		return fmt.Errorf("%w: an author and rule UUID are required", api.ErrPAMInvalid)
	}
	return s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		r, err := s.store.GetPAMAutoApprovalRule(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return fmt.Errorf("%w: the rule changed; read it again", orchestrator.ErrIdempotencyConflict)
		}
		return s.appendProject(ctx, tenantID, projections.EventPAMAutoApprovalRuleDeleted, projections.PAMAutoApprovalRuleDeleted{ID: id, Revision: revision + 1, Actor: actor, At: s.clock().UTC()})
	})
}
func (s *Server) SavePAMAutoApprovalRule(ctx context.Context, tenantID, actor string, in api.PAMAutoApprovalRule) (api.PAMAutoApprovalRule, error) {
	if s.pam == nil {
		return api.PAMAutoApprovalRule{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMAutoApprovalRule(ctx, tenantID, actor, in)
}
func (s *Server) ListPAMAutoApprovalRules(ctx context.Context, tenantID string) ([]api.PAMAutoApprovalRule, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMAutoApprovalRules(ctx, tenantID)
}
func (s *Server) DeletePAMAutoApprovalRule(ctx context.Context, tenantID, actor, id string, revision int64) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.DeletePAMAutoApprovalRule(ctx, tenantID, actor, id, revision)
}
