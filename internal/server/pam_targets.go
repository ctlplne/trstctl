// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func pamTargetNameOK(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func (s *Server) RegisterPAMTarget(ctx context.Context, tenantID, actor string, target api.PAMTarget) (api.PAMTarget, error) {
	if s.pam == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	return s.pam.RegisterPAMTarget(ctx, tenantID, actor, target)
}
func (s *Server) ListPAMTargets(ctx context.Context, tenantID string) ([]api.PAMTarget, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMTargets(ctx, tenantID)
}
func (s *Server) GetPAMTarget(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	if s.pam == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMTarget(ctx, tenantID, targetType, id)
}
func (s *Server) DisablePAMTarget(ctx context.Context, tenantID, targetType, id, actor, reason string) (api.PAMTarget, error) {
	if s.pam == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	return s.pam.DisablePAMTarget(ctx, tenantID, targetType, id, actor, reason)
}

func (s *pamService) RegisterPAMTarget(ctx context.Context, tenantID, actor string, target api.PAMTarget) (api.PAMTarget, error) {
	if _, err := uuid.Parse(tenantID); err != nil || actor == "" || !pamTargetNameOK(target.ID) {
		return api.PAMTarget{}, fmt.Errorf("%w: tenant, actor, and a lowercase target id are required", api.ErrPAMInvalid)
	}
	key := pamTargetID{tenantID, target.ID}
	switch target.TargetType {
	case pamTargetPostgres:
		if s.postgres[key] != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: operator-configured target already exists", api.ErrPAMTargetConflict)
		}
		if target.Host != "" || target.Port != 0 || len(target.Principals) != 0 {
			return api.PAMTarget{}, fmt.Errorf("%w: postgres target has SSH-only fields", api.ErrPAMInvalid)
		}
		d := s.targetDeps
		d.Config.PostgresTargets = []PAMPostgresTarget{{TenantID: tenantID, ID: target.ID, ProviderID: target.ProviderID, AllowedRoles: target.AllowedRoles}}
		if _, err := buildPAMPostgresTargets(d); err != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
		}
	case pamTargetSSH:
		if _, ok := s.sshTargets[key]; ok {
			return api.PAMTarget{}, fmt.Errorf("%w: operator-configured target already exists", api.ErrPAMTargetConflict)
		}
		if target.ProviderID != "" || len(target.AllowedRoles) != 0 {
			return api.PAMTarget{}, fmt.Errorf("%w: SSH target has postgres-only fields", api.ErrPAMInvalid)
		}
		if strings.ContainsAny(target.Host, "/@ \t\r\n") {
			return api.PAMTarget{}, fmt.Errorf("%w: SSH host must be a hostname or IP address", api.ErrPAMInvalid)
		}
		d := s.targetDeps
		d.Config.SSHTargets = []PAMSSHTarget{{TenantID: tenantID, ID: target.ID, Host: target.Host, Port: target.Port, Principals: target.Principals}}
		if _, err := buildPAMSSHTargets(d); err != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
		}
	default:
		return api.PAMTarget{}, fmt.Errorf("%w: target_type must be postgres or ssh", api.ErrPAMInvalid)
	}
	if _, err := s.store.GetPAMTarget(ctx, tenantID, target.TargetType, target.ID); err == nil {
		return api.PAMTarget{}, fmt.Errorf("%w: target id already registered", api.ErrPAMTargetConflict)
	} else if !errors.Is(err, store.ErrPAMTargetNotFound) {
		return api.PAMTarget{}, err
	}
	roles := append([]string(nil), target.AllowedRoles...)
	principals := append([]string(nil), target.Principals...)
	sort.Strings(roles)
	sort.Strings(principals)
	payload := projections.PAMTargetRegistered{TargetType: target.TargetType, ID: target.ID,
		ProviderID: target.ProviderID, AllowedRoles: roles, Host: target.Host, Port: target.Port,
		Principals: principals, RegisteredBy: actor}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-target:"+tenantID+":"+target.TargetType+":"+target.ID)).String()
	if err := s.appendCanonicalPAMTarget(ctx, tenantID, id, projections.EventPAMTargetRegistered, payload); err != nil {
		return api.PAMTarget{}, err
	}
	return s.GetPAMTarget(ctx, tenantID, target.TargetType, target.ID)
}

func (s *pamService) appendCanonicalPAMTarget(ctx context.Context, tenantID, id, kind string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	candidate := events.Event{ID: id, Type: kind, TenantID: tenantID, Data: data}
	if actor, ok := events.ActorFromContext(ctx); ok {
		candidate.Actor = &actor
	}
	e, err := s.log.Append(ctx, candidate)
	if err != nil {
		return err
	}
	if e.Type != kind || e.TenantID != tenantID || !bytes.Equal(e.Data, data) {
		return fmt.Errorf("%w: PAM target event has a different canonical payload", api.ErrPAMTargetConflict)
	}
	return s.projector.Apply(ctx, e)
}

func targetFromStore(rec store.PAMTarget) api.PAMTarget {
	return api.PAMTarget{ID: rec.ID, TargetType: rec.TargetType, ProviderID: rec.ProviderID,
		AllowedRoles: rec.AllowedRoles, Host: rec.Host, Port: rec.Port, Principals: rec.Principals,
		Enabled: rec.Enabled, Source: "tenant", RegisteredBy: rec.RegisteredBy,
		RegisteredAt: &rec.RegisteredAt, DisabledBy: rec.DisabledBy,
		DisabledReason: rec.DisabledReason, DisabledAt: rec.DisabledAt}
}

func (s *pamService) GetPAMTarget(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	key := pamTargetID{tenantID, id}
	switch targetType {
	case pamTargetPostgres:
		if t := s.postgres[key]; t != nil {
			return api.PAMTarget{ID: id, TargetType: targetType, ProviderID: t.cfg.ProviderID, AllowedRoles: t.cfg.AllowedRoles, Enabled: true, Source: "operator"}, nil
		}
	case pamTargetSSH:
		if t, ok := s.sshTargets[key]; ok {
			return api.PAMTarget{ID: id, TargetType: targetType, Host: t.Host, Port: t.Port, Principals: t.Principals, Enabled: true, Source: "operator"}, nil
		}
	default:
		return api.PAMTarget{}, fmt.Errorf("%w: unknown target type", api.ErrPAMInvalid)
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, targetType, id)
	if err != nil {
		return api.PAMTarget{}, err
	}
	return targetFromStore(rec), nil
}

func (s *pamService) ListPAMTargets(ctx context.Context, tenantID string) ([]api.PAMTarget, error) {
	recs, err := s.store.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMTarget, 0, len(recs)+len(s.postgres)+len(s.sshTargets))
	for _, rec := range recs {
		out = append(out, targetFromStore(rec))
	}
	for key, target := range s.postgres {
		if key.tenantID == tenantID {
			out = append(out, api.PAMTarget{ID: key.id, TargetType: pamTargetPostgres, ProviderID: target.cfg.ProviderID, AllowedRoles: target.cfg.AllowedRoles, Enabled: true, Source: "operator"})
		}
	}
	for key, target := range s.sshTargets {
		if key.tenantID == tenantID {
			out = append(out, api.PAMTarget{ID: key.id, TargetType: pamTargetSSH, Host: target.Host, Port: target.Port, Principals: target.Principals, Enabled: true, Source: "operator"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetType == out[j].TargetType {
			return out[i].ID < out[j].ID
		}
		return out[i].TargetType < out[j].TargetType
	})
	return out, nil
}

func (s *pamService) DisablePAMTarget(ctx context.Context, tenantID, targetType, id, actor, reason string) (api.PAMTarget, error) {
	if actor == "" || strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return api.PAMTarget{}, fmt.Errorf("%w: actor and disable reason are required", api.ErrPAMInvalid)
	}
	if (targetType == pamTargetPostgres && s.postgres[pamTargetID{tenantID, id}] != nil) || (targetType == pamTargetSSH && s.sshTargets[pamTargetID{tenantID, id}].ID != "") {
		return api.PAMTarget{}, fmt.Errorf("%w: operator-configured targets must be removed from deployment configuration", api.ErrPAMTargetConflict)
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, targetType, id)
	if err != nil {
		return api.PAMTarget{}, err
	}
	if !rec.Enabled {
		return api.PAMTarget{}, fmt.Errorf("%w: target already disabled", api.ErrPAMTargetConflict)
	}
	payload := projections.PAMTargetDisabled{TargetType: targetType, ID: id, DisabledBy: actor, Reason: strings.TrimSpace(reason)}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-target-disabled:"+tenantID+":"+targetType+":"+id)).String()
	if err := s.appendCanonicalPAMTarget(ctx, tenantID, eventID, projections.EventPAMTargetDisabled, payload); err != nil {
		return api.PAMTarget{}, err
	}
	return s.GetPAMTarget(ctx, tenantID, targetType, id)
}

func (s *pamService) postgresTarget(ctx context.Context, tenantID, id string) (*pamPostgresTarget, error) {
	if t := s.postgres[pamTargetID{tenantID, id}]; t != nil {
		return t, nil
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, pamTargetPostgres, id)
	if errors.Is(err, store.ErrPAMTargetNotFound) {
		return nil, fmt.Errorf("%w: unknown postgres target %q", api.ErrPAMInvalid, id)
	}
	if err != nil {
		return nil, err
	}
	if !rec.Enabled {
		return nil, fmt.Errorf("%w: postgres target %q is disabled", api.ErrPAMRejected, id)
	}
	d := s.targetDeps
	d.Config.PostgresTargets = []PAMPostgresTarget{{TenantID: tenantID, ID: id, ProviderID: rec.ProviderID, AllowedRoles: rec.AllowedRoles}}
	targets, err := buildPAMPostgresTargets(d)
	if err != nil {
		return nil, fmt.Errorf("%w: registered postgres target %q is no longer valid: %v", api.ErrPAMRejected, id, err)
	}
	return targets[pamTargetID{tenantID, id}], nil
}

func (s *pamService) sshTarget(ctx context.Context, tenantID, id string) (PAMSSHTarget, error) {
	if t, ok := s.sshTargets[pamTargetID{tenantID, id}]; ok {
		return t, nil
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, pamTargetSSH, id)
	if errors.Is(err, store.ErrPAMTargetNotFound) {
		return PAMSSHTarget{}, fmt.Errorf("%w: unknown ssh target %q", api.ErrPAMInvalid, id)
	}
	if err != nil {
		return PAMSSHTarget{}, err
	}
	if !rec.Enabled {
		return PAMSSHTarget{}, fmt.Errorf("%w: ssh target %q is disabled", api.ErrPAMRejected, id)
	}
	d := s.targetDeps
	d.Config.SSHTargets = []PAMSSHTarget{{TenantID: tenantID, ID: id, Host: rec.Host, Port: rec.Port, Principals: rec.Principals}}
	targets, err := buildPAMSSHTargets(d)
	if err != nil {
		return PAMSSHTarget{}, fmt.Errorf("%w: registered ssh target %q is no longer valid: %v", api.ErrPAMRejected, id, err)
	}
	return targets[pamTargetID{tenantID, id}], nil
}
