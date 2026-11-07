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
	"trstctl.com/trstctl/internal/crypto/secret"
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
	var result api.PAMTarget
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		if err := s.requirePAMFolder(ctx, tenantID, target.Folder); err != nil {
			return err
		}
		var err error
		result, err = s.registerPAMTarget(ctx, tenantID, actor, target)
		return err
	})
	return result, err
}

func (s *pamService) registerPAMTarget(ctx context.Context, tenantID, actor string, target api.PAMTarget) (api.PAMTarget, error) {
	if _, err := uuid.Parse(tenantID); err != nil || actor == "" || !pamTargetNameOK(target.ID) {
		return api.PAMTarget{}, fmt.Errorf("%w: tenant, actor, and a lowercase target id are required", api.ErrPAMInvalid)
	}
	key := pamTargetID{tenantID, target.ID}
	if err := s.validateGatewayBinding(ctx, tenantID, target); err != nil {
		return api.PAMTarget{}, err
	}
	switch {
	case isPAMDatabaseType(target.TargetType):
		if s.databases[pamDatabaseID{tenantID, target.TargetType, target.ID}] != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: operator-configured target already exists", api.ErrPAMTargetConflict)
		}
		if target.Host != "" || target.Port != 0 || len(target.Principals) != 0 {
			return api.PAMTarget{}, fmt.Errorf("%w: %s target has SSH-only fields", api.ErrPAMInvalid, target.TargetType)
		}
		if _, err := s.buildDatabaseTarget(PAMDatabaseTarget{TargetType: target.TargetType, TenantID: tenantID, ID: target.ID,
			ProviderID: target.ProviderID, AllowedRoles: target.AllowedRoles,
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress, AccountSecret: target.AccountSecret}); err != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
		}
		if target.AccountSecret != "" {
			// The vaulted account's secret must be readable now.
			if s.secretReader == nil {
				return api.PAMTarget{}, fmt.Errorf("%w: vaulted accounts need the secrets API", api.ErrPAMInvalid)
			}
			value, _, err := s.secretReader(ctx, tenantID, target.AccountSecret)
			if err != nil {
				return api.PAMTarget{}, fmt.Errorf("%w: account secret %q is not readable: %v", api.ErrPAMInvalid, target.AccountSecret, err)
			}
			secret.Wipe(value)
		}
	case target.TargetType == pamTargetWindowsLocal:
		// A268: one Windows local administrator account, vaulted in the
		// application secret its native provider rotates on the enrolled host.
		if target.Host != "" || target.Port != 0 || len(target.Principals) != 0 || target.GatewayAgentID != "" ||
			target.GatewayAddress != "" || len(target.HostKeyFingerprints) != 0 {
			return api.PAMTarget{}, fmt.Errorf("%w: a windows_local target names only its native provider and account secret", api.ErrPAMInvalid)
		}
		if len(target.AllowedRoles) == 0 {
			target.AllowedRoles = []string{target.AccountSecret}
		}
		if err := s.windowsLocalAccount(tenantID, target.ProviderID, target.AccountSecret, target.AllowedRoles); err != nil {
			return api.PAMTarget{}, err
		}
		value, _, err := s.secretReader(ctx, tenantID, target.AccountSecret)
		if err != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: account secret %q is not readable: %v", api.ErrPAMInvalid, target.AccountSecret, err)
		}
		secret.Wipe(value)
	case target.TargetType == pamTargetSSH:
		if _, ok := s.sshTargets[key]; ok {
			return api.PAMTarget{}, fmt.Errorf("%w: operator-configured target already exists", api.ErrPAMTargetConflict)
		}
		if target.ProviderID != "" || len(target.AllowedRoles) != 0 || target.AccountSecret != "" {
			return api.PAMTarget{}, fmt.Errorf("%w: SSH target has database-only fields", api.ErrPAMInvalid)
		}
		if strings.ContainsAny(target.Host, "/@ \t\r\n") {
			return api.PAMTarget{}, fmt.Errorf("%w: SSH host must be a hostname or IP address", api.ErrPAMInvalid)
		}
		d := s.targetDeps
		d.Config.SSHTargets = []PAMSSHTarget{{TenantID: tenantID, ID: target.ID, Host: target.Host, Port: target.Port, Principals: target.Principals,
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress, HostKeyFingerprints: target.HostKeyFingerprints}}
		if _, err := buildPAMSSHTargets(d); err != nil {
			return api.PAMTarget{}, fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
		}
	default:
		return api.PAMTarget{}, fmt.Errorf("%w: target_type must be one of %s", api.ErrPAMInvalid, pamTargetTypesText())
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
		Principals: principals, RegisteredBy: actor, GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress,
		HostKeyFingerprints: append([]string(nil), target.HostKeyFingerprints...), AccountSecret: target.AccountSecret, Folder: target.Folder}
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
		DisabledReason: rec.DisabledReason, DisabledAt: rec.DisabledAt,
		GatewayAgentID: rec.GatewayAgentID, GatewayAddress: rec.GatewayAddress, HostKeyFingerprints: rec.HostKeyFingerprints,
		AccountSecret: rec.AccountSecret, Folder: rec.Folder}
}

// operatorDatabaseTarget and operatorSSHTarget are the reads of
// operator-configured targets, with their gateway bindings.
func operatorDatabaseTarget(id string, t *pamDatabaseTarget) api.PAMTarget {
	return api.PAMTarget{ID: id, TargetType: t.cfg.TargetType, ProviderID: t.cfg.ProviderID, AllowedRoles: t.cfg.AllowedRoles, Enabled: true, Source: "operator",
		GatewayAgentID: t.cfg.GatewayAgentID, GatewayAddress: t.cfg.GatewayAddress}
}

func operatorSSHTarget(id string, t PAMSSHTarget) api.PAMTarget {
	return api.PAMTarget{ID: id, TargetType: pamTargetSSH, Host: t.Host, Port: t.Port, Principals: t.Principals, Enabled: true, Source: "operator",
		GatewayAgentID: t.GatewayAgentID, GatewayAddress: t.GatewayAddress, HostKeyFingerprints: t.HostKeyFingerprints}
}

func (s *pamService) GetPAMTarget(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	target, err := s.getPAMTarget(ctx, tenantID, targetType, id)
	if err != nil || !isPAMDatabaseType(targetType) {
		return target, err
	}
	health, err := s.store.ListPAMAccountHealth(ctx, tenantID)
	if err != nil {
		return api.PAMTarget{}, err
	}
	if h, ok := health[[2]string{target.TargetType, target.ID}]; ok {
		target.Health = healthView(h)
	}
	return target, nil
}

func (s *pamService) getPAMTarget(ctx context.Context, tenantID, targetType, id string) (api.PAMTarget, error) {
	switch {
	case isPAMDatabaseType(targetType):
		if t := s.databases[pamDatabaseID{tenantID, targetType, id}]; t != nil {
			return operatorDatabaseTarget(id, t), nil
		}
	case targetType == pamTargetSSH:
		if t, ok := s.sshTargets[pamTargetID{tenantID, id}]; ok {
			return operatorSSHTarget(id, t), nil
		}
	case targetType == pamTargetWindowsLocal:
		// Tenant-registered only.
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
	out := make([]api.PAMTarget, 0, len(recs)+len(s.databases)+len(s.sshTargets))
	for _, rec := range recs {
		out = append(out, targetFromStore(rec))
	}
	for key, target := range s.databases {
		if key.tenantID == tenantID {
			out = append(out, operatorDatabaseTarget(key.id, target))
		}
	}
	for key, target := range s.sshTargets {
		if key.tenantID == tenantID {
			out = append(out, operatorSSHTarget(key.id, target))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetType == out[j].TargetType {
			return out[i].ID < out[j].ID
		}
		return out[i].TargetType < out[j].TargetType
	})
	health, err := s.store.ListPAMAccountHealth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if h, ok := health[[2]string{out[i].TargetType, out[i].ID}]; ok {
			out[i].Health = healthView(h)
		}
	}
	return out, nil
}

func (s *pamService) DisablePAMTarget(ctx context.Context, tenantID, targetType, id, actor, reason string) (api.PAMTarget, error) {
	if actor == "" || strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return api.PAMTarget{}, fmt.Errorf("%w: actor and disable reason are required", api.ErrPAMInvalid)
	}
	if s.databases[pamDatabaseID{tenantID, targetType, id}] != nil || (targetType == pamTargetSSH && s.sshTargets[pamTargetID{tenantID, id}].ID != "") {
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

// databaseTarget is a database target of the given type: the deployment's
// own, or a tenant-registered one checked again against its provider now.
func (s *pamService) databaseTarget(ctx context.Context, tenantID, targetType, id string) (*pamDatabaseTarget, error) {
	if t := s.databases[pamDatabaseID{tenantID, targetType, id}]; t != nil {
		return t, nil
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, targetType, id)
	if errors.Is(err, store.ErrPAMTargetNotFound) {
		return nil, fmt.Errorf("%w: unknown %s target %q", api.ErrPAMInvalid, targetType, id)
	}
	if err != nil {
		return nil, err
	}
	if !rec.Enabled {
		return nil, fmt.Errorf("%w: %s target %q is disabled", api.ErrPAMRejected, targetType, id)
	}
	target, err := s.buildDatabaseTarget(PAMDatabaseTarget{TargetType: targetType, TenantID: tenantID, ID: id, ProviderID: rec.ProviderID,
		AllowedRoles: rec.AllowedRoles, GatewayAgentID: rec.GatewayAgentID, GatewayAddress: rec.GatewayAddress, AccountSecret: rec.AccountSecret})
	if err != nil {
		return nil, fmt.Errorf("%w: registered %s target %q is no longer valid: %v", api.ErrPAMRejected, targetType, id, err)
	}
	return target, nil
}

// buildDatabaseTarget checks one database target as the deployment's own are
// checked, against its tenant's providers.
func (s *pamService) buildDatabaseTarget(target PAMDatabaseTarget) (*pamDatabaseTarget, error) {
	d := s.targetDeps
	d.Config.PostgresTargets, d.Config.DatabaseTargets = nil, []PAMDatabaseTarget{target}
	targets, err := buildPAMDatabaseTargets(d)
	if err != nil {
		return nil, err
	}
	return targets[pamDatabaseID{target.TenantID, target.TargetType, strings.TrimSpace(target.ID)}], nil
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
	d.Config.SSHTargets = []PAMSSHTarget{{TenantID: tenantID, ID: id, Host: rec.Host, Port: rec.Port, Principals: rec.Principals,
		GatewayAgentID: rec.GatewayAgentID, GatewayAddress: rec.GatewayAddress, HostKeyFingerprints: rec.HostKeyFingerprints}}
	targets, err := buildPAMSSHTargets(d)
	if err != nil {
		return PAMSSHTarget{}, fmt.Errorf("%w: registered ssh target %q is no longer valid: %v", api.ErrPAMRejected, id, err)
	}
	return targets[pamTargetID{tenantID, id}], nil
}

// pamVaultedRef prefixes a vaulted session's backend reference: the
// application secret holding the account it signs in as (A261).
const pamVaultedRef = "secret:"

// isPAMVaultedSession reports whether a database session signs in as a
// vaulted account rather than a per-session lease (A261).
func isPAMVaultedSession(rec store.PAMSession) bool {
	return isPAMDatabaseType(rec.TargetType) && strings.HasPrefix(rec.BackendRef, pamVaultedRef)
}

// windowsLocalAccount checks a windows_local target's account (A268): its
// provider rotates the account secret's role as one exact Windows local SAM
// account on its enrolled host, and that role is the target's only one.
func (s *pamService) windowsLocalAccount(tenantID, providerID, accountSecret string, roles []string) error {
	switch {
	case providerID == "" || accountSecret == "" || len(roles) != 1 || roles[0] != accountSecret:
		return fmt.Errorf("%w: a windows_local target names its native Windows provider and one account secret, which is its only role", api.ErrPAMInvalid)
	case s.secretReader == nil || s.rotation.native == nil:
		return fmt.Errorf("%w: windows_local accounts need the secrets API", api.ErrPAMInvalid)
	case !s.rotation.native(tenantID, providerID, accountSecret):
		return fmt.Errorf("%w: provider %q does not rotate %q as an exact Windows local account on an enrolled host", api.ErrPAMInvalid,
			providerID, accountSecret)
	}
	return nil
}
