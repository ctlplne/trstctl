// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

func (p *configuredADRotationProvider) StaticReconciliation(role string) (dynsecret.Provider, dynsecret.ADReconcilePrincipal, error) {
	var identity dynsecret.ADReconcilePrincipal
	grant := p.cfg.ADReconcile
	if p.reconcileMode || grant == nil || !p.AllowsStaticRotation(role) || p.RotationPhase(role) != dynsecret.RotationSinglePhase || !slices.Contains(grant.AllowedRoles, role) {
		return nil, identity, errors.New("server: no designated reconcile principal for this single-account role")
	}
	identity = dynsecret.ADReconcilePrincipal{DN: grant.BindDN, SID: grant.SID, GUID: strings.ToLower(grant.GUID)}
	cfg := p.cfg
	cfg.BindDN, cfg.PasswordRef = grant.BindDN, grant.PasswordRef
	// This object never enters the registry and grants only the reviewed role.
	cfg.AllowedRoles = []string{role}
	cfg.RoleBindings = map[string]string{role: p.cfg.RoleBindings[role]}
	cfg.RotationAccounts = nil
	if p.cfg.ADLogonNames != nil {
		cfg.ADLogonNames = map[string]string{p.cfg.RoleBindings[role]: p.cfg.ADLogonNames[p.cfg.RoleBindings[role]]}
	}
	selected := newConfiguredDynamicProvider(cfg, map[string]bool{role: true}, p.maxTTL, p.credentials, p.guard).(*configuredADRotationProvider)
	selected.reconcileMode = true
	selected.rotationBindDN = p.cfg.BindDN
	return selected, identity, nil
}

func copyADReconcileConfig(p *config.ADReconcileConfig) *config.ADReconcileConfig {
	if p == nil {
		return nil
	}
	value := *p
	value.AllowedRoles = append([]string(nil), p.AllowedRoles...)
	return &value
}
