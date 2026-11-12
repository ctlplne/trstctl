// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"slices"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type configuredWindowsLocalRotationProvider struct {
	*configuredDynamicProvider
	store   *store.Store
	log     *events.Log
	enabled bool
}

func attachWindowsLocalRotationProviders(providers []dynsecret.Provider, d Deps) []dynsecret.Provider {
	result := append([]dynsecret.Provider(nil), providers...)
	for i, p := range result {
		if native, ok := p.(*configuredWindowsLocalRotationProvider); ok {
			copy := *native
			copy.store = d.Store
			copy.log = d.Log
			copy.enabled = slices.Contains(d.AgentClaimableJobKinds, hostaccounts.RotationDestination)
			result[i] = &copy
		}
	}
	return result
}
func (p *configuredWindowsLocalRotationProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("native local accounts support prepared static rotation only")
}
func (p *configuredWindowsLocalRotationProvider) StaticRotationBinding(role string) string {
	if !p.AllowsStaticRotation(role) || p.cfg.RoleBindings[role] == "" {
		return ""
	}
	raw, _ := json.Marshal(struct{ Tenant, Provider, Host, SID, Role string }{p.tenantID, p.id, p.cfg.WindowsHostAgentID, p.cfg.RoleBindings[role], role})
	return crypto.SHA256Hex(append([]byte("trstctl/windows-native-provider/v1\x00"), raw...))
}
func (p *configuredWindowsLocalRotationProvider) PrepareStaticCredential(ctx context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	if !p.enabled || p.store == nil || p.log == nil || !req.Static || !validUUID(req.LeaseID) || p.StaticRotationBinding(req.Role) == "" {
		return nil, errors.New("native local rotation is not explicitly configured")
	}
	host, e := p.store.GetAgent(ctx, p.tenantID, p.cfg.WindowsHostAgentID)
	if e != nil || host.OffboardedAt != nil || !slices.Contains(host.Roles, mtls.AgentRoleHost) {
		return nil, errors.New("native local rotation requires an active enrolled host")
	}
	scan, e := p.store.LatestCompleteWindowsLocalAccountScan(ctx, p.tenantID, p.cfg.WindowsHostAgentID)
	if e != nil {
		return nil, e
	}
	catalog := &pamService{store: p.store, log: p.log}
	if e = catalog.canonicalWindowsLocalAccountScan(ctx, p.tenantID, scan, false); e != nil {
		return nil, e
	}
	if scan.Report == nil || scan.Report.Inventory == nil {
		return nil, errors.New("native local rotation requires a complete signed inventory")
	}
	var account winaccounts.Account
	for _, a := range scan.Report.Inventory.Accounts {
		if a.SID == p.cfg.RoleBindings[req.Role] {
			account = a
			break
		}
	}
	binding := winaccounts.RotationBinding{Machine: scan.Report.Inventory.Machine, Account: account}
	if binding.Validate() != nil {
		return nil, errors.New("selected local SID is missing or cannot rotate")
	}
	previous := ""
	last, e := p.store.LatestWindowsLocalRotation(ctx, p.tenantID, p.cfg.WindowsHostAgentID, account.SID)
	if e == nil {
		last, cmd, err := projections.CanonicalWindowsLocalRotation(ctx, p.store, p.log, p.tenantID, last.Intent.RotationID)
		if err != nil {
			return nil, err
		}
		switch {
		case last.Observation != nil && last.Observation.Report.Status == "succeeded" && cmd.Phase == store.SecretStaticRotationCompleted:
			previous = last.Intent.RotationID
		case last.Observation != nil && last.Observation.Report.Status == "not_applied" && cmd.Terminal():
			// A268-O1: a generation the host proved it never applied left its
			// predecessor current.
			previous = last.Intent.PredecessorGenerationID
		default:
			return nil, orchestrator.DeferDelivery(errors.New("earlier local generation still requires completion or recovery"))
		}
	} else if !errors.Is(e, store.ErrWindowsLocalRotationNotFound) {
		return nil, e
	}
	accountID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl:pam-discovery:"+p.tenantID+"/"+store.WindowsHostAccountProviderID(p.cfg.WindowsHostAgentID)+"/sid:"+account.SID)).String()
	intent, e := hostaccounts.NewRotationIntent(hostaccounts.RotationIntent{RotationID: req.LeaseID, AccountID: accountID, TenantID: p.tenantID, AgentID: p.cfg.WindowsHostAgentID, InventoryRunID: scan.ID, PredecessorGenerationID: previous, Native: binding})
	if e != nil {
		return nil, e
	}
	password, e := crypto.RandomAccountPassword(24)
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(password)
	return hostaccounts.MarshalRotationPreparation(hostaccounts.RotationPreparation{Intent: intent, ProviderBinding: p.StaticRotationBinding(req.Role), Role: req.Role, Credential: hostaccounts.LocalCredential{Host: binding.Machine.Name, Username: binding.Account.Name, Password: secret.JSONBytes(password)}})
}
func (p *configuredWindowsLocalRotationProvider) boundPreparation(req dynsecret.GenerateRequest, raw []byte) (hostaccounts.RotationPreparation, error) {
	v, e := hostaccounts.DecodeRotationPreparation(raw)
	if e != nil {
		return v, e
	}
	if !req.Static || v.Intent.RotationID != req.LeaseID || v.Role != req.Role || v.ProviderBinding != p.StaticRotationBinding(req.Role) || v.Intent.TenantID != p.tenantID || v.Intent.AgentID != p.cfg.WindowsHostAgentID || v.Intent.Native.Account.SID != p.cfg.RoleBindings[req.Role] {
		secret.Wipe(v.Credential.Password)
		return hostaccounts.RotationPreparation{}, errors.New("sealed local generation has changed provider authority")
	}
	return v, nil
}
func (p *configuredWindowsLocalRotationProvider) PreparedHostRotationIntent(req dynsecret.GenerateRequest, raw, old []byte) (hostaccounts.RotationIntent, error) {
	v, e := p.boundPreparation(req, raw)
	if e != nil {
		return hostaccounts.RotationIntent{}, e
	}
	defer secret.Wipe(v.Credential.Password)
	c, e := hostaccounts.DecodeLocalCredential(old, v.Intent)
	secret.Wipe(c.Password)
	return v.Intent, e
}
func (p *configuredWindowsLocalRotationProvider) GenerateStaticPrepared(ctx context.Context, req dynsecret.GenerateRequest, raw []byte) (dynsecret.Credential, error) {
	v, e := p.boundPreparation(req, raw)
	if e != nil {
		return dynsecret.Credential{}, e
	}
	defer secret.Wipe(v.Credential.Password)
	state, cmd, e := projections.CanonicalWindowsLocalRotation(ctx, p.store, p.log, p.tenantID, req.LeaseID)
	if e != nil {
		return dynsecret.Credential{}, e
	}
	if state.Intent != v.Intent || cmd.ProviderBinding != v.ProviderBinding {
		return dynsecret.Credential{}, errors.New("native local prepared source differs")
	}
	if state.Observation == nil || state.Observation.Report.Status != "succeeded" {
		return dynsecret.Credential{}, orchestrator.DeferDelivery(errors.New("native host generation is awaiting exact authentication proof; retained for host return"))
	}
	value, e := hostaccounts.MarshalLocalCredential(v.Credential)
	return dynsecret.Credential{BackendRef: req.LeaseID, Secret: value, Metadata: map[string]string{"provider_type": "windows", "role": req.Role}}, e
}

// PreparedHostRotationNotApplied reports the host's proof that this prepared
// generation was never applied (A268-O1).
func (p *configuredWindowsLocalRotationProvider) PreparedHostRotationNotApplied(ctx context.Context, req dynsecret.GenerateRequest) (bool, error) {
	state, _, e := projections.CanonicalWindowsLocalRotation(ctx, p.store, p.log, p.tenantID, req.LeaseID)
	if e != nil {
		return false, e
	}
	return state.Observation != nil && state.Observation.Report.Status == "not_applied", nil
}

// Historical rotation evidence is not a fresh credential-health sign-in.
func (p *configuredWindowsLocalRotationProvider) VerifyStaticCredential(context.Context, string, []byte) (string, error) {
	return "not_available", nil
}
func (p *configuredWindowsLocalRotationProvider) VerifyStaticPreparedCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared, raw []byte) error {
	v, e := p.boundPreparation(req, prepared)
	if e != nil {
		return e
	}
	defer secret.Wipe(v.Credential.Password)
	c, e := hostaccounts.DecodeLocalCredential(raw, v.Intent)
	if e != nil {
		return e
	}
	defer secret.Wipe(c.Password)
	if !bytes.Equal(v.Credential.Password, c.Password) {
		return errors.New("native proof cannot authorize another password")
	}
	state, cmd, e := projections.CanonicalWindowsLocalRotation(ctx, p.store, p.log, p.tenantID, req.LeaseID)
	if e != nil {
		return e
	}
	if state.Intent != v.Intent || cmd.ProviderBinding != v.ProviderBinding || state.Observation == nil || state.Observation.Report.Status != "succeeded" {
		return errors.New("exact native generation has no signed authentication proof")
	}
	return nil
}
func (p *configuredWindowsLocalRotationProvider) RestorePreparedStaticCredential(context.Context, dynsecret.GenerateRequest, []byte, []byte) error {
	return errors.New("native local generation requires explicit recovery; no blind inverse reset")
}
func (p *configuredWindowsLocalRotationProvider) RestoreStaticCredential(context.Context, string, string, []byte) error {
	return errors.New("native local generation requires its retained preparation")
}
func (p *configuredWindowsLocalRotationProvider) Revoke(ctx context.Context, ref string) error {
	// In-place native success already includes exact predecessor refusal. A
	// second password reset here would revoke the new generation.
	v, _, e := projections.CanonicalWindowsLocalRotation(ctx, p.store, p.log, p.tenantID, ref)
	if e != nil {
		return e
	}
	if v.Observation == nil || v.Observation.Report.Status != "succeeded" {
		return errors.New("local predecessor retirement is unproven")
	}
	return nil
}
