// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A272: break-glass identity provider administrators. A breakglass target
// vaults an Okta, Entra ID or Google Workspace super administrator in the
// application secret its provider rotates. It is never opened as a session
// and never checked out after review: only a named emergency responder
// releases it, at once, through emergency access — every approver is
// notified, the credential (password and current TOTP code, never the seed)
// is shown once, and checking it in or its deadline rotates it. Its hardware
// security keys stay with the people its provider records as holding them.

// pamBreakGlassProviderTypes are the providers a break-glass account comes
// from.
var pamBreakGlassProviderTypes = map[string]bool{"okta-user": true, "entra-user": true, "google-workspace-user": true}

// breakGlassAccount checks a breakglass target's provider and secret: one of
// pamBreakGlassProviderTypes in this tenant, rotating the secret's role in
// place, which is the target's only role.
func (s *pamService) breakGlassAccount(tenantID, providerID, accountSecret string, roles []string) (dynsecret.Provider, error) {
	if providerID == "" || accountSecret == "" || len(roles) != 1 || roles[0] != accountSecret {
		return nil, fmt.Errorf("%w: a break-glass target names its provider and one account secret, which is its only role", api.ErrPAMInvalid)
	}
	if s.secretReader == nil || s.rotation.check == nil || s.rotation.queue == nil {
		return nil, fmt.Errorf("%w: break-glass accounts need the secrets API", api.ErrPAMInvalid)
	}
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		profile, ok := provider.(interface{ DynamicSecretProviderType() string })
		static, isStatic := provider.(dynsecret.StaticRotationProvider)
		phaser, phased := provider.(dynsecret.RotationPhaser)
		switch {
		case !ok || !pamBreakGlassProviderTypes[profile.DynamicSecretProviderType()]:
			return nil, fmt.Errorf("%w: provider %q is not an Okta, Entra ID or Google Workspace administrator provider", api.ErrPAMInvalid, providerID)
		case !isStatic || !static.AllowsStaticRotation(accountSecret) || !phased || phaser.RotationPhase(accountSecret) != dynsecret.RotationSinglePhase:
			return nil, fmt.Errorf("%w: provider %q does not rotate %q in place as a static credential", api.ErrPAMInvalid, providerID, accountSecret)
		}
		return provider, nil
	}
	return nil, fmt.Errorf("%w: no dynamic-secret provider %s in this tenant", api.ErrPAMInvalid, providerID)
}

// breakGlassHardwareKeys is who holds a break-glass role's hardware keys.
func (s *pamService) breakGlassHardwareKeys(tenantID, providerID, role string) []string {
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		if holders, ok := provider.(interface{ BreakGlassHardwareKeyHolders(string) []string }); ok {
			return holders.BreakGlassHardwareKeyHolders(role)
		}
	}
	return nil
}

// breakGlassTOTP computes a break-glass role's current TOTP code with the
// totp provider (A239) its provider names for it; none when it names none.
// The seed never leaves that provider; the caller wipes the code.
func (s *pamService) breakGlassTOTP(ctx context.Context, tenantID string, provider dynsecret.Provider, role, leaseID string) ([]byte, time.Time, error) {
	named, ok := provider.(interface{ BreakGlassTOTPProvider(string) string })
	if !ok || named.BreakGlassTOTPProvider(role) == "" {
		return nil, time.Time{}, nil
	}
	id := named.BreakGlassTOTPProvider(role)
	for _, candidate := range s.providers.ForTenant(tenantID) {
		if candidate == nil || candidate.Name() != id {
			continue
		}
		cred, err := candidate.Generate(ctx, dynsecret.GenerateRequest{Role: role, TTL: 30 * time.Second, LeaseID: leaseID})
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("%w: the account's TOTP code is unavailable", api.ErrPAMRejected)
		}
		var code struct {
			Code       secret.JSONBytes `json:"code"`
			ValidUntil time.Time        `json:"valid_until"`
		}
		err = json.Unmarshal(cred.Secret, &code)
		secret.Wipe(cred.Secret)
		if err != nil || len(code.Code) == 0 {
			secret.Wipe(code.Code)
			return nil, time.Time{}, fmt.Errorf("%w: the account's TOTP code is unavailable", api.ErrPAMRejected)
		}
		return code.Code, code.ValidUntil, nil
	}
	return nil, time.Time{}, fmt.Errorf("%w: the account's totp provider %s is not configured", api.ErrPAMRejected, id)
}

func pamEmergencyReleasedEventID(tenantID, requestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-checkout-emergency-released\x00"+tenantID+"\x00"+requestID)).String()
}

// OpenPAMEmergencyCheckout releases a break-glass account once to a named
// responder without review.
func (s *pamService) OpenPAMEmergencyCheckout(ctx context.Context, tenantID, idempotencyKey, responder string, req api.PAMCheckoutRequest) (*api.PAMEmergencyCheckout, error) {
	reason := strings.TrimSpace(req.Reason)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	switch {
	case responder == "" || idempotencyKey == "":
		return nil, fmt.Errorf("%w: a named responder and an idempotency key are required", api.ErrPAMInvalid)
	case req.TargetType != pamTargetBreakGlass || req.TargetID == "":
		return nil, fmt.Errorf("%w: an emergency check-out names a breakglass target", api.ErrPAMInvalid)
	case !validUUID(req.RequestID):
		return nil, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	case req.TemplateID != "":
		return nil, fmt.Errorf("%w: emergency access takes no template", api.ErrPAMInvalid)
	case reason == "" || utf8.RuneCountInString(reason) > pamCheckoutReasonMax || strings.ContainsAny(reason, "\r\n"):
		return nil, fmt.Errorf("%w: emergency access needs a reason of one line, 1-%d characters", api.ErrPAMInvalid, pamCheckoutReasonMax)
	case ttl < pamCheckoutMinTTL || ttl > pamEmergencyMaxTTL:
		return nil, fmt.Errorf("%w: ttl_seconds must be %d-%d", api.ErrPAMInvalid, int(pamCheckoutMinTTL.Seconds()), int(pamEmergencyMaxTTL.Seconds()))
	}
	responders, err := s.store.ListPAMEmergencyResponders(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(responders, responder) {
		return nil, fmt.Errorf("%w: %s is not a named emergency responder", api.ErrPAMRejected, responder)
	}
	rec, err := s.store.GetPAMTarget(ctx, tenantID, pamTargetBreakGlass, req.TargetID)
	if err != nil {
		return nil, fmt.Errorf("%w: unknown breakglass target %q", api.ErrPAMInvalid, req.TargetID)
	}
	if !rec.Enabled {
		return nil, fmt.Errorf("%w: breakglass target %q is disabled", api.ErrPAMRejected, req.TargetID)
	}
	provider, err := s.breakGlassAccount(tenantID, rec.ProviderID, rec.AccountSecret, rec.AllowedRoles)
	if err != nil {
		return nil, fmt.Errorf("%w: registered breakglass target %q is no longer valid: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	if _, err := s.store.GetPAMCheckout(ctx, tenantID, req.RequestID); err == nil {
		return nil, fmt.Errorf("%w: this release's credential was already shown; it is shown once", api.ErrPAMTargetConflict)
	}
	// The rotation that will retire what is shown must be able to run.
	if err := s.rotation.check(ctx, tenantID, rec.ProviderID, rec.AccountSecret, ""); err != nil {
		return nil, err
	}
	value, version, _, err := s.vaultedAccount(ctx, tenantID, pamTargetBreakGlass, rec.AccountSecret)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value)
	var account struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(value, &account) != nil || account.Username == "" || len(account.Password) == 0 {
		secret.Wipe(account.Password)
		return nil, fmt.Errorf("%w: account secret %q does not hold a username and password", api.ErrPAMRejected, rec.AccountSecret)
	}
	defer secret.Wipe(account.Password)
	code, validUntil, err := s.breakGlassTOTP(ctx, tenantID, provider, rec.AccountSecret, req.RequestID)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(code)
	released := struct {
		Username       string           `json:"username"`
		Password       secret.JSONBytes `json:"password"`
		TOTPCode       secret.JSONBytes `json:"totp_code,omitempty"`
		TOTPValidUntil *time.Time       `json:"totp_valid_until,omitempty"`
	}{Username: account.Username, Password: account.Password, TOTPCode: code}
	if len(code) > 0 {
		released.TOTPValidUntil = &validUntil
	}
	credential, err := json.Marshal(released) // #nosec G117 -- the one-time break-glass release the responder asked for; returned as wiped bytes, never stored (CWE-200)
	if err != nil {
		return nil, err
	}

	now := s.clock().UTC()
	expiresAt := now.Add(ttl)
	// The grant and its notice to every approver are recorded before the
	// credential is released.
	if _, err := s.store.GetPAMEmergencyGrant(ctx, tenantID, req.RequestID); err != nil {
		if err := s.recordEmergency(ctx, tenantID, projections.PAMEmergencyOpened{SessionID: req.RequestID, Responder: responder,
			Reason: reason, TargetType: pamTargetBreakGlass, TargetID: req.TargetID, Role: rec.AccountSecret,
			OpenedAt: now, ExpiresAt: expiresAt}); err != nil {
			secret.Wipe(credential)
			return nil, err
		}
	}
	payload, err := json.Marshal(projections.PAMCheckoutEmergencyReleased{RequestID: req.RequestID, TargetType: pamTargetBreakGlass,
		TargetID: req.TargetID, ProviderID: rec.ProviderID, AccountSecret: rec.AccountSecret, SecretVersion: version, Reason: reason,
		ExpiresAt: expiresAt, Responder: responder, At: now})
	if err != nil {
		secret.Wipe(credential)
		return nil, err
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		candidate := events.Event{ID: pamEmergencyReleasedEventID(tenantID, req.RequestID), Type: projections.EventPAMCheckoutEmergencyReleased,
			TenantID: tenantID, Time: now.Truncate(time.Microsecond), Data: payload}
		if actor, ok := events.ActorFromContext(ctx); ok {
			candidate.Actor = &actor
		}
		canonical, err := s.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, payload) {
			return fmt.Errorf("%w: this release's credential was already shown; it is shown once", api.ErrPAMTargetConflict)
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		secret.Wipe(credential)
		return nil, err
	}
	checkout, err := s.store.GetPAMCheckout(ctx, tenantID, req.RequestID)
	if err != nil {
		secret.Wipe(credential)
		return nil, err
	}
	grant, err := s.store.GetPAMEmergencyGrant(ctx, tenantID, req.RequestID)
	if err != nil {
		secret.Wipe(credential)
		return nil, err
	}
	return &api.PAMEmergencyCheckout{Checkout: pamCheckoutView(checkout), Credential: credential,
		HardwareKeyHolders: s.breakGlassHardwareKeys(tenantID, rec.ProviderID, rec.AccountSecret), Emergency: emergencyView(grant)}, nil
}

// OpenPAMEmergencyCheckout is the served broker's break-glass release.
func (s *Server) OpenPAMEmergencyCheckout(ctx context.Context, tenantID, idempotencyKey, responder string, req api.PAMCheckoutRequest) (*api.PAMEmergencyCheckout, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMEmergencyCheckout(ctx, tenantID, idempotencyKey, responder, req)
}
