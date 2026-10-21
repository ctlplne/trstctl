// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

// External Account Binding as authorization, not as a doorbell (epic B4).
//
// RFC 8555 §7.3.4 EAB proves that whoever is creating this ACME account was
// pre-authorized out of band. The server verified that proof and then threw the
// key id away. Every account that got past the door was then identical: nothing
// recorded which credential admitted it, so nothing could scope what it went on
// to ask for, count what it had already taken, or stop it without stopping
// everyone.
//
// A kid is now an authorization with a scope attached. The account remembers
// which one admitted it, and every order is checked against that credential's
// policy: which identifiers it may ask for, which profile it is bound to, how
// many orders it may place, how long it stays valid, and whether an operator has
// switched it off. Denials are recorded, and disabling a credential stops new
// orders without touching certificates already issued under it.
//
// The HMAC key itself stays where it was — byte-backed, in locked memory, sourced
// from operator config (AN-8). Nothing here puts a shared MAC secret into a
// database row or an HTTP response.

// EABPolicy is what one external account credential is authorized to do. A zero
// policy authorizes everything the server would otherwise allow, which is the
// pre-B4 behavior and remains the default for an operator who sets no scope.
type EABPolicy struct {
	// AllowedIdentifiers scopes which DNS identifiers orders under this
	// credential may request. An entry is either an exact name
	// ("api.example.com") or a wildcard suffix ("*.example.com", which matches
	// example.com and anything under it). Empty means unscoped.
	AllowedIdentifiers []string
	// Profile pins the tenant certificate profile every order under this
	// credential is issued with (A55). The newOrder handler records it on the
	// order, the issuance seam signs under it, and a client that asks for a
	// different profile is refused. Empty keeps the mount's default profile.
	Profile string
	// MaxOrders caps how many orders may be created under this credential over
	// the server's lifetime. Zero means uncapped.
	MaxOrders int
	// NotAfter closes the credential at a point in time. Zero means no window.
	NotAfter time.Time
	// Disabled refuses new accounts and new orders under this credential.
	// Certificates already issued stay valid — this is a tap, not a revocation.
	Disabled bool
}

// scopesIdentifiers reports whether the policy constrains identifiers at all.
func (p EABPolicy) scopesIdentifiers() bool { return len(p.AllowedIdentifiers) > 0 }

// permits reports whether a DNS identifier is inside the credential's scope.
// Matching is case-insensitive and, for a wildcard entry, covers the apex as well
// as any label beneath it: "*.example.com" permits example.com, a.example.com,
// and a.b.example.com. An entry with no wildcard is an exact match only.
func (p EABPolicy) permits(identifier string) bool {
	if !p.scopesIdentifiers() {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(identifier, ".")))
	if name == "" {
		return false
	}
	for _, allowed := range p.AllowedIdentifiers {
		pattern := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(allowed, ".")))
		if pattern == "" {
			continue
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if name == suffix || strings.HasSuffix(name, "."+suffix) {
				return true
			}
			continue
		}
		if name == pattern {
			return true
		}
	}
	return false
}

// expired reports whether the credential's validity window has closed.
func (p EABPolicy) expired(now time.Time) bool {
	return !p.NotAfter.IsZero() && !now.Before(p.NotAfter)
}

// ExternalAccountBindingKey maps one ACME EAB kid to its HMAC key and the scope
// that key authorizes. The key is copied into locked memory by
// WithExternalAccountBindings; callers should wipe their own copy after
// construction.
type ExternalAccountBindingKey struct {
	KeyID   string
	HMACKey []byte
	Policy  EABPolicy
}

// eabCredential is the server's live view of one credential: its secret, its
// policy, the operator's runtime override, and what has been taken under it.
type eabCredential struct {
	keyID  string
	key    *secret.Buffer
	policy EABPolicy
	// hmacKeyRef is the secret reference a rotated credential's MAC key was
	// resolved from (A50/A54); empty for a configuration key.
	hmacKeyRef string
	// keyUnavailable marks a rotated credential whose reference could not be
	// resolved at startup: it admits nothing until the reference resolves.
	keyUnavailable bool

	mu sync.Mutex
	// disabledByOperator is the served disable verb's state. It is separate from
	// policy.Disabled so a config-disabled credential cannot be re-enabled by an
	// API call — config remains the floor.
	disabledByOperator bool
	accountsBound      int
	ordersCreated      int
	ordersDenied       int
	lastUsed           time.Time
}

// active reports whether the credential may admit new work, and why not if it
// may not. The reason is operator-facing and is what the ACME problem document
// says, so it must name the cause without naming the secret.
func (c *eabCredential) active(now time.Time) (bool, string) {
	c.mu.Lock()
	operatorDisabled := c.disabledByOperator
	orders := c.ordersCreated
	c.mu.Unlock()

	switch {
	case c.keyUnavailable:
		return false, "external account credential's MAC key reference could not be resolved"
	case c.policy.Disabled:
		return false, "external account credential is disabled in configuration"
	case operatorDisabled:
		return false, "external account credential has been disabled by an operator"
	case c.policy.expired(now):
		return false, "external account credential's validity window has closed"
	case c.policy.MaxOrders > 0 && orders >= c.policy.MaxOrders:
		return false, "external account credential has reached its order quota"
	default:
		return true, ""
	}
}

// pendingFinalizationAllowed checks revocation of an internal-trust grant
// without reapplying the new-order quota. The last permitted order must still
// be finalizable, but disabling or expiring its grant stops an unissued leaf.
func (c *eabCredential) pendingFinalizationAllowed(now time.Time) bool {
	c.mu.Lock()
	operatorDisabled := c.disabledByOperator
	c.mu.Unlock()
	return !c.policy.Disabled && !operatorDisabled && !c.policy.expired(now)
}

func (c *eabCredential) recordAccountBound(now time.Time) {
	c.mu.Lock()
	c.accountsBound++
	c.lastUsed = now
	c.mu.Unlock()
}

func (c *eabCredential) recordOrder(now time.Time) {
	c.mu.Lock()
	c.ordersCreated++
	c.lastUsed = now
	c.mu.Unlock()
}

func (c *eabCredential) recordDenial(now time.Time) {
	c.mu.Lock()
	c.ordersDenied++
	c.lastUsed = now
	c.mu.Unlock()
}

func (c *eabCredential) status(now time.Time) EABCredentialStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := EABCredentialStatus{
		KeyID:              c.keyID,
		AllowedIdentifiers: append([]string(nil), c.policy.AllowedIdentifiers...),
		MaxOrders:          c.policy.MaxOrders,
		AccountsBound:      c.accountsBound,
		OrdersCreated:      c.ordersCreated,
		OrdersDenied:       c.ordersDenied,
		DisabledInConfig:   c.policy.Disabled,
		DisabledByOperator: c.disabledByOperator,
	}
	if !c.policy.NotAfter.IsZero() {
		notAfter := c.policy.NotAfter.UTC()
		out.NotAfter = &notAfter
	}
	if !c.lastUsed.IsZero() {
		lastUsed := c.lastUsed.UTC()
		out.LastUsedAt = &lastUsed
	}
	out.Profile = c.policy.Profile
	out.HMACKeyRef = c.hmacKeyRef
	switch {
	case c.keyUnavailable:
		out.State, out.Reason = "unavailable", "MAC key reference could not be resolved"
	case c.policy.Disabled:
		out.State, out.Reason = "disabled", "disabled in configuration"
	case c.disabledByOperator:
		out.State, out.Reason = "disabled", "disabled by an operator"
	case c.policy.expired(now):
		out.State, out.Reason = "expired", "validity window has closed"
	case c.policy.MaxOrders > 0 && c.ordersCreated >= c.policy.MaxOrders:
		out.State, out.Reason = "exhausted", "order quota reached"
	default:
		out.State = "active"
	}
	return out
}

// EABCredentialStatus is the served, secret-free view of one external account
// credential. It carries scope, quota, and what has been taken under the
// credential — never the HMAC key, in any form.
type EABCredentialStatus struct {
	KeyID              string     `json:"key_id"`
	State              string     `json:"state"` // active | disabled | expired | exhausted
	Reason             string     `json:"reason,omitempty"`
	AllowedIdentifiers []string   `json:"allowed_identifiers,omitempty"`
	MaxOrders          int        `json:"max_orders,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	AccountsBound      int        `json:"accounts_bound"`
	OrdersCreated      int        `json:"orders_created"`
	OrdersDenied       int        `json:"orders_denied"`
	DisabledInConfig   bool       `json:"disabled_in_config"`
	DisabledByOperator bool       `json:"disabled_by_operator"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
	// Profile is the certificate profile the credential pins (A55).
	Profile string `json:"profile,omitempty"`
	// HMACKeyRef is the secret reference a rotated credential's key came from
	// (A54); it names where the key lives, never the key.
	HMACKeyRef string `json:"hmac_key_ref,omitempty"`
}

// EABPolicyUpdate is the served policy an operator sets on one credential
// (A53). Disabling stays with the disable verb; the configuration floor for a
// config-disabled credential is untouched.
type EABPolicyUpdate struct {
	AllowedIdentifiers []string
	MaxOrders          int
	NotAfter           time.Time
	Profile            string
}

const (
	acmeEventEABPolicyUpdated      = "acme.eab.policy_updated"
	acmeEventEABCredentialRotated  = "acme.eab.credential_rotated" // #nosec G101 -- an event type name, not credential material (CWE-798)
	eabResolvedKeyMinimumLength    = 16
	eabCredentialKeyIDMaximumBytes = 128
)

type acmeEABPolicyUpdatedEvent struct {
	KeyID              string   `json:"key_id"`
	AllowedIdentifiers []string `json:"allowed_identifiers,omitempty"`
	MaxOrders          int      `json:"max_orders,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	Profile            string   `json:"profile,omitempty"`
}

type acmeEABCredentialRotatedEvent struct {
	KeyID              string   `json:"key_id"`
	PredecessorKeyID   string   `json:"predecessor_key_id"`
	HMACKeyRef         string   `json:"hmac_key_ref"`
	AllowedIdentifiers []string `json:"allowed_identifiers,omitempty"`
	MaxOrders          int      `json:"max_orders,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	Profile            string   `json:"profile,omitempty"`
	RotatedAt          string   `json:"rotated_at"`
}

// EABCredentialsContext refreshes the registration-bound view before an
// operator reads it, so a listing after a tenant re-registration reflects the
// replayed policy and rotation events.
func (s *Server) EABCredentialsContext(ctx context.Context) ([]EABCredentialStatus, error) {
	_, release, err := s.beginStateScope(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.EABCredentials(), nil
}

// WithEABSecretResolver supplies the tenant secret-reference resolver a
// rotated credential's MAC key is read through (A54), both when an operator
// rotates and when the state log replays. The returned bytes are copied into
// locked memory and the resolver's copy is wiped.
func (s *Server) WithEABSecretResolver(resolve func(context.Context, string) ([]byte, error)) *Server {
	s.eabSecretResolver = resolve
	return s
}

func validEABKeyID(keyID string) bool {
	return keyID != "" && len(keyID) <= eabCredentialKeyIDMaximumBytes && !strings.ContainsAny(keyID, " \t\r\n/")
}

// UpdateEABPolicy replaces a credential's scope, quota, window and profile at
// runtime and records the change in the state log so it survives a restart
// (A53). ok is false for an unknown credential.
func (s *Server) UpdateEABPolicy(ctx context.Context, keyID string, update EABPolicyUpdate) (EABCredentialStatus, bool, error) {
	if s == nil {
		return EABCredentialStatus{}, false, nil
	}
	keyID = strings.TrimSpace(keyID)
	ctx, release, err := s.beginStateScope(ctx)
	if err != nil {
		return EABCredentialStatus{}, true, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := s.eabCredentials[keyID]
	if cred == nil {
		return EABCredentialStatus{}, false, nil
	}
	payload := acmeEABPolicyUpdatedEvent{KeyID: keyID, AllowedIdentifiers: normalizedEABIdentifiers(update.AllowedIdentifiers),
		MaxOrders: update.MaxOrders, Profile: strings.TrimSpace(update.Profile)}
	if !update.NotAfter.IsZero() {
		payload.NotAfter = update.NotAfter.UTC().Format(time.RFC3339)
	}
	if err := s.appendStateEventLocked(ctx, acmeEventEABPolicyUpdated, payload); err != nil {
		return EABCredentialStatus{}, true, err
	}
	s.applyEABPolicyUpdatedLocked(payload)
	return cred.status(time.Now()), true, nil
}

func normalizedEABIdentifiers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) applyEABPolicyUpdatedLocked(payload acmeEABPolicyUpdatedEvent) {
	cred := s.eabCredentials[payload.KeyID]
	if cred == nil {
		return
	}
	cred.mu.Lock()
	defer cred.mu.Unlock()
	cred.policy.AllowedIdentifiers = append([]string(nil), payload.AllowedIdentifiers...)
	cred.policy.MaxOrders = payload.MaxOrders
	cred.policy.NotAfter = time.Time{}
	if payload.NotAfter != "" {
		if notAfter, err := time.Parse(time.RFC3339, payload.NotAfter); err == nil {
			cred.policy.NotAfter = notAfter
		}
	}
	cred.policy.Profile = payload.Profile
}

// RotateEABCredential registers a successor credential whose MAC key is read
// from hmacKeyRef through the secret resolver, inheriting the predecessor's
// scope, quota, window and profile, and records it in the state log (A50/A54).
// The predecessor stays as it is: the operator disables it once clients
// have migrated. The key never appears in the event or any response.
func (s *Server) RotateEABCredential(ctx context.Context, keyID, successorKeyID, hmacKeyRef string) (EABCredentialStatus, bool, error) {
	if s == nil {
		return EABCredentialStatus{}, false, nil
	}
	keyID, successorKeyID, hmacKeyRef = strings.TrimSpace(keyID), strings.TrimSpace(successorKeyID), strings.TrimSpace(hmacKeyRef)
	if !validEABKeyID(successorKeyID) {
		return EABCredentialStatus{}, true, errors.New("acme: successor key id must be a single non-empty token")
	}
	if s.eabSecretResolver == nil {
		return EABCredentialStatus{}, true, errors.New("acme: this mount has no secret resolver; rotation needs the tenant secret store")
	}
	ctx, release, err := s.beginStateScope(ctx)
	if err != nil {
		return EABCredentialStatus{}, true, err
	}
	defer release()
	s.mu.Lock()
	predecessor := s.eabCredentials[keyID]
	_, taken := s.eabCredentials[successorKeyID]
	s.mu.Unlock()
	if predecessor == nil {
		return EABCredentialStatus{}, false, nil
	}
	if taken {
		return EABCredentialStatus{}, true, fmt.Errorf("acme: external account credential %q already exists", successorKeyID)
	}
	raw, err := s.eabSecretResolver(ctx, hmacKeyRef)
	if err != nil {
		return EABCredentialStatus{}, true, fmt.Errorf("acme: resolve successor MAC key reference: %w", err)
	}
	defer secret.Wipe(raw)
	if len(raw) < eabResolvedKeyMinimumLength {
		return EABCredentialStatus{}, true, fmt.Errorf("acme: the successor MAC key must be at least %d bytes", eabResolvedKeyMinimumLength)
	}
	buf, err := secret.NewFrom(raw)
	if err != nil {
		return EABCredentialStatus{}, true, err
	}
	predecessor.mu.Lock()
	policy := predecessor.policy
	policy.AllowedIdentifiers = append([]string(nil), predecessor.policy.AllowedIdentifiers...)
	predecessor.mu.Unlock()
	policy.Disabled = false
	payload := acmeEABCredentialRotatedEvent{KeyID: successorKeyID, PredecessorKeyID: keyID, HMACKeyRef: hmacKeyRef,
		AllowedIdentifiers: policy.AllowedIdentifiers, MaxOrders: policy.MaxOrders, Profile: policy.Profile,
		RotatedAt: time.Now().UTC().Format(time.RFC3339)}
	if !policy.NotAfter.IsZero() {
		payload.NotAfter = policy.NotAfter.UTC().Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, raced := s.eabCredentials[successorKeyID]; raced {
		buf.Destroy()
		return EABCredentialStatus{}, true, fmt.Errorf("acme: external account credential %q already exists", successorKeyID)
	}
	if err := s.appendStateEventLocked(ctx, acmeEventEABCredentialRotated, payload); err != nil {
		buf.Destroy()
		return EABCredentialStatus{}, true, err
	}
	cred := &eabCredential{keyID: successorKeyID, key: buf, policy: policy, hmacKeyRef: hmacKeyRef}
	s.eabCredentials[successorKeyID] = cred
	return cred.status(time.Now()), true, nil
}

// applyEABCredentialRotatedLocked restores a rotated credential on replay,
// resolving its MAC key through the resolver. A reference that cannot be
// resolved registers the credential as unavailable, which admits nothing
// until the reference resolves again; the mount still starts.
func (s *Server) applyEABCredentialRotatedLocked(ctx context.Context, payload acmeEABCredentialRotatedEvent) {
	if s.eabCredentials == nil {
		s.eabCredentials = map[string]*eabCredential{}
	}
	if _, exists := s.eabCredentials[payload.KeyID]; exists {
		return
	}
	policy := EABPolicy{AllowedIdentifiers: append([]string(nil), payload.AllowedIdentifiers...),
		MaxOrders: payload.MaxOrders, Profile: payload.Profile}
	if payload.NotAfter != "" {
		if notAfter, err := time.Parse(time.RFC3339, payload.NotAfter); err == nil {
			policy.NotAfter = notAfter
		}
	}
	cred := &eabCredential{keyID: payload.KeyID, policy: policy, hmacKeyRef: payload.HMACKeyRef, keyUnavailable: true}
	if s.eabSecretResolver != nil {
		if raw, err := s.eabSecretResolver(ctx, payload.HMACKeyRef); err == nil && len(raw) >= eabResolvedKeyMinimumLength {
			if buf, err := secret.NewFrom(raw); err == nil {
				cred.key, cred.keyUnavailable = buf, false
			}
			secret.Wipe(raw)
		}
	}
	s.eabCredentials[payload.KeyID] = cred
}

// EABCredentials returns the served status of every configured external account
// credential, sorted by key id. It is the read half of the operator surface and
// contains no secret material.
func (s *Server) EABCredentials() []EABCredentialStatus {
	if s == nil {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	creds := make([]*eabCredential, 0, len(s.eabCredentials))
	for _, c := range s.eabCredentials {
		creds = append(creds, c)
	}
	s.mu.Unlock()

	out := make([]EABCredentialStatus, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.status(now))
	}
	sortEABStatuses(out)
	return out
}

// SetEABDisabled switches one credential off or on at runtime, so an operator can
// stop a leaked or misbehaving credential without a config push and without
// touching certificates already issued under it. It cannot re-enable a credential
// that configuration disables — config is the floor, and an API call must not be
// able to lift it.
func (s *Server) SetEABDisabled(keyID string, disabled bool) (EABCredentialStatus, bool) {
	if s == nil {
		return EABCredentialStatus{}, false
	}
	keyID = strings.TrimSpace(keyID)
	s.mu.Lock()
	cred := s.eabCredentials[keyID]
	s.mu.Unlock()
	if cred == nil {
		return EABCredentialStatus{}, false
	}
	cred.mu.Lock()
	cred.disabledByOperator = disabled
	cred.mu.Unlock()
	return cred.status(time.Now()), true
}

func sortEABStatuses(in []EABCredentialStatus) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].KeyID < in[j-1].KeyID; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// acmeEventEABOrderDenied records an order refused by its authorizing
// credential's policy. A denial has to be as durable as an issuance: it is the
// evidence that the scope did something, and the only way an operator learns a
// credential is being used for names it was never granted.
const acmeEventEABOrderDenied = "acme.eab.order_denied"

type acmeEABOrderDeniedEvent struct {
	AccountURL  string   `json:"account_url"`
	EABKeyID    string   `json:"eab_key_id"`
	Identifiers []string `json:"identifiers,omitempty"`
	Reason      string   `json:"reason"`
}

// authorizeOrderAgainstEAB decides whether an order is inside the scope of the
// credential that admitted its account. It returns that credential (so the caller
// can count the outcome) and an operator-facing denial reason, empty when the
// order may proceed.
//
// An account created without EAB has no credential and is unconstrained here —
// the deployment either requires EAB or it does not, and this function does not
// re-litigate that decision.
func (s *Server) authorizeOrderAgainstEAB(acct *account, req OrderRequest) (*eabCredential, string) {
	if acct == nil || acct.eabKeyID == "" {
		return nil, ""
	}
	s.mu.Lock()
	cred := s.eabCredentials[acct.eabKeyID]
	s.mu.Unlock()
	if cred == nil {
		// The credential that admitted this account is gone from configuration.
		// Fail closed: an account outlives a config reload, and silently treating
		// it as unscoped would turn removing a credential into widening it.
		return nil, "the external account credential that authorized this account is no longer configured"
	}
	if ok, reason := cred.active(time.Now()); !ok {
		return cred, reason
	}
	for _, id := range req.Identifiers {
		if !cred.policy.permits(id.Value) {
			return cred, "identifier " + id.Value + " is outside the scope of external account credential " + cred.keyID
		}
	}
	return cred, ""
}

// recordEABOrderDenial appends the denial to the state log. A log failure must
// not turn a refusal into an acceptance, so the error is deliberately not
// propagated: the order is refused either way, and the caller has already
// decided that.
func (s *Server) recordEABOrderDenial(ctx context.Context, acct *account, req OrderRequest, reason string) {
	if s.stateLog == nil || acct == nil {
		return
	}
	payload := acmeEABOrderDeniedEvent{AccountURL: acct.url, EABKeyID: acct.eabKeyID, Reason: reason}
	for _, id := range req.Identifiers {
		payload.Identifiers = append(payload.Identifiers, id.Value)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = s.stateLog.Append(ctx, events.Event{
		Type: acmeEventEABOrderDenied, TenantID: s.stateTenantID, Data: body,
	})
}

// ExternalAccountRequired reports whether this mount refuses a newAccount that
// carries no external account binding (RFC 8555 §7.3.4).
func (s *Server) ExternalAccountRequired() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.ExternalAccountRequired
}
