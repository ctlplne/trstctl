// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"encoding/json"
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
// pre-B4 behaviour and remains the default for an operator who sets no scope.
type EABPolicy struct {
	// AllowedIdentifiers scopes which DNS identifiers orders under this
	// credential may request. An entry is either an exact name
	// ("api.example.com") or a wildcard suffix ("*.example.com", which matches
	// example.com and anything under it). Empty means unscoped.
	AllowedIdentifiers []string
	// Profile binding is deliberately absent. The ACME server does not select a
	// certificate profile — that decision is made at the issuance seam in
	// internal/server — so a Profile field here would be policy that nothing
	// reads. Adding one before the seam can honour it would put back exactly the
	// kind of advertised-but-inert setting the truth-integrity sweep removed.
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
	switch {
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
