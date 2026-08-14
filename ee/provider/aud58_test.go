// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/samlsp"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
)

// AUD-58 is one authority chain, not three disconnected feature demos:
//
//   verified IdP identity -> active SCIM operator -> exact customer/operation grant.
//
// The directory is checked at request time so a leaver is denied even while an
// OIDC token or SAML session is still cryptographically valid. Delegations keep
// their source, expiry, last-use, and revocation evidence so an administrator can
// answer who had access and why instead of only seeing the rows still in force.

type aud58AccessStore struct {
	mu          sync.Mutex
	identities  map[string]OperatorIdentity
	delegations map[string]DelegationRecord
}

func newAUD58AccessStore() *aud58AccessStore {
	return &aud58AccessStore{identities: map[string]OperatorIdentity{}, delegations: map[string]DelegationRecord{}}
}

func (s *aud58AccessStore) ResolveOperator(_ context.Context, subject string) (OperatorIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, identity := range s.identities {
		if identity.ID == subject || identity.ExternalID == subject || identity.UserName == subject {
			return identity, nil
		}
	}
	return OperatorIdentity{}, ErrNotFound
}

func (s *aud58AccessStore) ListOperatorAccess(context.Context) ([]OperatorAccess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := map[string]*OperatorAccess{}
	for id, identity := range s.identities {
		copy := OperatorAccess{Identity: identity, Delegations: []DelegationRecord{}}
		byID[id] = &copy
	}
	for _, delegation := range s.delegations {
		if row := byID[delegation.OperatorID]; row != nil {
			row.Delegations = append(row.Delegations, delegation)
		}
	}
	out := make([]OperatorAccess, 0, len(byID))
	for _, access := range byID {
		out = append(out, *access)
	}
	return out, nil
}

func (s *aud58AccessStore) Delegations(context.Context) (*DelegationSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	var active []Delegation
	for _, row := range s.delegations {
		if !row.RevokedAt.IsZero() || (!row.ExpiresAt.IsZero() && !now.Before(row.ExpiresAt)) {
			continue
		}
		active = append(active, Delegation{OperatorID: row.OperatorID, CustomerID: row.CustomerID, Operations: []Operation{row.Operation}})
	}
	return NewDelegationSet(active), nil
}

func (s *aud58AccessStore) apply(eventType string, payload AuthorityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if payload.Operator != nil {
		s.identities[payload.Operator.ID] = *payload.Operator
		if !payload.Operator.Active {
			for key, delegation := range s.delegations {
				if delegation.OperatorID == payload.Operator.ID && delegation.RevokedAt.IsZero() {
					delegation.RevokedAt = payload.EffectiveAt
					delegation.RevokedBy = payload.Audit.OperatorID
					s.delegations[key] = delegation
				}
			}
		}
	}
	for _, mutation := range authorityDelegations(payload) {
		key := mutation.OperatorID + "\x00" + mutation.CustomerID + "\x00" + string(mutation.Operation)
		row := DelegationRecord{
			OperatorID: mutation.OperatorID, CustomerID: mutation.CustomerID, Operation: mutation.Operation,
			Source: mutation.Source, GrantedBy: mutation.GrantedBy, GrantedAt: payload.EffectiveAt, ExpiresAt: mutation.ExpiresAt,
		}
		if eventType == EventDelegationRevoked {
			row = s.delegations[key]
			row.RevokedAt, row.RevokedBy = payload.EffectiveAt, payload.Audit.OperatorID
		}
		s.delegations[key] = row
	}
}

type aud58MutationSink struct {
	store *aud58AccessStore
	mu    sync.Mutex
	seen  map[string]eventspec.Event
}

func (s *aud58MutationSink) Append(_ context.Context, key, typ, tenantID string, payload AuthorityEvent) (eventspec.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]eventspec.Event{}
	}
	if prior, ok := s.seen[tenantID+"\x00"+key]; ok {
		return prior, nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return eventspec.Event{}, err
	}
	event := eventspec.Event{ID: "evt-" + key, Type: typ, TenantID: tenantID, Time: payload.EffectiveAt, Data: body}
	s.seen[tenantID+"\x00"+key] = event
	s.store.apply(typ, payload)
	return event, nil
}

func TestAUD58OIDCRejectsADeprovisionedSCIMOperatorImmediately(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	directory := newAUD58AccessStore()
	directory.identities["operator-1"] = OperatorIdentity{
		ID: "operator-1", ExternalID: "op-1", UserName: "dana@provider.example",
		Email: "dana@provider.example", Role: OperatorAdmin, Active: true, Source: "scim:entra",
	}
	authenticator := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer: "https://idp.provider.example", Audience: "trstctl-provider",
		JWKS: f.auth.cfg.JWKS, RoleClaim: "groups", AdminValues: []string{"trstctl-admins"},
		MFAClaim: "amr", MFAValues: []string{"mfa"}, Now: func() time.Time { return f.now },
		Directory: directory, RequireDirectory: true,
	})
	request := f.request(t, f.signer, "idp-k1", f.baseClaims())
	if op, ok := authenticator.AuthenticateOperator(request); !ok || op.ID != "operator-1" {
		t.Fatalf("active SCIM operator = %+v ok=%v, want canonical directory identity", op, ok)
	}

	identity := directory.identities["operator-1"]
	identity.Active = false
	identity.DeprovisionedAt = f.now
	directory.identities[identity.ID] = identity
	if op, ok := authenticator.AuthenticateOperator(request); ok {
		t.Fatalf("deprovisioned operator still authenticated as %+v; a valid token is not active employment", op)
	}
}

func TestAUD58SCIMJoinerAndLeaverAreImmutableAuthorityEvents(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	access := newAUD58AccessStore()
	mutations := &aud58MutationSink{store: access}
	rawToken := "aud58-provider-scim-secret" // #nosec G101 -- deterministic non-deployable test bearer exercises hashing/authentication (CWE-798).
	h := NewHandler(Config{
		License: providerLicense(t, 10), Mutations: mutations, Access: access,
		Clock: func() time.Time { return now },
		SCIM:  &SCIMConfig{Tokens: []SCIMToken{{Name: "entra", TokenHash: crypto.SHA256Hex([]byte(rawToken))}}},
	})

	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	createBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"entra-42","userName":"casey@example.test","displayName":"Casey","active":true,"roles":[{"value":"operator"}]}`
	created := call(http.MethodPost, "/provider/scim/v2/Users", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM joiner = %d body=%s", created.Code, created.Body.String())
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("decode SCIM joiner: id=%q err=%v body=%s", user.ID, err, created.Body.String())
	}
	identity, err := access.ResolveOperator(t.Context(), "entra-42")
	if err != nil || !identity.Active || identity.Role != OperatorOperator || identity.Source != "scim:entra" {
		t.Fatalf("projected joiner = %+v err=%v", identity, err)
	}
	// IdP retries without a custom key converge on the request-derived event id.
	if replay := call(http.MethodPost, "/provider/scim/v2/Users", createBody); replay.Code != http.StatusCreated {
		t.Fatalf("SCIM joiner replay = %d body=%s", replay.Code, replay.Body.String())
	}
	if got := len(mutations.seen); got != 1 {
		t.Fatalf("SCIM joiner replay emitted %d events, want 1", got)
	}
	defaultActiveBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"entra-43","userName":"default-active@example.test","displayName":"active","roles":[{"value":"operator"}]}`
	defaultActive := call(http.MethodPost, "/provider/scim/v2/Users", defaultActiveBody)
	if defaultActive.Code != http.StatusCreated || !strings.Contains(defaultActive.Body.String(), `"active":true`) {
		t.Fatalf("SCIM omitted active did not default true when another field contained the word: %d body=%s", defaultActive.Code, defaultActive.Body.String())
	}
	left := call(http.MethodDelete, "/provider/scim/v2/Users/"+user.ID, "")
	if left.Code != http.StatusNoContent {
		t.Fatalf("SCIM leaver = %d body=%s", left.Code, left.Body.String())
	}
	identity, err = access.ResolveOperator(t.Context(), user.ID)
	if err != nil || identity.Active || identity.DeprovisionedAt.IsZero() {
		t.Fatalf("projected leaver = %+v err=%v", identity, err)
	}
}

func TestAUD58AdminAPIGrantsListsAndRevokesExactAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	access := newAUD58AccessStore()
	access.identities["op-1"] = OperatorIdentity{ID: "op-1", Email: "admin@example.test", Role: OperatorAdmin, Active: true, Source: "scim:entra"}
	access.identities["worker-1"] = OperatorIdentity{ID: "worker-1", ExternalID: "worker-sub", Email: "worker@example.test", Role: OperatorOperator, Active: true, Source: "scim:entra"}
	store := NewMemStore()
	customerID := CustomerID("aud58-bank")
	if _, err := store.CreateTenant(t.Context(), Tenant{ID: customerID, Slug: "aud58-bank", Name: "AUD58 Bank", Status: TenantActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	secondCustomer := CustomerID("aud58-credit-union")
	if _, err := store.CreateTenant(t.Context(), Tenant{ID: secondCustomer, Slug: "aud58-credit-union", Name: "AUD58 Credit Union", Status: TenantActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	mutations := &aud58MutationSink{store: access}
	h := NewHandler(Config{
		License: providerLicense(t, 10), Store: store, Mutations: mutations, Access: access,
		Authenticator: stubAuth{accept: "Bearer real-credential"}, Delegations: access,
		Clock: func() time.Time { return now },
	})

	call := func(method, path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer real-credential")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(http.MethodGet, "/provider/v1/access/customers", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), customerID) || !strings.Contains(rec.Body.String(), secondCustomer) {
		t.Fatalf("admin access customer roster = %d body=%s", rec.Code, rec.Body.String())
	}

	expires := now.Add(8 * time.Hour).Format(time.RFC3339)
	body := `{"customer_id":"` + customerID + `","operations":["read","suspend"],"expires_at":"` + expires + `"}`
	if rec := call(http.MethodPost, "/provider/v1/operators/worker-1/delegations", body, "grant-worker-bank"); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d body=%s", rec.Code, rec.Body.String())
	}
	// An identical transport retry must converge on the same immutable command.
	if rec := call(http.MethodPost, "/provider/v1/operators/worker-1/delegations", body, "grant-worker-bank"); rec.Code != http.StatusCreated {
		t.Fatalf("grant replay status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/provider/v1/operators", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("inventory status = %d body=%s", rec.Code, rec.Body.String())
	} else if got := rec.Body.String(); !strings.Contains(got, `"source":"console"`) || !strings.Contains(got, expires) || !strings.Contains(got, `"operator_id":"worker-1"`) {
		t.Fatalf("inventory omitted source/expiry/operator: %s", got)
	}
	if rec := call(http.MethodPost, "/provider/v1/operators/worker-1/role", `{"role":"admin"}`, "promote-worker"); rec.Code != http.StatusOK {
		t.Fatalf("role change status = %d body=%s", rec.Code, rec.Body.String())
	}
	if identity, err := access.ResolveOperator(t.Context(), "worker-1"); err != nil || identity.Role != OperatorAdmin {
		t.Fatalf("projected role change = %+v err=%v", identity, err)
	}

	revokeBody := `{"customer_id":"` + customerID + `","operations":["suspend"],"reason":"IdP role changed"}`
	if rec := call(http.MethodPost, "/provider/v1/operators/worker-1/revocations", revokeBody, "revoke-worker-suspend"); rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}
	rows, err := access.ListOperatorAccess(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var revoked bool
	for _, row := range rows {
		for _, delegation := range row.Delegations {
			if delegation.OperatorID == "worker-1" && delegation.Operation == OpSuspend && !delegation.RevokedAt.IsZero() {
				revoked = true
			}
		}
	}
	if !revoked {
		t.Fatalf("revoked delegation disappeared instead of retaining revocation evidence: %+v", rows)
	}
}

type aud58SAMLProvider struct{ assertion samlsp.Assertion }

func (p aud58SAMLProvider) LoginRedirect(string) (samlsp.Redirect, error) {
	return samlsp.Redirect{URL: "https://idp.example.test/sso", RequestID: "request-1"}, nil
}
func (p aud58SAMLProvider) MetadataXML() ([]byte, error) { return []byte("<EntityDescriptor/ >"), nil }
func (p aud58SAMLProvider) VerifyResponse(*http.Request, []string) (samlsp.Assertion, error) {
	if p.assertion.Subject == "" {
		return samlsp.Assertion{}, errors.New("invalid signed assertion")
	}
	return p.assertion, nil
}

func TestAUD58SAMLSessionRechecksSCIMLifecycleOnEveryRequest(t *testing.T) {
	t.Parallel()
	access := newAUD58AccessStore()
	access.identities["saml-op"] = OperatorIdentity{
		ID: "saml-op", ExternalID: "saml-subject", Email: "saml@example.test",
		Role: OperatorAdmin, Active: true, Source: "scim:okta",
	}
	samlAuth := NewSAMLAuthenticator(SAMLAuthenticatorConfig{
		Provider: aud58SAMLProvider{assertion: samlsp.Assertion{
			Subject: "saml-subject", Issuer: "https://idp.example.test",
			Attributes: map[string][]string{"groups": {"provider-admin"}, "amr": {"mfa"}, "email": {"saml@example.test"}},
		}},
		Directory: access, RequireDirectory: true, RoleAttribute: "groups", AdminValues: []string{"provider-admin"},
		MFAAttribute: "amr", MFAValues: []string{"mfa"}, EmailAttribute: "email",
		SessionSecret: []byte("aud58-saml-session-secret-32bytes"), SessionTTL: time.Hour,
		Secure: true,
	})
	if samlAuth == nil {
		t.Fatal("fully configured provider SAML authenticator is nil")
	}

	loginReq := httptest.NewRequest(http.MethodGet, "/provider/v1/auth/saml/login", nil)
	loginRec := httptest.NewRecorder()
	samlAuth.ServeLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("SAML login = %d body=%s", loginRec.Code, loginRec.Body.String())
	}
	if state := cookieByName(loginRec.Result().Cookies(), providerSAMLStateCookie); state == nil || !state.Secure || state.SameSite != http.SameSiteNoneMode {
		t.Fatalf("SAML POST correlation cookie = %+v; cross-site ACS needs Secure SameSite=None", state)
	}
	uncorrelatedReq := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/saml/acs", strings.NewReader("SAMLResponse=valid-but-unsolicited"))
	uncorrelatedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	uncorrelatedRec := httptest.NewRecorder()
	samlAuth.ServeACS(uncorrelatedRec, uncorrelatedReq)
	if uncorrelatedRec.Code == http.StatusFound {
		t.Fatalf("SAML ACS accepted an assertion without RelayState/request-cookie correlation: %d", uncorrelatedRec.Code)
	}
	acsReq := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/saml/acs", strings.NewReader("RelayState="+cookieValueByName(loginRec.Result().Cookies(), providerSAMLStateCookie)))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range loginRec.Result().Cookies() {
		acsReq.AddCookie(cookie)
	}
	acsRec := httptest.NewRecorder()
	samlAuth.ServeACS(acsRec, acsReq)
	if acsRec.Code != http.StatusFound {
		t.Fatalf("SAML ACS = %d body=%s", acsRec.Code, acsRec.Body.String())
	}
	session := cookieByName(acsRec.Result().Cookies(), providerSessionCookie)
	if session == nil || !session.HttpOnly {
		t.Fatalf("SAML ACS did not issue an HttpOnly provider session: %+v", acsRec.Result().Cookies())
	}
	authReq := httptest.NewRequest(http.MethodGet, "/provider/v1/operators", nil)
	authReq.AddCookie(session)
	if op, ok := samlAuth.AuthenticateOperator(authReq); !ok || op.ID != "saml-op" || op.Session == "" {
		t.Fatalf("SAML provider session = %+v ok=%v", op, ok)
	}

	mutations := &aud58MutationSink{store: access}
	handler := NewHandler(Config{
		License: providerLicense(t, 10), Access: access, Mutations: mutations,
		Authenticator: samlAuth, SAML: samlAuth, Idempotency: orchestrator.NewMemoryIdempotency(),
		Clock: func() time.Time { return time.Now().UTC() },
	})
	roleRequest := func(withCSRF bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/operators/saml-op/role", strings.NewReader(`{"role":"operator"}`))
		req.AddCookie(session)
		req.Header.Set("Idempotency-Key", "saml-role-change")
		if withCSRF {
			csrf := cookieByName(acsRec.Result().Cookies(), providerCSRFCookie)
			if csrf == nil {
				t.Fatal("SAML ACS did not issue the double-submit CSRF cookie")
			}
			req.AddCookie(csrf)
			req.Header.Set(providerCSRFHeader, csrf.Value)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := roleRequest(false); rec.Code != http.StatusForbidden {
		t.Fatalf("SAML session mutation without CSRF = %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if rec := roleRequest(true); rec.Code != http.StatusOK {
		t.Fatalf("SAML session mutation with CSRF = %d body=%s", rec.Code, rec.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/logout", nil)
	logoutReq.AddCookie(session)
	csrf := cookieByName(acsRec.Result().Cookies(), providerCSRFCookie)
	logoutReq.AddCookie(csrf)
	logoutReq.Header.Set(providerCSRFHeader, csrf.Value)
	logoutReq.Header.Set("Idempotency-Key", "saml-logout")
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("SAML logout = %d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	if op, ok := samlAuth.AuthenticateOperator(authReq); ok {
		t.Fatalf("revoked SAML session remained usable as %+v", op)
	}
	logoutReplayReq := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/logout", nil)
	logoutReplayReq.AddCookie(session)
	logoutReplayReq.AddCookie(csrf)
	logoutReplayReq.Header.Set(providerCSRFHeader, csrf.Value)
	logoutReplayReq.Header.Set("Idempotency-Key", "saml-logout")
	logoutReplayRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutReplayRec, logoutReplayReq)
	if logoutReplayRec.Code != http.StatusNoContent {
		t.Fatalf("SAML logout replay = %d body=%s, want original 204", logoutReplayRec.Code, logoutReplayRec.Body.String())
	}

	// Mint a fresh session so the request-time SCIM leaver check is proved
	// independently from explicit logout revocation.
	freshLoginRec := httptest.NewRecorder()
	samlAuth.ServeLogin(freshLoginRec, loginReq)
	freshACSReq := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/saml/acs",
		strings.NewReader("RelayState="+cookieValueByName(freshLoginRec.Result().Cookies(), providerSAMLStateCookie)))
	freshACSReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range freshLoginRec.Result().Cookies() {
		freshACSReq.AddCookie(cookie)
	}
	acsRec = httptest.NewRecorder()
	samlAuth.ServeACS(acsRec, freshACSReq)
	session = cookieByName(acsRec.Result().Cookies(), providerSessionCookie)
	authReq = httptest.NewRequest(http.MethodGet, "/provider/v1/operators", nil)
	authReq.AddCookie(session)

	identity := access.identities["saml-op"]
	identity.Active = false
	identity.DeprovisionedAt = time.Now().UTC()
	access.identities[identity.ID] = identity
	if op, ok := samlAuth.AuthenticateOperator(authReq); ok {
		t.Fatalf("deprovisioned SAML session remained usable as %+v", op)
	}
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func cookieValueByName(cookies []*http.Cookie, name string) string {
	if cookie := cookieByName(cookies, name); cookie != nil {
		return cookie.Value
	}
	return ""
}
