// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// a221SCIM drives the Provider SCIM handler and an OIDC authenticator over one
// directory, the way an IdP and an operator's browser reach the same server.
type a221SCIM struct {
	t     *testing.T
	h     http.Handler
	token string
	oidc  *OIDCAuthenticator
	f     oidcFixture
}

func newA221SCIM(t *testing.T, access OperatorAccessStore, mutations MutationSink, clock func() time.Time) *a221SCIM {
	t.Helper()
	f := newOIDCFixture(t)
	token := "a221-provider-scim-secret" // #nosec G101 -- deterministic non-deployable test bearer exercises hashing/authentication (CWE-798).
	h := NewHandler(Config{
		License: providerLicense(t, 10), Mutations: mutations, Access: access, Clock: clock,
		SCIM: &SCIMConfig{Tokens: []SCIMToken{{Name: "okta", TokenHash: crypto.SHA256Hex([]byte(token))}}},
	})
	oidc := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer: "https://idp.provider.example", Audience: "trstctl-provider",
		JWKS: f.auth.cfg.JWKS, RoleClaim: "groups", AdminValues: []string{"trstctl-admins"},
		MFAClaim: "amr", MFAValues: []string{"mfa"}, Now: func() time.Time { return f.now },
		Directory: access, RequireDirectory: true,
	})
	return &a221SCIM{t: t, h: h, token: token, oidc: oidc, f: f}
}

func (s *a221SCIM) call(method, path, body string) *httptest.ResponseRecorder {
	s.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+s.token)
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

// create provisions a user the way Okta and Entra do: without roles, with
// membership pushed separately.
func (s *a221SCIM) create(externalID string) string {
	s.t.Helper()
	rec := s.call(http.MethodPost, "/provider/scim/v2/Users", `{"schemas":["`+scim.SchemaUser+`"],"externalId":"`+externalID+
		`","userName":"`+externalID+`@example.test","active":true}`)
	if rec.Code != http.StatusCreated {
		s.t.Fatalf("create %s = %d %s", externalID, rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"roles"`) {
		s.t.Fatalf("a user created without roles shows roles: %s", rec.Body.String())
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil || user.ID == "" {
		s.t.Fatalf("decode %s: %v %s", externalID, err, rec.Body.String())
	}
	return user.ID
}

func (s *a221SCIM) patch(group, operations string) *httptest.ResponseRecorder {
	s.t.Helper()
	return s.call(http.MethodPatch, "/provider/scim/v2/Groups/"+group, `{"schemas":["`+scim.SchemaPatchOp+`"],"Operations":`+operations+`}`)
}

func (s *a221SCIM) members(group string) []string {
	s.t.Helper()
	rec := s.call(http.MethodGet, "/provider/scim/v2/Groups/"+group, "")
	var body scim.Group
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		s.t.Fatalf("get group %s = %d %s", group, rec.Code, rec.Body.String())
	}
	out := []string{}
	for _, member := range body.Members {
		out = append(out, member.Value)
	}
	slices.Sort(out)
	return out
}

func (s *a221SCIM) signIn(externalID string) (Operator, bool) {
	claims := s.f.baseClaims()
	claims["sub"] = externalID
	return s.oidc.AuthenticateOperator(s.f.request(s.t, s.f.signer, "idp-k1", claims))
}

func addMembers(ids ...string) string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, `{"value":"`+id+`"}`)
	}
	return `[{"op":"add","path":"members","value":[` + strings.Join(values, ",") + `]}]`
}

func sortedIDs(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

// A221: removing an operator from a Provider role group through SCIM revokes
// the role with a provider.operator.role_revoked audit event, in the shapes
// Okta and Entra send; replace and PUT revoke whoever they leave out and give
// the role to whoever they name; operations apply in order; the revoked
// operator's still-valid OIDC token is refused on its next request.
func TestProviderSCIMGroupRemovalRevokesTheRole(t *testing.T) {
	t.Parallel()
	access := newAUD58AccessStore()
	mutations := &aud58MutationSink{store: access}
	s := newA221SCIM(t, access, mutations, func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) })
	revocations := func() []AuthorityEvent {
		t.Helper()
		var out []AuthorityEvent
		for _, event := range mutations.seen {
			if event.Type != EventOperatorRoleRevoked {
				continue
			}
			var payload AuthorityEvent
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				t.Fatal(err)
			}
			out = append(out, payload)
		}
		return out
	}

	casey := s.create("okta-casey")
	if _, ok := s.signIn("okta-casey"); ok {
		t.Fatal("an operator holding no role signed in")
	}
	if rec := s.patch("admin", addMembers(casey)); rec.Code != http.StatusOK {
		t.Fatalf("add casey = %d %s", rec.Code, rec.Body.String())
	}
	if op, ok := s.signIn("okta-casey"); !ok || op.Role != OperatorAdmin {
		t.Fatalf("casey after the group add = %+v %v; want admin", op, ok)
	}

	// Okta's remove: a members filter.
	remove := `[{"op":"remove","path":"members[value eq \"` + casey + `\"]"}]`
	if rec := s.patch("admin", remove); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), casey) {
		t.Fatalf("remove casey = %d %s; want 200 and the group without casey", rec.Code, rec.Body.String())
	}
	if identity, err := access.ResolveOperator(t.Context(), casey); err != nil || identity.Role != "" || !identity.Active {
		t.Fatalf("casey after the remove = %+v %v; want active with no role", identity, err)
	}
	if op, ok := s.signIn("okta-casey"); ok {
		t.Fatalf("the revoked operator's still-valid token signed in as %+v", op)
	}
	revoked := revocations()
	if len(revoked) != 1 || revoked[0].Operator == nil || revoked[0].Operator.Role != "" || revoked[0].Audit.Subject != casey ||
		revoked[0].Audit.OperatorID != "scim:okta" || !strings.Contains(revoked[0].Audit.Reason, "provider-admin") {
		t.Fatalf("role revocation events = %+v; want one naming casey, the group and the SCIM token", revoked)
	}
	before := len(mutations.seen)
	if rec := s.patch("admin", remove); rec.Code != http.StatusOK || len(mutations.seen) != before {
		t.Fatalf("retried remove = %d with %d new events; want 200 and none", rec.Code, len(mutations.seen)-before)
	}
	// An IdP's user update that names no role keeps the revocation.
	if rec := s.call(http.MethodPut, "/provider/scim/v2/Users/"+casey, `{"schemas":["`+scim.SchemaUser+
		`"],"externalId":"okta-casey","userName":"okta-casey@example.test","displayName":"Casey","active":true}`); rec.Code != http.StatusOK {
		t.Fatalf("user update after the revocation = %d %s", rec.Code, rec.Body.String())
	}
	if identity, _ := access.ResolveOperator(t.Context(), casey); identity.Role != "" || identity.DisplayName != "Casey" {
		t.Fatalf("casey after a role-less update = %+v; want the update without a role", identity)
	}

	// Entra's remove: op casing, path members and a value array.
	dana := s.create("entra-dana")
	if rec := s.patch("operator", addMembers(dana)); rec.Code != http.StatusOK {
		t.Fatalf("add dana = %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.patch("operator", `[{"op":"Remove","path":"members","value":[{"$ref":null,"value":"`+dana+`"}]}]`); rec.Code != http.StatusOK {
		t.Fatalf("Entra remove = %d %s", rec.Code, rec.Body.String())
	}
	if identity, _ := access.ResolveOperator(t.Context(), dana); identity.Role != "" || len(revocations()) != 2 {
		t.Fatalf("dana after Entra's remove = %+v (%d revocations); want no role", identity, len(revocations()))
	}

	// Replace and PUT: whoever they leave out loses the role, whoever they name
	// gains it, and a member named by external id is the same operator.
	erin, frank, gail := s.create("erin"), s.create("frank"), s.create("gail")
	if rec := s.patch("operator", addMembers(erin, frank)); rec.Code != http.StatusOK {
		t.Fatalf("add erin and frank = %d %s", rec.Code, rec.Body.String())
	}
	before = len(mutations.seen)
	if rec := s.patch("operator", `[{"op":"replace","path":"members","value":[{"value":"`+frank+`"},{"value":"gail"}]}]`); rec.Code != http.StatusOK {
		t.Fatalf("replace = %d %s", rec.Code, rec.Body.String())
	}
	if got := s.members("operator"); !slices.Equal(got, sortedIDs(frank, gail)) || len(mutations.seen) != before+2 {
		t.Fatalf("after replace members = %v with %d events; want frank and gail, erin revoked and gail added", got, len(mutations.seen)-before)
	}
	if rec := s.call(http.MethodPut, "/provider/scim/v2/Groups/operator", `{"schemas":["`+scim.SchemaGroup+
		`"],"displayName":"provider-operator","members":[{"value":"`+gail+`"}]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT group = %d %s", rec.Code, rec.Body.String())
	}
	if got := s.members("operator"); !slices.Equal(got, []string{gail}) {
		t.Fatalf("after PUT members = %v; want gail alone", got)
	}
	if identity, _ := access.ResolveOperator(t.Context(), frank); identity.Role != "" {
		t.Fatalf("frank after the PUT left him out = %+v; want no role", identity)
	}

	// Operations apply in order, a member to add that resolves to nobody refuses
	// the whole change, and a member to remove that is not there changes nothing.
	harry := s.create("harry")
	before = len(mutations.seen)
	if rec := s.patch("operator", `[{"op":"add","path":"members","value":[{"value":"`+harry+`"}]},{"op":"remove","path":"members[value eq \"`+harry+`\"]"}]`); rec.Code != http.StatusOK ||
		len(mutations.seen) != before || slices.Contains(s.members("operator"), harry) {
		t.Fatalf("add then remove = %d with %d events; want no change", rec.Code, len(mutations.seen)-before)
	}
	if rec := s.patch("operator", `[{"op":"remove","path":"members[value eq \"`+gail+`\"]"},{"op":"add","path":"members","value":[{"value":"nobody"}]}]`); rec.Code != http.StatusNotFound ||
		!slices.Contains(s.members("operator"), gail) {
		t.Fatalf("a change naming an unknown member = %d %s; want 404 with gail kept", rec.Code, rec.Body.String())
	}
	if rec := s.patch("operator", `[{"op":"remove","path":"members[value eq \"nobody\"]"}]`); rec.Code != http.StatusOK || len(mutations.seen) != before {
		t.Fatalf("removing an unknown member = %d %s; want 200 and nothing recorded", rec.Code, rec.Body.String())
	}
	// A remove of members with neither filter nor value empties the group.
	if rec := s.patch("operator", `[{"op":"remove","path":"members"}]`); rec.Code != http.StatusOK || len(s.members("operator")) != 0 {
		t.Fatalf("remove all = %d %s; want an empty group", rec.Code, rec.Body.String())
	}

	// Entra finds a group by its display name.
	list := s.call(http.MethodGet, "/provider/scim/v2/Groups?filter="+url.QueryEscape(`displayName eq "provider-admin"`), "")
	var groups scim.ListResponse
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &groups) != nil || groups.TotalResults != 1 ||
		!strings.Contains(list.Body.String(), `"id":"admin"`) {
		t.Fatalf("groups filtered by displayName = %d %s; want provider-admin alone", list.Code, list.Body.String())
	}
}

// A221: the role revocation is an authority event the PostgreSQL projection
// applies and a rebuild from the event history reproduces, and the PostgreSQL
// directory row it leaves refuses the operator's OIDC sign-in.
func TestProviderSCIMGroupRemovalIsDurable(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	access := NewPGAccessStore(st)
	s := newA221SCIM(t, access, runtime.Mutations, func() time.Time { return time.Now().UTC() })

	casey := s.create("okta-casey")
	if rec := s.patch("admin", addMembers(casey)); rec.Code != http.StatusOK {
		t.Fatalf("add casey = %d %s", rec.Code, rec.Body.String())
	}
	if op, ok := s.signIn("okta-casey"); !ok || op.Role != OperatorAdmin {
		t.Fatalf("casey after the group add = %+v %v; want admin", op, ok)
	}
	if rec := s.patch("admin", `[{"op":"remove","path":"members[value eq \"`+casey+`\"]"}]`); rec.Code != http.StatusOK {
		t.Fatalf("remove casey = %d %s", rec.Code, rec.Body.String())
	}
	check := func(when string) {
		t.Helper()
		identity, err := access.ResolveOperator(ctx, casey)
		if err != nil || identity.Role != "" || !identity.Active {
			t.Fatalf("%s: casey = %+v %v; want active with no role", when, identity, err)
		}
		if op, ok := s.signIn("okta-casey"); ok {
			t.Fatalf("%s: the revoked operator signed in as %+v", when, op)
		}
	}
	check("after the remove")
	truncateProviderAuthority(t, st)
	if err := projections.New(st, projections.WithEventProjection(NewAuthorityProjection(st))).Project(ctx, log); err != nil {
		t.Fatalf("rebuild from the event history: %v", err)
	}
	check("after a rebuild from the event history")
}
