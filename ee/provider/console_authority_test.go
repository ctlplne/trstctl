// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type consoleAuthorityAuth struct{ operator Operator }

type consoleAuthorityResponse struct {
	Available      bool `json:"available"`
	AccessRead     bool `json:"access_read"`
	AccessWrite    bool `json:"access_write"`
	Provision      bool `json:"provision"`
	IsolationDrill bool `json:"isolation_drill"`
	Customers      map[string]struct {
		ReadQuota  bool `json:"read_quota"`
		WriteQuota bool `json:"write_quota"`
		WriteBrand bool `json:"write_brand"`
		Suspend    bool `json:"suspend"`
		Offboard   bool `json:"offboard"`
	} `json:"customers"`
}

func (a consoleAuthorityAuth) AuthenticateOperator(*http.Request) (Operator, bool) {
	return a.operator, true
}

func readConsoleAuthority(t *testing.T, h http.Handler) consoleAuthorityResponse {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/provider/v1/auth/session", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated session = %d: %s", w.Code, w.Body.String())
	}
	var session struct {
		ID        string                    `json:"id"`
		Authority *consoleAuthorityResponse `json:"authority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.ID != "op-1" || session.Authority == nil {
		t.Fatalf("session must preserve verified identity and report effective authority: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-beta") {
		t.Fatalf("another operator's customer leaked through session authority: %s", w.Body.String())
	}
	return *session.Authority
}

func TestConsoleAuthorityLimitedOperatorCannotInheritAdministrativeActions(t *testing.T) {
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorOperator, MFA: true}},
		Delegations: StaticDelegations{
			{OperatorID: "op-1", CustomerID: "alpha", Operations: []Operation{OpRead, OpProvision, OpSuspend, OpOffboard}},
			{OperatorID: "op-2", CustomerID: "private-beta", Operations: Operations},
		},
		Quotas: &memQuotaStore{}, Brands: &memBrandStore{},
	})
	a := readConsoleAuthority(t, h)
	if !a.Available || a.AccessRead || a.AccessWrite || a.Provision || a.IsolationDrill {
		t.Fatalf("limited operator has administrative authority: %+v", a)
	}
	c := a.Customers["alpha"]
	if len(a.Customers) != 1 || !c.ReadQuota || c.WriteQuota || c.WriteBrand || c.Suspend || c.Offboard {
		t.Fatalf("role ceiling was not applied to customer grants: %+v", a.Customers)
	}
}

func TestConsoleAuthorityUsesCurrentExactCustomerOperations(t *testing.T) {
	grants := &mutableDelegations{set: StaticDelegations{
		{OperatorID: "op-1", CustomerID: "alpha", Operations: []Operation{OpRead, OpSuspend}},
		{OperatorID: "op-2", CustomerID: "private-beta", Operations: Operations},
	}}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorAdmin, MFA: true}},
		Delegations:   grants, Quotas: &memQuotaStore{}, Brands: &memBrandStore{},
	})
	a := readConsoleAuthority(t, h)
	c := a.Customers["alpha"]
	if !a.Available || !c.ReadQuota || !c.Suspend || c.Offboard || c.WriteQuota || c.WriteBrand || a.Provision || a.IsolationDrill || a.AccessRead {
		t.Fatalf("authority did not match exact grants and attached services: %+v", a)
	}
	grants.set = StaticDelegations{}
	if after := readConsoleAuthority(t, h); !after.Available || len(after.Customers) != 0 || after.Provision {
		t.Fatalf("revoked customer authority survived the next session read: %+v", after)
	}
}

func TestConsoleAuthorityUnavailableGrantsPreserveAuthenticationAndDenyControls(t *testing.T) {
	for _, source := range []DelegationSource{nil, brokenDelegations{}} {
		h := NewHandler(Config{
			License:       providerLicense(t, 10),
			Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorAdmin, MFA: true}},
			Delegations:   source,
		})
		a := readConsoleAuthority(t, h)
		if a.Available || len(a.Customers) != 0 || a.AccessRead || a.AccessWrite || a.Provision || a.IsolationDrill {
			t.Fatalf("unavailable authority enabled controls: %+v", a)
		}
	}
}

func TestConsoleAuthorityWithoutMFADeniesControls(t *testing.T) {
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorAdmin, MFA: false}},
		Delegations:   fullyDelegated("op-1", "alpha"),
	})
	a := readConsoleAuthority(t, h)
	if len(a.Customers) != 0 || a.AccessRead || a.AccessWrite || a.Provision || a.IsolationDrill {
		t.Fatalf("missing MFA still enabled controls: %+v", a)
	}
}

func TestConsoleAuthorityIsNotServedWithoutProviderEntitlement(t *testing.T) {
	h := NewHandler(Config{
		Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorAdmin, MFA: true}},
		Delegations:   fullyDelegated("op-1", "alpha"),
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/provider/v1/auth/session", nil))
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "op-1") {
		t.Fatalf("unlicensed session exposed Provider authority: %d %s", w.Code, w.Body.String())
	}
}

func TestConsoleAuthorityFullyAttachedAdminCanUseGrantedControls(t *testing.T) {
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: consoleAuthorityAuth{Operator{ID: "op-1", Role: OperatorAdmin, MFA: true}},
		Delegations:   fullyDelegated("op-1", "alpha"),
		Access:        newAUD58AccessStore(), Quotas: &memQuotaStore{}, Brands: &memBrandStore{}, Drills: &stubDriller{},
	})
	a := readConsoleAuthority(t, h)
	c := a.Customers["alpha"]
	if !a.Available || !a.AccessRead || !a.AccessWrite || !a.Provision || !a.IsolationDrill ||
		!c.ReadQuota || !c.WriteQuota || !c.WriteBrand || !c.Suspend || !c.Offboard {
		t.Fatalf("fully authorized administrator lost a supported control: %+v %+v", a, c)
	}
}
