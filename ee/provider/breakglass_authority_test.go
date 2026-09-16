// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

// An authenticated name is not permission to approve or veto another
// customer's emergency request. Drive the served handler and inspect the
// stored grant, so a refusal after a partial mutation cannot pass.
func TestBreakGlassConsentRequiresCurrentCustomerAuthority(t *testing.T) {
	for _, approve := range []bool{true, false} {
		for _, name := range []string{"no-mfa", "no-role", "no-grant", "other-customer", "read-only-grant", "unavailable-grants", "license-read-only"} {
			t.Run(fmt.Sprintf("%s/approve=%t", name, approve), func(t *testing.T) {
				svc := breakGlassService(t)
				grant := requestGrant(t, svc)
				actor := providerOperator("unrelated")
				svc.delegations = fullyDelegated(actor.ID, "tenant-x")
				switch name {
				case "no-mfa":
					actor.MFA = false
				case "no-role":
					actor.Role = ""
				case "no-grant":
					svc.delegations = StaticDelegations{}
				case "other-customer":
					svc.delegations = fullyDelegated(actor.ID, "tenant-other")
				case "read-only-grant":
					svc.delegations = StaticDelegations{{OperatorID: actor.ID, CustomerID: "tenant-x", Operations: []Operation{OpRead}}}
				case "unavailable-grants":
					svc.delegations = brokenDelegations{}
				case "license-read-only":
					svc.license = readOnlyConsentLicense(t)
				}
				svc.authenticator = consoleAuthorityAuth{operator: actor}
				h := &handler{svc: svc}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/provider/v1/breakglass/"+grant.ID+"/consent",
					strings.NewReader(fmt.Sprintf(`{"tenant_id":"tenant-x","approve":%t}`, approve))))
				if w.Code != http.StatusForbidden {
					t.Errorf("unqualified consent = %d/%s, want 403", w.Code, w.Body.String())
				}
				after, err := svc.store.BreakGlassGrant(context.Background(), grant.ID)
				if err != nil {
					t.Fatal(err)
				}
				if after.State(svc.clock()) != GrantPending || after.ConsentedBy != "" || after.DeniedBy != "" {
					t.Fatalf("refused approval changed grant: %+v", after)
				}
			})
		}
	}
}

func readOnlyConsentLicense(t *testing.T) *license.Manager {
	t.Helper()
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	raw, err := license.Sign(license.Claims{V: 1, ID: "consent-read-only", Customer: "QA", Tier: license.TierProvider,
		IssuedAt: now.Add(-90 * 24 * time.Hour), ExpiresAt: now.Add(-license.GracePeriod - time.Hour)}, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := license.Load(path, [][]byte{public})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Mode(license.FeatureProviderPlane) != license.ModeReadOnly {
		t.Fatal("fixture must be past the full-function grace period")
	}
	return manager
}

func TestBreakGlassConsentRechecksDelegationsBeforeEachDecision(t *testing.T) {
	svc := breakGlassService(t)
	grant := requestGrant(t, svc)
	ctx := context.Background()
	if _, err := svc.ConsentBreakGlass(ctx, providerOperator("approver-a"), "tenant-x", grant.ID, true); err != nil {
		t.Fatal(err)
	}
	svc.delegations = StaticDelegations{}
	for _, approve := range []bool{true, false} {
		if _, err := svc.ConsentBreakGlass(ctx, providerOperator("approver-b"), "tenant-x", grant.ID, approve); err == nil {
			t.Fatalf("revoked approver changed grant with approve=%t", approve)
		}
	}
	after, err := svc.store.BreakGlassGrant(ctx, grant.ID)
	if err != nil || after.State(svc.clock()) != GrantAwaitingCoConsent || after.ConsentedBy != "approver-a" {
		t.Fatalf("refusal must preserve the existing first consent: %+v, %v", after, err)
	}
	svc.delegations = fullyDelegated("approver-b", "tenant-x")
	after, err = svc.ConsentBreakGlass(ctx, providerOperator("approver-b"), "tenant-x", grant.ID, true)
	if err != nil || after.State(svc.clock()) != GrantActive {
		t.Fatalf("newly authorized distinct approver must still activate access: %+v, %v", after, err)
	}
}
