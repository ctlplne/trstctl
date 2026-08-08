// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
)

// Delegation ENFORCEMENT on the served provider plane (epic L1).
//
// delegation.go held the rule and delegation_test.go tested the rule. Nothing
// called it: no served route consulted a delegation set, so an authenticated
// operator still reached every customer. These tests drive the HTTP surface,
// because a rule that is only true in a unit test is the defect, not the fix.

// twoCustomerHandler serves a plane where alpha's operator is delegated alpha
// and nothing else, and both customers exist.
func twoCustomerHandler(t *testing.T, delegations DelegationSource) (http.Handler, *MemStore) {
	t.Helper()
	store := NewMemStore()
	now := fixedClock()()
	for _, id := range []string{"tenant-alpha", "tenant-beta"} {
		if _, err := store.CreateTenant(context.Background(), Tenant{
			ID: id, Slug: strings.TrimPrefix(id, "tenant-"), Name: id,
			Status: TenantActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         store,
		Audit:         &captureAudit{},
		Clock:         fixedClock(),
		Authenticator: stubAuth{accept: "Bearer real-credential"},
		Delegations:   delegations,
	})
	return h, store
}

func providerRequest(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer real-credential")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The cross-customer refusal, on the wire.
//
// An operator delegated one customer must not be able to suspend or offboard
// another by naming it in the path. This is the single worst thing a provider
// plane can do: one customer's engineer interrupting or DESTROYING another
// customer's tenancy, with a credential that is entirely valid.
func TestADelegatedOperatorCannotTouchACustomerTheyWereNotGiven(t *testing.T) {
	t.Parallel()
	h, store := twoCustomerHandler(t, fullyDelegated("op-1", "tenant-alpha"))

	for _, action := range []string{"suspend", "offboard"} {
		rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-beta/"+action, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s of an undelegated customer = %d, want 403.\n\n"+
				"An operator delegated only tenant-alpha reached tenant-beta. Authentication answers "+
				"WHO an operator is; it must never answer WHICH CUSTOMERS they may touch.\nbody: %s",
				action, rec.Code, rec.Body.String())
		}
		tenant, err := store.Tenant(context.Background(), "tenant-beta")
		if err != nil {
			t.Fatalf("read beta: %v", err)
		}
		if tenant.Status != TenantActive {
			t.Fatalf("tenant-beta status is %q after a refused %s; the refusal must happen before "+
				"the store is written, or the audit trail says refused while the customer is down",
				tenant.Status, action)
		}
	}
}

// The delegated customer still works, so the refusal above is scope and not a
// plane that refuses everything.
func TestTheDelegatedCustomerIsStillReachable(t *testing.T) {
	t.Parallel()
	h, store := twoCustomerHandler(t, fullyDelegated("op-1", "tenant-alpha"))
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-alpha/suspend", "")
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent && rec.Code != http.StatusAccepted {
		t.Fatalf("suspend of the DELEGATED customer = %d, want success: %s", rec.Code, rec.Body.String())
	}
	tenant, err := store.Tenant(context.Background(), "tenant-alpha")
	if err != nil {
		t.Fatalf("read alpha: %v", err)
	}
	if tenant.Status != TenantSuspended {
		t.Fatalf("tenant-alpha status = %q, want suspended", tenant.Status)
	}
}

// Operations are delegated separately, because they carry different blast
// radii. An operator trusted to suspend — interrupt a live service, reversibly
// — is not thereby trusted to offboard, which destroys.
func TestSuspendDoesNotImplyOffboard(t *testing.T) {
	t.Parallel()
	h, store := twoCustomerHandler(t, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpSuspend}},
	})
	if rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-alpha/suspend", ""); rec.Code >= 400 {
		t.Fatalf("suspend with the suspend grant = %d: %s", rec.Code, rec.Body.String())
	}
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-alpha/offboard", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("offboard with only a SUSPEND grant = %d, want 403.\n\n"+
			"Suspending interrupts a live service and is reversible; offboarding destroys. Folding "+
			"them into one permission means every operator who can pause a customer can erase "+
			"one.\nbody: %s", rec.Code, rec.Body.String())
	}
	tenant, _ := store.Tenant(context.Background(), "tenant-alpha")
	if tenant.Status == TenantOffboarded {
		t.Fatal("the customer was offboarded by an operator holding only a suspend grant")
	}
}

// No delegation source configured refuses everything. An absent source read as
// "everything is permitted" is exactly the unscoped access this replaces.
func TestAnAbsentDelegationSourceRefusesEveryOperator(t *testing.T) {
	t.Parallel()
	h, _ := twoCustomerHandler(t, nil)
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-alpha/suspend", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("with no delegation source at all, suspend = %d, want 403.\n"+
			"A provider plane that authorises everybody until somebody wires delegations is the "+
			"state this epic exists to end.\nbody: %s", rec.Code, rec.Body.String())
	}
}

// A delegation source that ERRORS refuses too. Serving on an unreadable grant
// table would make the plane widest exactly when it is least healthy.
type brokenDelegations struct{}

func (brokenDelegations) Delegations(context.Context) (*DelegationSet, error) {
	return nil, errors.New("grant table unreachable")
}

func TestAnUnreadableDelegationSourceRefusesRatherThanServes(t *testing.T) {
	t.Parallel()
	h, _ := twoCustomerHandler(t, brokenDelegations{})
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants/tenant-alpha/suspend", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("with an erroring delegation source, suspend = %d, want 403.\n"+
			"Failing OPEN on a read error means an outage in the grant store silently widens every "+
			"operator to every customer.\nbody: %s", rec.Code, rec.Body.String())
	}
}

// The customer list is scoped too.
//
// An unfiltered list hands every operator the provider's whole customer roster
// — a disclosure on its own, and the reconnaissance step for the cross-customer
// action above: you cannot ask to suspend a tenancy you cannot name.
func TestTheTenantListShowsOnlyDelegatedCustomers(t *testing.T) {
	t.Parallel()
	h, _ := twoCustomerHandler(t, fullyDelegated("op-1", "tenant-alpha"))
	rec := providerRequest(t, h, http.MethodGet, "/provider/v1/tenants", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "tenant-beta") {
		t.Fatalf("an operator delegated only tenant-alpha was shown tenant-beta:\n%s\n\n"+
			"The customer roster is the provider's commercial information and the map an operator "+
			"would need to attempt a cross-customer action.", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "tenant-alpha") {
		t.Fatalf("the operator's OWN delegated customer is missing from the list:\n%s", rec.Body.String())
	}
}

// Break-glass is its own grant, and it is re-checked when the grant is USED.
//
// Checking only at request time means revoking a delegation stops future
// requests but not the access an operator already holds — revocation that only
// works on people who have not already asked is not revocation.
func TestBreakGlassIsRecheckedAtUseNotOnlyAtRequest(t *testing.T) {
	t.Parallel()
	store := NewMemStore()
	now := fixedClock()()
	if _, err := store.CreateTenant(context.Background(), Tenant{
		ID: "tenant-alpha", Slug: "alpha", Name: "Alpha",
		Status: TenantActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	audit := &captureAudit{}
	// A source whose answer can be revoked between request and use.
	revocable := &mutableDelegations{set: fullyDelegated("op-1", "tenant-alpha")}
	svc := NewService(Config{
		License:     providerLicense(t, 10),
		Store:       store,
		Audit:       audit,
		Telemetry:   &auditCheckingTelemetry{audit: audit},
		Clock:       fixedClock(),
		Delegations: revocable,
	})
	op := providerOperator("op-1")
	ctx := context.Background()

	grant, err := svc.RequestBreakGlass(ctx, op, BreakGlassRequest{
		TenantID: "tenant-alpha", Reason: "tenant requested emergency diagnosis", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("request break-glass while delegated: %v", err)
	}
	if _, err := svc.ConsentBreakGlass(ctx, "tenant-alpha", grant.ID, "customer-admin", true); err != nil {
		t.Fatalf("consent: %v", err)
	}
	// L4 dual consent: a second distinct approver is required before the grant
	// is active and this revocation test is meaningful.
	if _, err := svc.ConsentBreakGlass(ctx, "tenant-alpha", grant.ID, "customer-admin-2", true); err != nil {
		t.Fatalf("co-consent: %v", err)
	}

	// The customer revokes the operator's delegation.
	revocable.set = StaticDelegations{}

	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("using a consented grant after the delegation was revoked returned %v, want "+
			"ErrForbidden.\n\nA grant issued while delegated must not survive the delegation. "+
			"Otherwise revocation reaches only the operators who had not already asked.", err)
	}
}

type mutableDelegations struct{ set StaticDelegations }

func (m *mutableDelegations) Delegations(ctx context.Context) (*DelegationSet, error) {
	return m.set.Delegations(ctx)
}

// Provisioning is scoped to the customer id that WILL be created, so an
// operator cannot conjure a tenancy of any name — including one colliding with
// a real customer's.
func TestProvisioningIsScopedToTheCustomerBeingCreated(t *testing.T) {
	t.Parallel()
	h, _ := twoCustomerHandler(t, StaticDelegations{
		{OperatorID: "op-1", CustomerID: CustomerID("permitted"), Operations: []Operation{OpProvision}},
	})
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants",
		`{"slug":"not-permitted","name":"Not Permitted"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("provisioning an undelegated customer id = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	ok := providerRequest(t, h, http.MethodPost, "/provider/v1/tenants",
		`{"slug":"permitted","name":"Permitted"}`)
	if ok.Code != http.StatusCreated {
		t.Fatalf("provisioning the DELEGATED customer id = %d, want 201: %s", ok.Code, ok.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(ok.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// recordingRevoker is a delegation source that can also revoke, so a test can
// observe whether offboarding cleared the grants.
type recordingRevoker struct {
	set     StaticDelegations
	cleared []string
}

func (r *recordingRevoker) Delegations(ctx context.Context) (*DelegationSet, error) {
	return r.set.Delegations(ctx)
}

func (r *recordingRevoker) RevokeAllForCustomer(_ context.Context, customerID string) error {
	r.cleared = append(r.cleared, customerID)
	var kept StaticDelegations
	for _, d := range r.set {
		if d.CustomerID != customerID {
			kept = append(kept, d)
		}
	}
	r.set = kept
	return nil
}

// Offboarding a customer clears the grants over it.
//
// Tenant ids here are derived from the slug, so a grant that outlived the
// tenancy would hand a REUSED slug to whoever held access on the old customer —
// silently, and with the audit trail showing only a normal provisioning.
func TestOffboardingACustomerClearsTheGrantsOverIt(t *testing.T) {
	t.Parallel()
	src := &recordingRevoker{set: fullyDelegated("op-1", "tenant-alpha", "tenant-beta")}
	store := NewMemStore()
	now := fixedClock()()
	for _, id := range []string{"tenant-alpha", "tenant-beta"} {
		if _, err := store.CreateTenant(context.Background(), Tenant{
			ID: id, Slug: strings.TrimPrefix(id, "tenant-"), Name: id,
			Status: TenantActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	svc := NewService(Config{
		License: providerLicense(t, 10), Store: store, Audit: &captureAudit{},
		Clock: fixedClock(), Delegations: src,
	})
	op := providerOperator("op-1")
	if err := svc.Offboard(context.Background(), op, "tenant-alpha"); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if len(src.cleared) != 1 || src.cleared[0] != "tenant-alpha" {
		t.Fatalf("offboarding cleared %v, want [tenant-alpha].\n\n"+
			"Grants over a destroyed tenancy are dangling authority: reusing the slug restores "+
			"that access with nothing in the system saying so.", src.cleared)
	}
	// The other customer's grants are untouched.
	set, _ := src.Delegations(context.Background())
	if err := set.Authorize(op, "tenant-beta", OpSuspend); err != nil {
		t.Fatalf("offboarding one customer revoked another's grants: %v", err)
	}
	if err := set.Authorize(op, "tenant-alpha", OpSuspend); err == nil {
		t.Fatal("the offboarded customer's grant survived")
	}
}

// Suspending does NOT clear grants. A suspended customer is expected back, and
// an operator who has to be re-granted to resume one is an operator who will be
// granted more than they had.
func TestSuspendingDoesNotClearGrants(t *testing.T) {
	t.Parallel()
	src := &recordingRevoker{set: fullyDelegated("op-1", "tenant-alpha")}
	store := NewMemStore()
	now := fixedClock()()
	if _, err := store.CreateTenant(context.Background(), Tenant{
		ID: "tenant-alpha", Slug: "alpha", Name: "Alpha",
		Status: TenantActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewService(Config{
		License: providerLicense(t, 10), Store: store, Audit: &captureAudit{},
		Clock: fixedClock(), Delegations: src,
	})
	if err := svc.Suspend(context.Background(), providerOperator("op-1"), "tenant-alpha"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if len(src.cleared) != 0 {
		t.Fatalf("suspending cleared grants for %v; a suspended customer is expected back", src.cleared)
	}
}

// The delegation check runs BEFORE the store is asked.
//
// Asserting only on the error message was not enough: MemStore refuses every
// direct snapshot anyway, so a version that queried first and checked after
// still produced the delegation message and the test passed. What has to be
// true is that the STORE IS NEVER TOUCHED for an undelegated customer —
// otherwise a timing or side-effect difference discloses whether that customer
// exists at all.
type recordingStore struct {
	Store
	snapshotsFor []string
}

func (r *recordingStore) DirectTenantSnapshot(ctx context.Context, tenantID string) (TenantSnapshot, error) {
	r.snapshotsFor = append(r.snapshotsFor, tenantID)
	return r.Store.DirectTenantSnapshot(ctx, tenantID)
}

func TestTheDelegationCheckRunsBeforeTheStoreIsAsked(t *testing.T) {
	t.Parallel()
	store := &recordingStore{Store: NewMemStore()}
	svc := NewService(Config{
		License: providerLicense(t, 10), Store: store, Audit: &captureAudit{},
		Clock: fixedClock(), Delegations: fullyDelegated("op-1", "tenant-alpha"),
	})
	op := providerOperator("op-1")
	_, err := svc.DirectTenantSnapshot(context.Background(), op, "tenant-beta")
	if err == nil {
		t.Fatal("an undelegated direct snapshot succeeded")
	}
	if len(store.snapshotsFor) != 0 {
		t.Fatalf("the store was queried for %v on behalf of an operator not delegated it.\n\n"+
			"The refusal must land before the store is touched: anything the query does — timing, "+
			"a cache warm, a log line — discloses whether that customer exists.", store.snapshotsFor)
	}
	if !strings.Contains(err.Error(), "not delegated customer tenant-beta") {
		t.Fatalf("refusal was %q; it should name the missing delegation, because "+
			"\"you are not delegated this customer\" and \"direct reads are never served\" need "+
			"different people to fix them", err)
	}
}

// Quota administration behind the same gate (epic L2).
//
// A cap is a provisioning-class act on a customer, so it obeys the delegation
// partition exactly as provision/suspend do: an operator holding alpha must
// not set — or even read — beta's caps.
func TestQuotaAdministrationObeysTheDelegationPartition(t *testing.T) {
	t.Parallel()
	quotas := &memQuotaStore{}
	h, _ := twoCustomerHandlerWithQuotas(t, fullyDelegated("op-1", "tenant-alpha"), quotas)

	// The delegated customer: set then read back.
	rec := providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-alpha/quota",
		`{"max_certificates_stored": 25}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set quota on the delegated customer = %d: %s", rec.Code, rec.Body.String())
	}
	if got := quotas.byTenant["tenant-alpha"]; got == nil || *got.MaxCertificatesStored != 25 {
		t.Fatalf("the cap never reached the store: %+v", quotas.byTenant)
	}
	if quotas.byTenant["tenant-alpha"].TenantID != "tenant-alpha" {
		t.Fatal("the stored row's tenant did not come from the authorized path")
	}
	rec = providerRequest(t, h, http.MethodGet, "/provider/v1/tenants/tenant-alpha/quota", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("read quota = %d", rec.Code)
	}

	// The OTHER customer: both verbs refused, and the store untouched.
	rec = providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-beta/quota",
		`{"max_certificates_stored": 1}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("set quota on an undelegated customer = %d, want 403.\n\n"+
			"A cap is a denial-of-service lever: an operator who can set another customer's "+
			"certificate limit to 1 can stop their issuance cold with a valid credential.", rec.Code)
	}
	if _, ok := quotas.byTenant["tenant-beta"]; ok {
		t.Fatal("the refused write reached the store anyway")
	}
	if rec := providerRequest(t, h, http.MethodGet, "/provider/v1/tenants/tenant-beta/quota", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("read of an undelegated customer's quota = %d, want 403 — a cap discloses "+
			"commercial terms", rec.Code)
	}

	// A body naming another tenant must not redirect the write: the PATH the
	// operator was authorized against wins.
	rec = providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-alpha/quota",
		`{"tenant_id": "tenant-beta", "max_agents": 1}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set with body tenant_id = %d", rec.Code)
	}
	if _, ok := quotas.byTenant["tenant-beta"]; ok {
		t.Fatal("a body tenant_id redirected an authorized write onto an unauthorized customer.\n\n" +
			"That turns an authorization on one tenancy into a write on another — the same shape " +
			"as the evidence route's customer_id refusal, one plane up.")
	}
}

// memQuotaStore records what the plane wrote, keyed by tenant.
type memQuotaStore struct {
	byTenant map[string]*billing.Quota
}

func (m *memQuotaStore) QuotaFor(_ context.Context, tenantID string) (billing.Quota, error) {
	if m.byTenant == nil {
		return billing.Quota{TenantID: tenantID}, nil
	}
	if q, ok := m.byTenant[tenantID]; ok {
		return *q, nil
	}
	return billing.Quota{TenantID: tenantID}, nil
}

func (m *memQuotaStore) SetQuota(_ context.Context, q billing.Quota) error {
	if m.byTenant == nil {
		m.byTenant = map[string]*billing.Quota{}
	}
	copied := q
	m.byTenant[q.TenantID] = &copied
	return nil
}

func twoCustomerHandlerWithQuotas(t *testing.T, delegations DelegationSource, quotas QuotaStore) (http.Handler, *MemStore) {
	t.Helper()
	store := NewMemStore()
	now := fixedClock()()
	for _, id := range []string{"tenant-alpha", "tenant-beta"} {
		if _, err := store.CreateTenant(context.Background(), Tenant{
			ID: id, Slug: strings.TrimPrefix(id, "tenant-"), Name: id,
			Status: TenantActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         store,
		Audit:         &captureAudit{},
		Clock:         fixedClock(),
		Authenticator: stubAuth{accept: "Bearer real-credential"},
		Delegations:   delegations,
		Quotas:        quotas,
	})
	return h, store
}
