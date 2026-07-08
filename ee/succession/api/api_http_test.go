// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/ee/succession"
	succapi "trstctl.com/trstctl/ee/succession/api"
	"trstctl.com/trstctl/ee/succession/retirement"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantA  = "11111111-1111-1111-1111-111111111111"
	identity = "spiffe://d/id"
)

var testDSN string

func TestMain(m *testing.M) {
	if os.Getenv("PCAS_API_SKIP_PG") == "1" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "trstctl-pcas-api-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)).
		RuntimePath(dir + "/rt").DataPath(dir + "/data").BinariesPath(dir + "/bin").
		Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func openStore(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return cs
}

// fakeService records calls so the HTTP contract can be asserted without a database.
type fakeService struct {
	mu           sync.Mutex
	requestCalls int
	lastReq      succapi.RequestSuccessionRequest
	lastAck      succapi.AckRequest
	chainRecords [][]byte
}

func (f *fakeService) RequestSuccession(_ context.Context, _ string, req succapi.RequestSuccessionRequest) (succapi.RequestSuccessionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestCalls++
	f.lastReq = req
	return succapi.RequestSuccessionResponse{
		RequestID: fmt.Sprintf("req-%d", f.requestCalls), IdentityID: req.IdentityID,
		CredentialType: req.CredentialType, TargetAlgorithm: req.TargetAlgorithm, Status: "queued",
	}, nil
}

func (f *fakeService) FetchChain(_ context.Context, _, identityID string) (succapi.ChainResponse, error) {
	return succapi.ChainResponse{IdentityID: identityID, Records: f.chainRecords, Count: len(f.chainRecords)}, nil
}

func (f *fakeService) RecordAck(_ context.Context, _ string, req succapi.AckRequest) (succapi.AckResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAck = req
	return succapi.AckResponse{AckID: "ack-1", IdentityID: req.IdentityID, Epoch: req.Epoch, RelyingParty: req.RelyingParty, RecordedAt: time.Now()}, nil
}

func (f *fakeService) ConfigureDelegationScope(_ context.Context, _ string, req succapi.DelegationScopeRequest) (succapi.DelegationScopeResponse, error) {
	return succapi.DelegationScopeResponse{ScopeID: req.ScopeID, ParentScopeID: req.ParentScopeID, EpochFloor: req.EpochFloor, Status: "configured", UpdatedAt: time.Now()}, nil
}

func (f *fakeService) RaiseDelegationFloor(_ context.Context, _ string, req succapi.DelegationFloorRequest) (succapi.DelegationScopeResponse, error) {
	return succapi.DelegationScopeResponse{ScopeID: req.ScopeID, EpochFloor: req.EpochFloor, Status: "raised", UpdatedAt: time.Now()}, nil
}

func (f *fakeService) ConfigureRecoveryPolicy(_ context.Context, _ string, req succapi.RecoveryPolicyRequest) (succapi.RecoveryPolicyResponse, error) {
	return succapi.RecoveryPolicyResponse{IdentityID: req.IdentityID, Status: "configured", UpdatedAt: time.Now()}, nil
}

func (f *fakeService) RequestRecovery(_ context.Context, _ string, req succapi.RecoveryRequest) (succapi.AsyncRequestResponse, error) {
	return succapi.AsyncRequestResponse{RequestID: "recovery-1", Status: "queued", QueuedAt: time.Now(), IdentityID: req.IdentityID}, nil
}

func (f *fakeService) RequestFederationImport(_ context.Context, _ string, req succapi.FederationImportRequest) (succapi.AsyncRequestResponse, error) {
	return succapi.AsyncRequestResponse{RequestID: "federation-1", Status: "queued", QueuedAt: time.Now(), Target: req.ForeignDeploymentID, IdentityID: req.IdentityID}, nil
}

func (f *fakeService) RequestKEMRewrap(_ context.Context, _ string, req succapi.KEMRewrapRequest) (succapi.AsyncRequestResponse, error) {
	return succapi.AsyncRequestResponse{RequestID: "kem-1", Status: "queued", QueuedAt: time.Now(), IdentityID: req.IdentityID}, nil
}

func (f *fakeService) RegisterIssuerAuthority(_ context.Context, _ string, req succapi.IssuerAuthorityRequest) (succapi.IssuerAuthorityResponse, error) {
	return succapi.IssuerAuthorityResponse{IssuerID: req.IssuerID, IdentityID: req.IdentityID, CurrentEpoch: req.CurrentEpoch, CAKeyHandle: req.CAKeyHandle, Status: "registered", UpdatedAt: time.Now()}, nil
}

func (f *fakeService) IssueIssuerLeaf(_ context.Context, _ string, req succapi.IssueLeafRequest) (succapi.IssueLeafResponse, error) {
	return succapi.IssueLeafResponse{IssuerID: req.IssuerID, IdentityID: identity, Epoch: 1, RotationVersion: req.RotationVersion, CertDER: []byte("cert"), IssuedAt: time.Now()}, nil
}

func (f *fakeService) IssueStapledLeaf(_ context.Context, _ string, req succapi.IssueStapledLeafRequest) (succapi.IssueLeafResponse, error) {
	return succapi.IssueLeafResponse{IssuerID: req.IssuerID, IdentityID: identity, Epoch: 1, CertDER: []byte("cert"), IssuedAt: time.Now()}, nil
}

func (f *fakeService) RewrapStatus(_ context.Context, _ string, identityID string, predecessorEpoch uint64) (succapi.RewrapStatusResponse, error) {
	return succapi.RewrapStatusResponse{IdentityID: identityID, PredecessorEpoch: predecessorEpoch, Jobs: []succapi.RewrapJobState{}, Complete: true, CheckedAt: time.Now()}, nil
}

func (f *fakeService) ConfigureRetirementPolicy(_ context.Context, _ string, req succapi.RetirementPolicyRequest) (succapi.RetirementPolicyResponse, error) {
	return succapi.RetirementPolicyResponse{IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch, Threshold: req.Threshold, Roster: req.Roster, Status: "active", UpdatedAt: time.Now()}, nil
}

func (f *fakeService) RetirementStatus(_ context.Context, _ string, identityID string, predecessorEpoch uint64) (succapi.RetirementPolicyResponse, bool, error) {
	return succapi.RetirementPolicyResponse{IdentityID: identityID, PredecessorEpoch: predecessorEpoch, Threshold: 1, Status: "active", UpdatedAt: time.Now(), RewrapComplete: true}, true, nil
}

func (f *fakeService) LatestCheckpoint(_ context.Context, _, identityID string) (succapi.CheckpointResponse, bool, error) {
	return succapi.CheckpointResponse{IdentityID: identityID, Epoch: 1, IssuedAt: time.Now()}, true, nil
}

func (f *fakeService) PostureReport(_ context.Context, _, identityID string) (succapi.PostureReportResponse, bool, error) {
	return succapi.PostureReportResponse{IdentityID: identityID, TenantID: tenantA, Algorithm: "ECDSA-P256", Epoch: 1, Signature: []byte("sig"), IssuedAt: time.Now()}, true, nil
}

func (f *fakeService) ListMisissuance(context.Context, string) (succapi.MisissuanceListResponse, error) {
	return succapi.MisissuanceListResponse{Findings: []succapi.MisissuanceResponse{}, Count: 0}, nil
}

var pcasRole = authz.Role{Name: "pcas-operator", Permissions: []authz.Permission{authz.CertsWrite, authz.CertsRead}}

func newAPI(t *testing.T, svc succapi.Service) *api.API {
	t.Helper()
	cs := openStore(t)
	idem := orchestrator.NewIdempotency(cs)
	principal := authz.Principal{TenantID: tenantA, Subject: "op", Grants: []authz.Grant{{Role: pcasRole, Scope: authz.Scope{TenantID: tenantA}}}}
	opts := []api.Option{
		api.WithLicensedRoutes(succapi.Routes(svc)...),
		api.WithRoles(pcasRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	}
	return api.New(cs, idem, nil, opts...)
}

// TestRequestSuccession_Idempotent: a replayed Idempotency-Key returns the original
// result and the service mints the request exactly once (claim 6).
func TestRequestSuccession_Idempotent(t *testing.T) {
	svc := &fakeService{}
	a := newAPI(t, svc)
	body := `{"identity_id":"spiffe://d/id","credential_type":"x509","target_algorithm":"ML-DSA-65"}`

	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/successions", bytes.NewBufferString(body))
		r.Header.Set("Idempotency-Key", "key-1")
		rr := httptest.NewRecorder()
		a.ServeHTTP(rr, r)
		return rr
	}
	first := do()
	if first.Code != http.StatusAccepted {
		t.Fatalf("first POST = %d body=%s, want 202", first.Code, first.Body.String())
	}
	second := do()
	if second.Code != http.StatusAccepted {
		t.Fatalf("replay POST = %d, want 202", second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("idempotent replay returned a different body:\n%s\n%s", first.Body.String(), second.Body.String())
	}
	if svc.requestCalls != 1 {
		t.Fatalf("service invoked %d times, want exactly 1 (idempotent)", svc.requestCalls)
	}
}

// TestRequestSuccession_MissingIdempotencyKey: a mutation without Idempotency-Key is
// refused (AN-5).
func TestRequestSuccession_MissingIdempotencyKey(t *testing.T) {
	a := newAPI(t, &fakeService{})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/successions", bytes.NewBufferString(`{"identity_id":"x","credential_type":"x509","target_algorithm":"ML-DSA-65"}`))
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing Idempotency-Key = %d, want 400", rr.Code)
	}
}

// TestIdentityTypes_X509_SSH_SVID_Token_Secret: every claim-9 credential type
// round-trips the API end-to-end; a type outside the genus is rejected (claim 9).
func TestIdentityTypes_X509_SSH_SVID_Token_Secret(t *testing.T) {
	svc := &fakeService{}
	a := newAPI(t, svc)
	for i, ct := range []string{"x509", "ssh", "workload-svid", "api-token", "secret"} {
		body := fmt.Sprintf(`{"identity_id":"spiffe://d/%d","credential_type":%q,"target_algorithm":"ML-DSA-65"}`, i, ct)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/successions", bytes.NewBufferString(body))
		r.Header.Set("Idempotency-Key", fmt.Sprintf("k-%s", ct))
		rr := httptest.NewRecorder()
		a.ServeHTTP(rr, r)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("credential type %q = %d body=%s, want 202", ct, rr.Code, rr.Body.String())
		}
		var resp succapi.RequestSuccessionResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.CredentialType != ct {
			t.Fatalf("credential_type round-trip = %q, want %q", resp.CredentialType, ct)
		}
	}
	// Outside the genus → 400.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/successions", bytes.NewBufferString(`{"identity_id":"x","credential_type":"kerberos","target_algorithm":"ML-DSA-65"}`))
	r.Header.Set("Idempotency-Key", "k-bad")
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("out-of-genus credential type = %d, want 400", rr.Code)
	}
}

// TestChain_Verifiable: the GET chain response decodes to records that verify with
// the succession verifier (PCAS-07's offline check) — claim 9 / acceptance 2.
func TestChain_Verifiable(t *testing.T) {
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://d", identity, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([][]byte, 0, len(sc.Records))
	for _, rec := range sc.Records {
		b, _ := json.Marshal(rec)
		encoded = append(encoded, b)
	}
	svc := &fakeService{chainRecords: encoded}
	a := newAPI(t, svc)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/pcas/chain?identity_id="+url.QueryEscape(identity), nil)
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET chain = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var resp succapi.ChainResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != len(sc.Records) {
		t.Fatalf("chain count = %d, want %d", resp.Count, len(sc.Records))
	}
	var records []succession.SuccessionRecord
	for _, b := range resp.Records {
		var rec succession.SuccessionRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("decode fetched record: %v", err)
		}
		records = append(records, rec)
	}
	if err := succession.VerifyChain(sc.Genesis, records, 0); err != nil {
		t.Fatalf("fetched chain does not verify offline (PCAS-07): %v", err)
	}
}

// TestAck_SignatureRequiredAndCountable: a signed ack is accepted and preserves the
// signature + identity/epoch binding intact, so PCAS-10 counts it; a stripped-signature
// ack is refused at ingestion (claim 3 inputs).
func TestAck_SignatureRequiredAndCountable(t *testing.T) {
	svc := &fakeService{}
	a := newAPI(t, svc)

	// Stripped signature → 400.
	noSig := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/acks", bytes.NewBufferString(`{"identity_id":"spiffe://d/id","epoch":1,"relying_party":"rp1","signature":""}`))
	noSig.Header.Set("Idempotency-Key", "ack-nosig")
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, noSig)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unsigned ack = %d, want 400", rr.Code)
	}

	// Signed ack → 202, and the captured ack is countable by the PCAS-10 quorum.
	rpKey, _ := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	sig, err := retirement.SignAck(rpKey, tenantA, identity, 1, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	ackBody, _ := json.Marshal(succapi.AckRequest{IdentityID: identity, Epoch: 1, RelyingParty: "rp1", Signature: sig})
	signed := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/acks", bytes.NewReader(ackBody))
	signed.Header.Set("Idempotency-Key", "ack-signed")
	rr2 := httptest.NewRecorder()
	a.ServeHTTP(rr2, signed)
	if rr2.Code != http.StatusAccepted {
		t.Fatalf("signed ack = %d body=%s, want 202", rr2.Code, rr2.Body.String())
	}
	// The service received the signature + identity/epoch binding intact.
	if svc.lastAck.IdentityID != identity || svc.lastAck.Epoch != 1 || svc.lastAck.RelyingParty != "rp1" || !bytes.Equal(svc.lastAck.Signature, sig) {
		t.Fatalf("ack binding not preserved through the API: %+v", svc.lastAck)
	}
	// Reconstruct the ledger ack and prove PCAS-10 counts it.
	countable := retirement.SignedAck{
		TenantID: tenantA, IdentityID: svc.lastAck.IdentityID, Epoch: svc.lastAck.Epoch,
		RelyingParty: svc.lastAck.RelyingParty, RecordedAt: time.Now(), Signature: svc.lastAck.Signature,
	}
	q := retirement.EvaluateQuorum([]retirement.SignedAck{countable},
		retirement.Target{TenantID: tenantA, IdentityID: identity, Epoch: 1},
		retirement.Roster{"rp1": rpKey.Public().DER}, retirement.QuorumPolicy{Threshold: 1}, time.Now())
	if !q.Met {
		t.Fatal("ack recorded via the API is not countable by the PCAS-10 quorum")
	}
}
