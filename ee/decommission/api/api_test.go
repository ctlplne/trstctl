// SPDX-License-Identifier: LicenseRef-trstctl-EE

// These tests exist because the capabilities they cover were COMPLETE and
// UNREACHABLE (AUD-2, AUD-3): the retirement checklist source had no production
// caller, so the served route answered 501 on every deployment, and the
// re-protection outbox handler had no producer, so the pipeline behind it could
// never receive one job. Both tests therefore drive the REAL wiring end to end —
// the factory the attach seam mounts, the served HTTP routes, a real PostgreSQL
// read model, and (for re-protection) the real outbox swept into the real
// licensed handler. A test that injected fakes at the option seam would pass on
// the broken tree; these cannot.
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	eedecommission "trstctl.com/trstctl/ee/decommission"
	decapi "trstctl.com/trstctl/ee/decommission/api"
	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/reprotect"
	decstore "trstctl.com/trstctl/ee/decommission/store"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-vdec-api-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(port).
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

// freePort reserves an ephemeral TCP port and returns it as the uint32 the
// embedded-postgres builder takes, so no caller needs a width conversion.
func freePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p <= 0 || p > math.MaxUint16 {
		panic(fmt.Sprintf("freePort: listener reported out-of-range TCP port %d", p))
	}
	return uint32(p)
}

func openStoreOn(t *testing.T, dbName string) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	base, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin open: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "DROP DATABASE IF EXISTS "+dbName); err != nil {
		t.Fatalf("drop db: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create db: %v", err)
	}
	base.Close()
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/" + dbName
	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(decstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(cs.Close)
	return cs
}

var vdecRole = authz.Role{Name: "vdec-operator", Permissions: []authz.Permission{authz.KeysRead, authz.KeysWrite}}

// newServedAPI assembles the core API exactly the way the server does for a
// VDEC-licensed deployment: the licensed options come from the SAME factory the
// attach seam mounts, over the same store and outbox.
func newServedAPI(t *testing.T, cs *corestore.Store, outbox *orchestrator.Outbox) *api.API {
	t.Helper()
	factory := decapi.NewAPIOptionsFactory()
	licensed, err := factory(editionseam.LicensedAPIOptionsDeps{Store: cs, Outbox: outbox})
	if err != nil {
		t.Fatalf("api options factory: %v", err)
	}
	principal := authz.Principal{TenantID: tenantA, Subject: "op", Grants: []authz.Grant{{Role: vdecRole, Scope: authz.Scope{TenantID: tenantA}}}}
	opts := append([]api.Option{
		api.WithRoles(vdecRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	}, licensed...)
	idem := orchestrator.NewIdempotency(cs)
	return api.New(cs, idem, nil, opts...)
}

func mustEncode(t *testing.T, p depstate.Payload, seq uint64) eventspec.Event {
	t.Helper()
	e, err := depstate.Encode(p)
	if err != nil {
		t.Fatalf("Encode(%T): %v", p, err)
	}
	e.Sequence = seq
	return e
}

func dep(class depstate.DependentClass, id string) depstate.Dependent {
	return depstate.Dependent{Class: class, ID: id}
}

// seedKeyState rebuilds the tenant read model with key-a carrying three
// registered dependents, one of which is already re-protected: two remain
// unaccounted.
func seedKeyState(t *testing.T, cs *corestore.Store) {
	t.Helper()
	repo := decstore.New(cs)
	events := []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "key-a", Dependent: dep(depstate.DependentCiphertext, "ct-1")}, 10),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "key-a", Dependent: dep(depstate.DependentWrappedKey, "wrap-1")}, 11),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "key-a", Dependent: dep(depstate.DependentCiphertext, "ct-2")}, 12),
		mustEncode(t, depstate.ReprotectionCompletedV1{TenantID: tenantA, KeyID: "key-a", JobID: "job-ct-2", Dependent: dep(depstate.DependentCiphertext, "ct-2"), SuccessorKeyID: "key-b"}, 13),
	}
	if err := repo.RebuildTenant(context.Background(), tenantA, events); err != nil {
		t.Fatalf("rebuild tenant: %v", err)
	}
}

// TestRetirementChecklist_ServedFromReadModel is the AUD-3 regression: the
// checklist route must answer 200 from the real read model when the licensed
// factory is applied, and keep refusing 501 when it is not. A handler-level test
// injecting a fake source could not catch the missing production caller.
func TestRetirementChecklist_ServedFromReadModel(t *testing.T) {
	cs := openStoreOn(t, "vdec_api_checklist")
	seedKeyState(t, cs)
	served := newServedAPI(t, cs, orchestrator.NewOutbox(cs))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/key-a/retirement", nil)
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("licensed GET retirement = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var got api.RetirementChecklist
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode checklist: %v", err)
	}
	if !got.Blocked {
		t.Fatal("checklist with unaccounted dependents must report blocked=true")
	}
	if got.Total != 3 || got.Accounted != 1 || len(got.Outstanding) != 2 {
		t.Fatalf("checklist = total %d accounted %d outstanding %d, want 3/1/2 (body=%s)", got.Total, got.Accounted, len(got.Outstanding), rr.Body.String())
	}
	refs := map[string]string{}
	for _, o := range got.Outstanding {
		refs[o.Ref] = o.Kind
	}
	if refs["ct-1"] != string(depstate.DependentCiphertext) || refs["wrap-1"] != string(depstate.DependentWrappedKey) {
		t.Fatalf("outstanding rows = %v, want ct-1 (ciphertext) and wrap-1 (wrapped_key)", got.Outstanding)
	}

	// Direction check: an unlicensed API (no factory options) must refuse with
	// 501, never serve an empty checklist.
	principal := authz.Principal{TenantID: tenantA, Subject: "op", Grants: []authz.Grant{{Role: vdecRole, Scope: authz.Scope{TenantID: tenantA}}}}
	unlicensed := api.New(cs, orchestrator.NewIdempotency(cs), nil,
		api.WithRoles(vdecRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }))
	rr = httptest.NewRecorder()
	unlicensed.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/key-a/retirement", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("unlicensed GET retirement = %d, want 501", rr.Code)
	}
}

func TestRetirementRequestRejectsCallerAssertedQuorumClassAndOperators(t *testing.T) {
	cs := openStoreOn(t, "vdec_api_retirement_authority")
	served := newServedAPI(t, cs, orchestrator.NewOutbox(cs))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/key-a/retirement", strings.NewReader(
		`{"final_epoch":7,"confirm_irreversible":true,"key_class":"bypass","approvals":["other-operator"]}`,
	))
	req.Header.Set("Idempotency-Key", "retirement-forged-authority")
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("caller-asserted retirement authority = %d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

// TestReprotection_StartFlowsThroughOutboxToLicensedHandler is the AUD-2
// regression, and it must go through the outbox: POST plans jobs for exactly the
// unaccounted dependents, records them as outbox rows, and a dispatcher sweep
// hands BOTH rows to the SAME licensed handler the attach seam mounts
// (handled=true). The pre-fix tree fails here twice over: no route, and no
// producer for the handler to receive from.
func TestReprotection_StartFlowsThroughOutboxToLicensedHandler(t *testing.T) {
	cs := openStoreOn(t, "vdec_api_reprotect")
	seedKeyState(t, cs)
	outbox := orchestrator.NewOutbox(cs)
	served := newServedAPI(t, cs, outbox)

	post := func(idemKey string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/key-a/reprotect", nil)
		req.Header.Set("Idempotency-Key", idemKey)
		rr := httptest.NewRecorder()
		served.ServeHTTP(rr, req)
		return rr
	}

	first := post("start-1")
	if first.Code != http.StatusAccepted {
		t.Fatalf("POST reprotect = %d body=%s, want 202", first.Code, first.Body.String())
	}
	var receipt decapi.ReprotectionReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.Planned != 2 || receipt.Enqueued != 2 {
		t.Fatalf("receipt planned=%d enqueued=%d, want 2/2 (body=%s)", receipt.Planned, receipt.Enqueued, first.Body.String())
	}

	// A replayed start under a NEW idempotency key re-plans the same jobs and
	// enqueues none of them again: job identity is the stable per-dependent key,
	// not the HTTP header.
	second := post("start-2")
	if second.Code != http.StatusAccepted {
		t.Fatalf("replayed POST reprotect = %d, want 202", second.Code)
	}
	var replay decapi.ReprotectionReceipt
	if err := json.Unmarshal(second.Body.Bytes(), &replay); err != nil {
		t.Fatalf("decode replay receipt: %v", err)
	}
	if replay.Planned != 2 || replay.Enqueued != 0 {
		t.Fatalf("replay planned=%d enqueued=%d, want 2/0", replay.Planned, replay.Enqueued)
	}

	// Sweep the outbox through the handler built by the SAME factory
	// attachVerifiableDecommission mounts. Reaching DeliverLicensed with
	// handled=true for both rows is the reachability the audit found missing;
	// executor-substrate errors (no transit boundary here) are the documented
	// fail-closed delivery-time state, not a routing failure.
	runtime, err := eedecommission.NewRuntime(eedecommission.RuntimeConfig{Store: cs})
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	handler, err := runtime.ReprotectionOutboxFactory(editionseam.LicensedOutboxDeps{Store: cs})
	if err != nil {
		t.Fatalf("outbox factory: %v", err)
	}
	var mu sync.Mutex
	reached := map[string]bool{}
	sweep := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		handled, err := handler.DeliverLicensed(ctx, m)
		if !handled {
			return fmt.Errorf("licensed handler did not own destination %q", m.Destination)
		}
		mu.Lock()
		reached[m.IdempotencyKey] = true
		mu.Unlock()
		if err != nil && errors.Is(err, reprotect.ErrExecutorUnavailable) {
			return nil // reached the executor stage; substrate absence is expected here
		}
		return err
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := outbox.Dispatch(context.Background(), sweep); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		mu.Lock()
		n := len(reached)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox sweep delivered %d re-protection jobs to the licensed handler, want 2", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReprotection_UnknownKeyRefuses pins the not-found direction: a key with no
// recorded dependency state is an explicit 404, never an empty success — "we
// know of nothing to do" and "nothing is recorded" are different answers.
func TestReprotection_UnknownKeyRefuses(t *testing.T) {
	cs := openStoreOn(t, "vdec_api_unknown")
	served := newServedAPI(t, cs, orchestrator.NewOutbox(cs))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/nope/reprotect", nil)
	req.Header.Set("Idempotency-Key", "start-x")
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("POST reprotect unknown key = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
}
