package query_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/query"
)

// admin can read every surface; viewer can read everything except the audit log;
// auditor can read only the log. Used to exercise the RBAC gate without a store.
func adminPrincipal(tenant string) authz.Principal {
	return authz.Principal{TenantID: tenant, Subject: "admin",
		Grants: []authz.Grant{{Role: authz.BuiltinRoles()["admin"], Scope: authz.Scope{TenantID: tenant}}}}
}
func viewerPrincipal(tenant string) authz.Principal {
	return authz.Principal{TenantID: tenant, Subject: "viewer",
		Grants: []authz.Grant{{Role: authz.BuiltinRoles()["viewer"], Scope: authz.Scope{TenantID: tenant}}}}
}

// These run entirely in validate()/authorize(), before any read, so they need no
// store — exactly the "fails closed before execution" property the design requires.
func newValidationEngine() *query.Engine {
	return query.New(nil, nil, nil, query.Config{MaxRows: 10, MaxDepth: 4, Timeout: time.Second})
}

func TestUnknownSurfaceFailsClosed(t *testing.T) {
	e := newValidationEngine()
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{Select: []query.Surface{"secrets"}})
	if !errors.Is(err, query.ErrMalformed) {
		t.Fatalf("unknown surface should be malformed, got %v", err)
	}
}

func TestInjectionViaFieldFailsClosed(t *testing.T) {
	e := newValidationEngine()
	// A crafted field name must be rejected at compile time — no statement runs.
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceOwners},
		Where:  []query.Predicate{{Field: "owners.name; DROP TABLE owners;--", Op: query.OpEq, Value: "x"}},
	})
	if !errors.Is(err, query.ErrMalformed) {
		t.Fatalf("crafted field must fail closed, got %v", err)
	}
}

func TestUnknownOperatorFailsClosed(t *testing.T) {
	e := newValidationEngine()
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceOwners},
		Where:  []query.Predicate{{Field: query.FieldOwnerName, Op: "like", Value: "x"}},
	})
	if !errors.Is(err, query.ErrMalformed) {
		t.Fatalf("unknown operator must fail closed, got %v", err)
	}
}

func TestPredicateOnUnselectedSurfaceFailsClosed(t *testing.T) {
	e := newValidationEngine()
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceOwners},
		Where:  []query.Predicate{{Field: query.FieldCBOMAlgorithm, Op: query.OpEq, Value: "RSA"}},
	})
	if !errors.Is(err, query.ErrMalformed) {
		t.Fatalf("predicate on an unselected surface must fail closed, got %v", err)
	}
}

func TestEmptySelectFailsClosed(t *testing.T) {
	e := newValidationEngine()
	if _, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{}); !errors.Is(err, query.ErrMalformed) {
		t.Fatalf("empty select must fail closed, got %v", err)
	}
}

func TestLimitOverBudgetFailsClosed(t *testing.T) {
	e := newValidationEngine() // MaxRows 10
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceOwners}, Limit: 11,
	})
	if !errors.Is(err, query.ErrCostExceeded) {
		t.Fatalf("over-budget limit must trip the cost guard, got %v", err)
	}
}

func TestDepthOverBudgetFailsClosed(t *testing.T) {
	e := newValidationEngine() // MaxDepth 4
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceGraph}, MaxDepth: 99,
	})
	if !errors.Is(err, query.ErrCostExceeded) {
		t.Fatalf("over-budget depth must trip the cost guard, got %v", err)
	}
}

func TestRBACOutOfScopeDeniedAtLayer(t *testing.T) {
	e := newValidationEngine()
	// A viewer lacks audit:read, so selecting the log surface is denied before any
	// read executes — denial at this layer, not post-filtering.
	_, err := e.Query(context.Background(), viewerPrincipal("t1"), query.Spec{
		Select: []query.Surface{query.SurfaceLog},
	})
	if !errors.Is(err, query.ErrForbidden) {
		t.Fatalf("viewer querying the audit log must be forbidden, got %v", err)
	}
	// And a principal with no grants is denied any surface.
	none := authz.Principal{TenantID: "t1"}
	if _, err := e.Query(context.Background(), none, query.Spec{Select: []query.Surface{query.SurfaceOwners}}); !errors.Is(err, query.ErrForbidden) {
		t.Fatalf("ungranted principal must be forbidden, got %v", err)
	}
}

func TestBackpressureRejectsWhenPoolSaturated(t *testing.T) {
	// One worker, a one-slot queue. Occupy the worker (taskA) and fill the queue
	// (taskB); the pool is now saturated, so the engine's submit must fast-reject.
	pool := bulkhead.New(bulkhead.Config{Name: "query", Workers: 1, Queue: 1})
	defer pool.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	if err := pool.Submit(func() { close(started); <-release }); err != nil {
		t.Fatalf("taskA should be accepted: %v", err)
	}
	<-started // the single worker is now busy
	if err := pool.Submit(func() { <-release }); err != nil {
		t.Fatalf("taskB should fill the queue: %v", err)
	}

	e := query.New(nil, nil, pool, query.Config{MaxRows: 10, MaxDepth: 4, Timeout: time.Second})
	_, err := e.Query(context.Background(), adminPrincipal("t1"), query.Spec{Select: []query.Surface{query.SurfaceOwners}})
	if !errors.Is(err, query.ErrRejected) {
		t.Fatalf("a saturated pool must fast-reject with ErrRejected, got %v", err)
	}
	close(release)
}
