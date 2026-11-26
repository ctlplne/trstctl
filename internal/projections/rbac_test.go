// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

func newRBACServer(t *testing.T, custom ...authz.Role) *httptest.Server {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)),
		api.WithRoles(custom...), api.WithInsecureHeaderResolver(), api.WithSecrets(api.SecretsBackend{}))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv
}

func ownerBody() map[string]any { return map[string]any{"kind": "service", "name": "svc"} }

// TestRBACViewerCannotWrite: a viewer may read but not write.
func TestRBACViewerCannotWrite(t *testing.T) {
	srv := newRBACServer(t)

	if st, _, body := do(t, srv, "GET", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "viewer"}); st != http.StatusOK {
		t.Fatalf("viewer GET owners = %d, want 200: %s", st, body)
	}
	st, hdr, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "viewer", idem: "v1", body: ownerBody()})
	if st != http.StatusForbidden {
		t.Fatalf("viewer POST owners = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)
}

// TestRBACAdminCanWrite: admin may write.
func TestRBACAdminCanWrite(t *testing.T) {
	srv := newRBACServer(t)
	if st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "admin", idem: "a1", body: ownerBody()}); st != http.StatusCreated {
		t.Fatalf("admin POST owners = %d, want 201: %s", st, body)
	}
}

// TestRBACUnauthenticatedDenied: no roles means no access.
func TestRBACUnauthenticatedDenied(t *testing.T) {
	srv := newRBACServer(t)
	// Explicit empty roles (the helper only defaults to admin when roles is the
	// zero value AND we don't override; here we force "none").
	st, hdr, body := do(t, srv, "GET", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "none"})
	if st != http.StatusForbidden {
		t.Fatalf("unknown role GET = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)
}

// TestRBACScopeEnforced: a project-scoped operator is allowed only within its
// project. The project's slug is a validated target; X-Project cannot turn a
// tenant-wide owner mutation into a project-scoped action.
func TestRBACScopeEnforced(t *testing.T) {
	srv := newRBACServer(t)

	// A project-scoped operator creates only the project named by the body.
	if st, _, body := do(t, srv, "POST", "/api/v1/secrets/projects", reqOpts{
		tenant: tenantA, roles: "operator", roleProject: "alpha", project: "beta", idem: "s1",
		body: map[string]any{"slug": "alpha", "environments": []map[string]string{{"slug": "dev"}}},
	}); st != http.StatusCreated {
		t.Fatalf("operator in-scope POST = %d, want 201: %s", st, body)
	}
	// Header "alpha" cannot authorize a different target slug.
	st, hdr, body := do(t, srv, "POST", "/api/v1/secrets/projects", reqOpts{
		tenant: tenantA, roles: "operator", roleProject: "alpha", project: "alpha", idem: "s2",
		body: map[string]any{"slug": "beta", "environments": []map[string]string{{"slug": "dev"}}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("operator out-of-scope POST = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)
	// A tenant-wide owner target is not covered by a project-scoped grant.
	if st, _, _ := do(t, srv, "POST", "/api/v1/owners", reqOpts{
		tenant: tenantA, roles: "operator", roleProject: "alpha", project: "alpha", idem: "s3", body: ownerBody(),
	}); st != http.StatusForbidden {
		t.Fatalf("operator tenant-wide target = %d, want 403", st)
	}
}

// TestRBACCustomRole: a custom role grants exactly its permissions.
func TestRBACCustomRole(t *testing.T) {
	deployer := authz.Role{Name: "deployer", Permissions: []authz.Permission{authz.IdentitiesRead, authz.IdentitiesWrite}}
	srv := newRBACServer(t, deployer)

	// An admin creates the owner the identity will belong to.
	_, _, ob := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "admin", idem: "o1", body: ownerBody()})
	ownerID := decode(t, ob)["id"].(string)

	// The deployer may create an identity...
	st, _, body := do(t, srv, "POST", "/api/v1/identities", reqOpts{
		tenant: tenantA, roles: "deployer", idem: "d1",
		body: map[string]any{"kind": "x509_certificate", "name": "svc.acme", "owner_id": ownerID},
	})
	if st != http.StatusCreated {
		t.Fatalf("deployer POST identities = %d, want 201: %s", st, body)
	}
	// ...but not an owner.
	st, hdr, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, roles: "deployer", idem: "d2", body: ownerBody()})
	if st != http.StatusForbidden {
		t.Fatalf("deployer POST owners = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)
}
