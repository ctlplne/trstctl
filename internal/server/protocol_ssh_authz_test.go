// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/ssh"
)

// newTestSSHCA builds a real signer-backed SSH CA so the served handlers run
// their genuine code paths rather than tripping over a nil dependency.
func newTestSSHCA(t *testing.T) *ssh.CA {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	ca, err := ssh.New(ssh.Config{TenantID: "tenant-a", Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// recordingSSHGuard stands in for the API mutation guard: it records the
// permission each route asks for and either refuses (what an anonymous caller
// sees) or runs the mutation for tenant-a.
type recordingSSHGuard struct {
	allow bool
	perms []authz.Permission
}

func (g *recordingSSHGuard) guard(perm authz.Permission, fn api.ProtocolMutationFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.perms = append(g.perms, perm)
		if !g.allow {
			w.Header().Set("WWW-Authenticate", `Bearer realm="trstctl"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		status, _, err := fn(r.Context(), "tenant-a", r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
	}
}

// stubSSHWorkflow records what the raw routes delegate to the product workflow.
type stubSSHWorkflow struct {
	issued  []api.SSHCertificateRequest
	revoked []api.SSHRevokeCertificateRequest
}

func (s *stubSSHWorkflow) IssueSSHCertificate(_ context.Context, _, _ string, req api.SSHCertificateRequest) (api.SSHCertificate, error) {
	s.issued = append(s.issued, req)
	return api.SSHCertificate{Certificate: "cert", Serial: 1, KeyID: req.KeyID}, nil
}

func (s *stubSSHWorkflow) RevokeSSHCertificate(_ context.Context, _, _ string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error) {
	s.revoked = append(s.revoked, req)
	return api.SSHStatus{}, nil
}

func newUnitSSHProtocol(t *testing.T, g *recordingSSHGuard, wf *stubSSHWorkflow) *sshProtocol {
	t.Helper()
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", g.guard, wf)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestServedSSHMutatingRoutesRequireTheAPIGuard is the regression guard for the
// served SSH CA's anonymous-issuance defect and for RV-08g: every mutating route
// is served through the API mutation guard, issuance under certs:issue and
// revocation under certs:write. The test drives the real mux, so it fails if a
// route is ever registered without the guard or under the wrong permission.
func TestServedSSHMutatingRoutesRequireTheAPIGuard(t *testing.T) {
	g := &recordingSSHGuard{}
	wf := &stubSSHWorkflow{}
	p := newUnitSSHProtocol(t, g, wf)

	body := `{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","key_id":"x","principals":["root"],"ttl_seconds":3600}`
	for _, route := range []struct {
		path, payload string
		perm          authz.Permission
	}{
		{"/ssh/issue/user", body, authz.CertsIssue},
		{"/ssh/issue/host", body, authz.CertsIssue},
		{"/ssh/revoke", `{"serial":1}`, authz.CertsWrite},
	} {
		t.Run(route.path, func(t *testing.T) {
			before := len(g.perms)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.payload)))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous POST %s = %d, want 401", route.path, rec.Code)
			}
			if len(g.perms) != before+1 || g.perms[before] != route.perm {
				t.Fatalf("POST %s consulted the guard for %v, want %s", route.path, g.perms[before:], route.perm)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("denial must carry an authentication challenge")
			}
		})
	}
	if len(wf.issued)+len(wf.revoked) != 0 {
		t.Fatalf("refused requests reached the workflow: %d issued, %d revoked", len(wf.issued), len(wf.revoked))
	}
}

// TestServedSSHTrustMaterialStaysPublic pins the other half of the contract: the
// two GET routes serve the material a host needs BEFORE it can authenticate
// anything (the CA public key for TrustedUserCAKeys, and the binary KRL for
// RevokedKeys), exactly like a CRL distribution point. Gating those would break
// every host bootstrap, so the fix must not over-reach.
func TestServedSSHTrustMaterialStaysPublic(t *testing.T) {
	g := &recordingSSHGuard{}
	p := newUnitSSHProtocol(t, g, &stubSSHWorkflow{})
	for _, path := range []string{"/ssh/ca", "/ssh/krl"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("GET %s must stay public: a host fetches it before it can authenticate", path)
		}
		if path == "/ssh/krl" && rec.Header().Get("X-Trstctl-Tenant-ID") != "tenant-a" {
			t.Errorf("GET /ssh/krl tenant header = %q, want served tenant", rec.Header().Get("X-Trstctl-Tenant-ID"))
		}
	}
	if len(g.perms) != 0 {
		t.Errorf("public trust routes consulted the guard %d times", len(g.perms))
	}
}

// TestServedSSHRefusesConstructionWithoutGuardOrWorkflow makes the fail-closed
// construction explicit: without the guard the CA would be anonymous again, and
// without the workflow a revocation would not be recorded.
func TestServedSSHRefusesConstructionWithoutGuardOrWorkflow(t *testing.T) {
	g := &recordingSSHGuard{}
	if _, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", nil, &stubSSHWorkflow{}); err == nil {
		t.Fatal("newSSHProtocol accepted a nil guard; the served SSH CA would be anonymous again")
	}
	if _, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", g.guard, nil); err == nil {
		t.Fatal("newSSHProtocol accepted a nil workflow; raw revocations would not be recorded")
	}
}

// TestServedSSHGuardedRequestReachesTheWorkflow proves the gate is not a blanket
// denial and that raw requests go through the product workflow with their fields.
func TestServedSSHGuardedRequestReachesTheWorkflow(t *testing.T) {
	g := &recordingSSHGuard{allow: true}
	wf := &stubSSHWorkflow{}
	p := newUnitSSHProtocol(t, g, wf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ssh/revoke", strings.NewReader(`{"serial":1,"key_id":"k"}`)))
	if rec.Code != http.StatusNoContent || len(wf.revoked) != 1 || wf.revoked[0].Serial != 1 || wf.revoked[0].KeyID != "k" {
		t.Fatalf("guarded revoke = %d, workflow saw %+v", rec.Code, wf.revoked)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ssh/issue/host", strings.NewReader(`{"public_key":"k","key_id":"h","principals":["web-1"]}`)))
	if rec.Code != http.StatusOK || len(wf.issued) != 1 || wf.issued[0].CertificateType != "host" || !slices.Equal(wf.issued[0].Principals, []string{"web-1"}) {
		t.Fatalf("guarded host issue = %d, workflow saw %+v", rec.Code, wf.issued)
	}
}
