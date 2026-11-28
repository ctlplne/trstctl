// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestServedESTUsesCurrentAccessBundleRunAuthority(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	x := a251Harness{t: t, h: h}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "est-bundle-admin", "access:write", "access:read", "certs:request", "certs:read")
	machine := seedScopedTokenSubject(t, h.store, h.tenant, "ci:est-client", "access:bundle.run")
	bundle := x.bundle(admin, "est-bundle-create", "est-enrollment", "certs:request")
	grant, _ := x.grant(admin, "est-bundle-grant", bundle, "machine", "ci:est-client")
	run := x.run(machine, "est-bundle-run", map[string]any{"bundle_ids": []string{bundle}, "ttl_seconds": 600})
	template := crypto.CertificateRequestTemplate{CommonName: "est-run.test", DNSNames: []string{"est-run.test"}}
	if code := estEnrollStatus(t, h, run.Token, template); code != http.StatusOK {
		t.Fatalf("EST enrollment with a current run = %d, want 200", code)
	}
	x.ungrant(admin, "est-bundle-ungrant", bundle, grant)
	if code := estEnrollStatus(t, h, run.Token, template); code != http.StatusUnauthorized {
		t.Fatalf("EST enrollment after the run lost its grant = %d, want 401", code)
	}

	deleted := x.bundle(admin, "est-bundle-delete-create", "est-delete", "certs:request")
	x.grant(admin, "est-bundle-delete-grant", deleted, "machine", "ci:est-client")
	deletedRun := x.run(machine, "est-bundle-delete-run", map[string]any{"bundle_ids": []string{deleted}})
	if code := estEnrollStatus(t, h, deletedRun.Token, template); code != http.StatusOK {
		t.Fatalf("EST enrollment before bundle deletion = %d, want 200", code)
	}
	x.call(http.MethodDelete, "/api/v1/access/bundles/"+deleted, admin, "est-bundle-delete", nil, http.StatusOK)
	if code := estEnrollStatus(t, h, deletedRun.Token, template); code != http.StatusUnauthorized {
		t.Fatalf("EST enrollment after the run's bundle was deleted = %d, want 401", code)
	}

	narrowed := x.bundle(admin, "est-bundle-narrow-create", "est-narrow", "certs:request", "certs:read")
	x.grant(admin, "est-bundle-narrow-grant", narrowed, "machine", "ci:est-client")
	narrowedRun := x.run(machine, "est-bundle-narrow-run", map[string]any{"bundle_ids": []string{narrowed}})
	if code := estEnrollStatus(t, h, narrowedRun.Token, template); code != http.StatusOK {
		t.Fatalf("EST enrollment before bundle narrowing = %d, want 200", code)
	}
	var current struct {
		Revision int64 `json:"revision"`
	}
	if raw := x.call(http.MethodGet, "/api/v1/access/bundles/"+narrowed, admin, "", nil, http.StatusOK); json.Unmarshal(raw, &current) != nil {
		t.Fatal("decode current bundle revision")
	}
	x.call(http.MethodPut, "/api/v1/access/bundles/"+narrowed, admin, "est-bundle-narrow",
		map[string]any{"name": "est-narrow", "permissions": []string{"certs:read"}, "audiences": []string{"ci"}, "revision": current.Revision}, http.StatusOK)
	if code := estEnrollStatus(t, h, narrowedRun.Token, template); code != http.StatusForbidden {
		t.Fatalf("EST enrollment after the run lost enrollment scope = %d, want 403", code)
	}
}
