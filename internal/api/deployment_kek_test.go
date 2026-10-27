// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type fakeDeploymentKEKLifecycle struct {
	domain   store.DeploymentKEKDomain
	found    bool
	beginErr error
	begins   []tenantseal.WrapperRef
	tenants  []string
}

func (f *fakeDeploymentKEKLifecycle) Status(context.Context) (store.DeploymentKEKDomain, bool, error) {
	return f.domain, f.found, nil
}

func (f *fakeDeploymentKEKLifecycle) Begin(_ context.Context, tenantID string, ref tenantseal.WrapperRef) (store.DeploymentKEKDomain, error) {
	f.tenants = append(f.tenants, tenantID)
	f.begins = append(f.begins, ref)
	return f.domain, f.beginErr
}

func deploymentKEKHandler(lifecycle api.DeploymentKEKLifecycle, operator string, woken *int) http.Handler {
	return api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(),
		api.WithDeploymentKEK(api.DeploymentKEKService{
			Lifecycle: lifecycle, OperatorTenantID: operator,
			Wake: func() { *woken++ },
		}))
}

// A198: only the configured operator tenant rotates the deployment KEK; with
// none configured nobody does; the status says which and never carries a key.
func TestDeploymentKEKRotationIsTheOperatorTenantsAlone(t *testing.T) {
	lifecycle := &fakeDeploymentKEKLifecycle{
		domain: store.DeploymentKEKDomain{
			DomainID: "6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11", NextGeneration: 1,
			NextWrapperKind: "pkcs11", NextWrapperID: "hsm-a", NextWrappedKEK: []byte("wrapped-secret-bytes"),
			OperationID: "op-1", OperationStatus: store.DeploymentKEKOperationRunning, Stage: store.DeploymentKEKStageSettling,
		},
		found: true,
	}
	body := []byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-a"}`)
	for _, c := range []struct {
		name, operator string
		want           int
	}{
		{"no operator tenant configured", "", http.StatusForbidden},
		{"another tenant is the operator", "22222222-2222-2222-2222-222222222222", http.StatusForbidden},
		{"the caller is the operator", connectorTenantA, http.StatusAccepted},
	} {
		woken := 0
		handler := deploymentKEKHandler(lifecycle, c.operator, &woken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tenantDomainRequest(http.MethodPost, "/api/v1/platform/deployment-kek/rotate", body, "deployment-kek-"+c.name))
		if rec.Code != c.want {
			t.Fatalf("%s: rotate = %d body=%s", c.name, rec.Code, rec.Body.String())
		}
		if c.want == http.StatusAccepted {
			var status api.DeploymentKEKStatus
			if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if !status.CanRotate || status.RotationAuthority != "operator_tenant" || status.Rotation == nil ||
				status.Rotation.NextWrapperID != "hsm-a" || woken != 1 {
				t.Fatalf("operator rotate = %+v woken=%d", status, woken)
			}
			if strings.Contains(rec.Body.String(), "wrapped-secret-bytes") || strings.Contains(rec.Body.String(), "d3JhcHBlZC1zZWNyZXQtYnl0ZXM") {
				t.Fatalf("the status carried the wrapped key: %s", rec.Body.String())
			}
		}
		status := httptest.NewRecorder()
		handler.ServeHTTP(status, tenantDomainRequest(http.MethodGet, "/api/v1/platform/deployment-kek", nil, ""))
		var read api.DeploymentKEKStatus
		if err := json.Unmarshal(status.Body.Bytes(), &read); err != nil || status.Code != http.StatusOK {
			t.Fatalf("%s: status = %d %v", c.name, status.Code, err)
		}
		wantAuthority := map[string]string{"": "not_configured", connectorTenantA: "operator_tenant"}[c.operator]
		if wantAuthority == "" {
			wantAuthority = "another_tenant"
		}
		if read.RotationAuthority != wantAuthority || read.CanRotate != (wantAuthority == "operator_tenant") {
			t.Fatalf("%s: authority = %q can_rotate=%v", c.name, read.RotationAuthority, read.CanRotate)
		}
	}
	if len(lifecycle.begins) != 1 || lifecycle.tenants[0] != connectorTenantA ||
		lifecycle.begins[0] != (tenantseal.WrapperRef{Kind: "pkcs11", ID: "hsm-a"}) {
		t.Fatalf("Begin calls = %v %v", lifecycle.tenants, lifecycle.begins)
	}
}

func TestDeploymentKEKRotateMapsRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		err  error
		want int
	}{
		{"unknown kind", `{"wrapper_kind":"kms","wrapper_id":"a"}`, nil, http.StatusBadRequest},
		{"missing id", `{"wrapper_kind":"local_file"}`, nil, http.StatusBadRequest},
		{"another wrapper running", `{"wrapper_kind":"local_file","wrapper_id":"b"}`, tenantseal.ErrDeploymentRotationConflict, http.StatusConflict},
		{"wrapper not configured", `{"wrapper_kind":"local_file","wrapper_id":"c"}`, tenantseal.ErrWrapperNotConfigured, http.StatusServiceUnavailable},
		{"unexpected", `{"wrapper_kind":"local_file","wrapper_id":"d"}`, errors.New("postgres://user:password@db"), http.StatusInternalServerError},
	} {
		woken := 0
		lifecycle := &fakeDeploymentKEKLifecycle{beginErr: c.err}
		rec := httptest.NewRecorder()
		deploymentKEKHandler(lifecycle, connectorTenantA, &woken).ServeHTTP(rec,
			tenantDomainRequest(http.MethodPost, "/api/v1/platform/deployment-kek/rotate", []byte(c.body), "deployment-kek-refusal-"+c.name))
		if rec.Code != c.want || strings.Contains(rec.Body.String(), "password") || woken != 0 {
			t.Fatalf("%s: rotate = %d woken=%d body=%s", c.name, rec.Code, woken, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	api.New(nil, orchestrator.NewMemoryIdempotency(), nil, api.WithInsecureHeaderResolver()).ServeHTTP(rec,
		tenantDomainRequest(http.MethodGet, "/api/v1/platform/deployment-kek", nil, ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"custody":"key_file"`) || !strings.Contains(rec.Body.String(), `"served":false`) {
		t.Fatalf("status without a rotation lifecycle = %d body=%s", rec.Code, rec.Body.String())
	}
}
