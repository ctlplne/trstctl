// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

type stubLeafRecovery struct{ err error }

func (s stubLeafRecovery) RecoverPKISecretLeaf(context.Context, string, []byte) (PKISecretLeafRecovery, error) {
	return PKISecretLeafRecovery{}, s.err
}

func (s stubLeafRecovery) RecoverCertificateDER(context.Context, string, string, CertificateDERRecoveryRequest) (CertificateDERRecovery, error) {
	return CertificateDERRecovery{}, s.err
}

func (s stubLeafRecovery) RecoverManagedCALeaf(context.Context, string, []byte) (PKISecretLeafRecovery, error) {
	return PKISecretLeafRecovery{}, s.err
}

// Managed CA leaf recovery (A209) shared the PKI-secret recovery's service and
// errors, so a caller sending a bad certificate to the managed-CA route read
// "not a recoverable PKI secret leaf", and the PKI-secret route's 503 lost its
// own wording. Each route now speaks for itself.
func TestLeafRecoveryRoutesSpeakForThemselves(t *testing.T) {
	type route struct {
		path    string
		handler func(*API, http.ResponseWriter, *http.Request)
	}
	pki := route{"/api/v1/certificates/pki-secret-recoveries", (*API).recoverPKISecretLeaf}
	managed := route{"/api/v1/certificates/managed-ca-recoveries", (*API).recoverManagedCALeaf}
	send := func(t *testing.T, a *API, r route, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := mutationBindingRequestWithBody("leaf-operator", http.MethodPost, r.path, "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
		req.Header.Set("Content-Type", "application/x-pem-file")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		r.handler(a, rec, req)
		return rec
	}
	expect := func(t *testing.T, rec *httptest.ResponseRecorder, code int, want, never string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), want) || (never != "" && strings.Contains(rec.Body.String(), never)) {
			t.Fatalf("got %d %s; want %d naming %q and never %q", rec.Code, rec.Body.String(), code, want, never)
		}
	}

	unwired := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	expect(t, send(t, unwired, pki, "pki-503"), http.StatusServiceUnavailable, "PKI secret leaf recovery is not available on this control plane", "")
	expect(t, send(t, unwired, managed, "managed-503"), http.StatusServiceUnavailable, "managed CA leaf recovery is not available on this control plane", "PKI secret")

	pkiRefusal := stubLeafRecovery{err: fmt.Errorf("%w: no PKI secret mint recorded serial 01", ErrPKISecretLeafNotRecoverable)}
	managedRefusal := stubLeafRecovery{err: fmt.Errorf("%w: none of this tenant's managed CAs signed the certificate", ErrManagedCALeafNotRecoverable)}
	wired := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithPKISecretLeafRecovery(pkiRefusal), WithManagedCALeafRecovery(managedRefusal))
	expect(t, send(t, wired, pki, "pki-422"), http.StatusUnprocessableEntity, "not a recoverable PKI secret leaf", "managed CA")
	expect(t, send(t, wired, managed, "managed-422"), http.StatusUnprocessableEntity, "not a recoverable managed CA leaf", "PKI secret")

	inInventory := stubLeafRecovery{err: fmt.Errorf("%w: as cert-1", ErrPKISecretLeafInInventory)}
	held := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithManagedCALeafRecovery(inInventory))
	expect(t, send(t, held, managed, "managed-409"), http.StatusConflict, "the leaf is already in inventory", "")
}
