// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

type boundExternalCAService struct {
	calls int
	last  ExternalCAIssueRequest
}

func (s *boundExternalCAService) ListExternalCAs(context.Context, string) ([]ExternalCA, error) {
	return []ExternalCA{{ID: "ca-one", Type: "test", Name: "Test CA", Status: "available"}}, nil
}

func (s *boundExternalCAService) IssueExternalCA(_ context.Context, _, _, _, _ string, request ExternalCAIssueRequest) (ExternalCAIssuedCertificate, error) {
	s.calls++
	s.last = ExternalCAIssueRequest{
		CSRDER: append([]byte(nil), request.CSRDER...), DNSNames: append([]string(nil), request.DNSNames...),
		TTLSeconds: request.TTLSeconds, ProfileName: request.ProfileName,
		RequestedEKUs: append([]string(nil), request.RequestedEKUs...),
	}
	return ExternalCAIssuedCertificate{
		CertificatePEM: "issued-certificate", Serial: "01", Issuer: "Test CA",
		NotAfter: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func TestExternalCAIssueIdempotencyBindsCanonicalCommandAndPrincipal(t *testing.T) {
	service := &boundExternalCAService{}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithExternalCAs(service))
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3, 4}}))
	body := externalCAIssueJSON{
		CSRPem: csr, DNSNames: []string{"B.example.test", "a.example.test"}, TTLSeconds: 3600,
		ProfileName: " tls-server ", RequestedEKUs: []string{"serverAuth", "clientAuth"},
	}
	request := func(caID, subject string, payload externalCAIssueJSON) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "external-ca-shared-key")
		req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
		req.Header.Set("X-Subject", subject)
		req.Header.Set("X-Roles", "admin")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	first := request("ca-one", "issuer-a", body)
	if first.Code != http.StatusCreated || service.calls != 1 {
		t.Fatalf("first issue status=%d calls=%d body=%s", first.Code, service.calls, first.Body.String())
	}
	canonicalReplay := body
	canonicalReplay.DNSNames = []string{"a.example.test", "b.EXAMPLE.TEST", "a.example.test"}
	canonicalReplay.ProfileName = "tls-server"
	canonicalReplay.RequestedEKUs = []string{"clientAuth", "serverAuth", "clientAuth"}
	replay := request("ca-one", "issuer-a", canonicalReplay)
	if replay.Code != http.StatusCreated || service.calls != 1 || replay.Body.String() != first.Body.String() {
		t.Fatalf("canonical replay status=%d calls=%d body=%s first=%s", replay.Code, service.calls, replay.Body.String(), first.Body.String())
	}
	changedBody := body
	changedBody.TTLSeconds++
	for label, recorder := range map[string]*httptest.ResponseRecorder{
		"body":      request("ca-one", "issuer-a", changedBody),
		"caller":    request("ca-one", "issuer-b", body),
		"authority": request("ca-two", "issuer-a", body),
	} {
		if recorder.Code != http.StatusConflict {
			t.Fatalf("changed %s status=%d body=%s, want 409", label, recorder.Code, recorder.Body.String())
		}
	}
	if service.calls != 1 {
		t.Fatalf("changed idempotency collisions reached external CA callback %d times, want 1 total", service.calls)
	}
	if !bytes.Equal(service.last.CSRDER, []byte{1, 2, 3, 4}) || service.last.ProfileName != "tls-server" ||
		len(service.last.DNSNames) != 2 || service.last.DNSNames[0] != "a.example.test" || service.last.DNSNames[1] != "b.example.test" {
		t.Fatalf("callback did not receive canonical request: %+v", service.last)
	}
}

func TestExternalCAIssueDirectHandlerHidesRegistryUntilAuthenticatedTenant(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3, 4}}))
	body, err := json.Marshal(externalCAIssueJSON{CSRPem: csr, DNSNames: []string{"service.example.test"}})
	if err != nil {
		t.Fatal(err)
	}

	request := func(ctx context.Context, tenantID string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/external-cas/ca-one/issue", bytes.NewReader(body)).WithContext(ctx)
		req.SetPathValue("id", "ca-one")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "external-ca-hidden-registry")
		if tenantID != "" {
			req.Header.Set("X-Tenant-ID", tenantID)
		}
		recorder := httptest.NewRecorder()
		a.issueExternalCA(recorder, req)
		return recorder
	}

	unauthenticated := request(context.Background(), "11111111-1111-1111-1111-111111111111")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated direct handler status=%d body=%s, want 401", unauthenticated.Code, unauthenticated.Body.String())
	}
	principalContext := context.WithValue(context.Background(), principalCtxKey, authz.Principal{Subject: "issuer-a"})
	missingTenant := request(principalContext, "")
	if missingTenant.Code != http.StatusUnauthorized {
		t.Fatalf("tenantless direct handler status=%d body=%s, want 401", missingTenant.Code, missingTenant.Body.String())
	}
	tenantID := "11111111-1111-1111-1111-111111111111"
	authenticatedContext := context.WithValue(context.Background(), principalCtxKey, authz.Principal{Subject: "issuer-a", TenantID: tenantID})
	authenticatedTenant := request(authenticatedContext, tenantID)
	if authenticatedTenant.Code != http.StatusServiceUnavailable {
		t.Fatalf("authenticated direct handler status=%d body=%s, want 503 for absent registry", authenticatedTenant.Code, authenticatedTenant.Body.String())
	}
}
