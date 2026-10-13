// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestBreakglassLiveOpenAPIRequestsCannotNominateApprovers(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	wantRefs := map[string]string{
		"/api/v1/breakglass/issue-ceremonies/preview": "#/components/schemas/BreakglassIssueIntentRequest",
		"/api/v1/breakglass/issue-ceremonies":         "#/components/schemas/BreakglassIssueIntentRequest",
		"/api/v1/breakglass/issue":                    "#/components/schemas/BreakglassIssueExecutionRequest",
	}
	for path, wantRef := range wantRefs {
		op := doc.Paths[path]["post"]
		if op == nil || op.RequestBody == nil {
			t.Fatalf("%s has no POST request body", path)
		}
		got := op.RequestBody.Content["application/json"].Schema
		if got == nil || got.Ref != wantRef {
			t.Fatalf("%s request schema=%+v, want %s", path, got, wantRef)
		}
	}
	for _, name := range []string{"BreakglassIssueIntentRequest", "BreakglassIssueExecutionRequest"} {
		schema := doc.Components.Schemas[name]
		if schema == nil {
			t.Fatalf("missing live schema %s", name)
		}
		if _, ok := schema.Properties["approvals"]; ok {
			t.Fatalf("live schema %s lets the caller nominate approvers", name)
		}
	}
	legacyRef := "#/components/schemas/BreakglassIssueRequest"
	for path, item := range doc.Paths {
		for method, op := range item {
			if op.RequestBody == nil {
				continue
			}
			for _, media := range op.RequestBody.Content {
				if media.Schema != nil && media.Schema.Ref == legacyRef {
					t.Fatalf("legacy caller-approval schema is still live on %s %s", method, path)
				}
			}
		}
	}
}

func TestBreakglassIssueRejectsSubjectDifferentFromSignedCSR(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "recovery.qa-breakglass.local",
		DNSNames:   []string{"recovery.qa-breakglass.local", "alternate.qa-breakglass.local"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	req := breakglassIssueRequest{RequestID: "bg-exact-identity", Subject: "misleading.qa-breakglass.local", CSRDer: csr, Reason: "QA identity binding", TTLSeconds: 900}
	for _, requireCeremony := range []bool{false, true} {
		if requireCeremony {
			req.CeremonyID = "11111111-1111-4111-8111-111111111111"
		}
		_, _, err := validateBreakglassIssueRequest(req, requireCeremony)
		if err == nil || !strings.Contains(err.Error(), "CSR common name") {
			t.Fatalf("requireCeremony=%v: subject/CSR mismatch was accepted or unexplained: %v", requireCeremony, err)
		}
	}
	req.Subject = "recovery.qa-breakglass.local"
	if _, _, err := validateBreakglassIssueRequest(req, true); err != nil {
		t.Fatalf("exact signed common name rejected: %v", err)
	}
}

func TestBreakglassIssuePreviewContractExplainsConfigurationAndEffects(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	op := doc.Paths["/api/v1/breakglass/issue-ceremonies/preview"]["post"]
	if op == nil || op.OperationID != "previewBreakglassIssue" || op.XPermission != "certs:issue" {
		t.Fatalf("break-glass preview route is incomplete: %+v", op)
	}
	for _, route := range New(nil, nil, nil).routes() {
		if route.opID == "previewBreakglassIssue" && route.mutation {
			t.Fatal("break-glass preview was registered as a mutation")
		}
	}
	schema := doc.Components.Schemas["BreakglassIssuePlanPreview"]
	if schema == nil {
		t.Fatal("missing BreakglassIssuePlanPreview schema")
	}
	for _, field := range []string{
		"capability", "operation", "ready", "effect_free", "request_fingerprint", "csr_sha256",
		"csr_common_name", "csr_dns_names", "csr_ip_addresses", "csr_email_addresses", "csr_uris",
		"approval_threshold", "configured_operator_count", "prerequisites", "blockers",
		"preview_writes", "preview_external_effects", "preview_signer_calls", "execution_writes",
		"execution_external_effects", "execution_signer_calls", "recovery_steps", "verification_steps",
	} {
		if schema.Properties[field] == nil {
			t.Errorf("BreakglassIssuePlanPreview missing %s", field)
		}
	}
}

func TestBreakglassIssueRejectsCallerApproverNames(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/breakglass/issue", bytes.NewBufferString(`{
		"ceremony_id":"11111111-1111-4111-8111-111111111111",
		"request_id":"bg-1","subject":"svc.example","csr_der":"Y3Ny",
		"reason":"recovery","ttl_seconds":300,"approvals":["caller-picked"]
	}`))
	var body breakglassIssueRequest
	if err := decodeJSON(req, &body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateBreakglassIssueRequest(body, true); err == nil {
		t.Fatal("caller-authored approvals field was accepted by live issue validation")
	}
}
