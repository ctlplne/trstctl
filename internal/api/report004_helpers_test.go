// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/risk"
	"trstctl.com/trstctl/internal/store"
)

func TestSummarizeContextualRiskCountsLeadershipSignals(t *testing.T) {
	priorities := []risk.ContextualPriority{
		{Severity: "critical", BlastRadius: 5, WeakCryptoContext: 1, OwnerActive: false, PriorityReasons: []string{"near_expiry"}, RecommendedAction: "rotate"},
		{Severity: "high", BlastRadius: 4, OwnerActive: true, RecommendedAction: "schedule"},
		{Severity: "medium", OwnerActive: true},
		{Severity: "low", OwnerActive: false, PriorityReasons: []string{"baseline_risk"}},
	}
	got := summarizeContextualRisk(priorities)
	if got.TotalAnalyzed != 4 || got.Priorities != 4 || got.Critical != 1 || got.High != 1 || got.Medium != 1 || got.Low != 1 {
		t.Fatalf("severity summary wrong: %+v", got)
	}
	if got.HighBlastRadius != 2 || got.WeakCryptoContext != 1 || got.Orphaned != 2 || got.NearExpiry != 1 || got.Recommendations != 2 {
		t.Fatalf("contextual signal summary wrong: %+v", got)
	}
}

func TestAPIErrorMappersPreserveStatusContracts(t *testing.T) {
	if mapCodeSigningError(nil) != nil || mapCTSubmissionError(nil) != nil {
		t.Fatal("nil mapper inputs must stay nil")
	}
	for _, tc := range []struct {
		err  error
		want int
	}{
		{errors.New("not permitted by policy"), http.StatusForbidden},
		{errors.New("idempotency key was already used for another signing command"), http.StatusConflict},
		{errors.New("digest required"), http.StatusBadRequest},
		{errors.New("unknown key id"), http.StatusNotFound},
	} {
		got, ok := mapCodeSigningError(tc.err).(*apiError)
		if !ok || got.status != tc.want {
			t.Fatalf("mapCodeSigningError(%q) = %#v, want status %d", tc.err, got, tc.want)
		}
	}
	if err := mapCodeSigningError(errors.New("backend down")); err == nil || !strings.Contains(err.Error(), "backend down") {
		t.Fatalf("default code-signing error not preserved: %v", err)
	}

	for _, msg := range []string{"certificate pem required", "malformed certificate", "ssrf outbound endpoint"} {
		got, ok := mapCTSubmissionError(errors.New(msg)).(*apiError)
		if !ok || got.status != http.StatusBadRequest {
			t.Fatalf("mapCTSubmissionError(%q) = %#v, want 400 apiError", msg, got)
		}
	}
	if err := mapCTSubmissionError(errors.New("transient log outage")); err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("default CT submission error not preserved: %v", err)
	}
	if codeSigningDisabledProblem().status != http.StatusNotImplemented || ctSubmissionDisabledProblem().status != http.StatusNotImplemented {
		t.Fatal("disabled served optional surfaces must fail closed with 501")
	}
}

func TestComplianceHelpersExposeStableTypesAndResponseShape(t *testing.T) {
	if !validComplianceReportType("framework_evidence_pack") || validComplianceReportType("made-up") {
		t.Fatal("validComplianceReportType accepted an invalid value or rejected framework_evidence_pack")
	}
	values := complianceFrameworkValues()
	if len(values) == 0 {
		t.Fatal("complianceFrameworkValues returned no frameworks")
	}
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	got := toComplianceReportScheduleResponse(store.ComplianceReportSchedule{
		ID: "sched-1", TenantID: "tenant-a", Framework: "soc2", Name: "quarterly",
		ReportType: "framework_evidence_pack", IntervalSeconds: 86400, Enabled: true,
		Delivery: "email", RecipientRef: "audit@example.com", NextRunAt: now,
		CreatedAt: now, UpdatedAt: now,
	})
	if got.ID != "sched-1" || got.TenantID != "tenant-a" || !got.Enabled || got.NextRunAt != now {
		t.Fatalf("schedule response lost fields: %+v", got)
	}
}

func TestVaultCompatServedResponseHelpers(t *testing.T) {
	a := &API{}

	health := httptest.NewRecorder()
	a.vaultHealth(health, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("vaultHealth status = %d", health.Code)
	}
	healthBody := decodeJSONMap(t, health.Body.Bytes())
	if healthBody["initialized"] != true || healthBody["sealed"] != false || healthBody["version"] != "trstctl-vault-compat" {
		t.Fatalf("unexpected health body: %#v", healthBody)
	}

	for _, tc := range []struct {
		path string
		typ  string
	}{
		{path: "secret/data/app", typ: "kv"},
		{path: "pki/issue/web", typ: "pki"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/sys/internal/ui/mounts/"+tc.path, nil)
		req.SetPathValue("path", tc.path)
		a.vaultMountInfo(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("vaultMountInfo(%q) status = %d body=%s", tc.path, rec.Code, rec.Body.String())
		}
		body := decodeJSONMap(t, rec.Body.Bytes())
		data := body["data"].(map[string]any)
		if data["type"] != tc.typ {
			t.Fatalf("vaultMountInfo(%q) type = %#v, want %q", tc.path, data["type"], tc.typ)
		}
	}
	missingMount := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodGet, "/v1/sys/internal/ui/mounts/unknown", nil)
	missingReq.SetPathValue("path", "unknown")
	a.vaultMountInfo(missingMount, missingReq)
	if missingMount.Code != http.StatusNotFound {
		t.Fatalf("missing mount status = %d body=%s", missingMount.Code, missingMount.Body.String())
	}

	principal := authz.Principal{
		TenantID: "tenant-a",
		Subject:  "svc@example.test",
		Grants: []authz.Grant{{
			Role:  authz.BuiltinRoles()["admin"],
			Scope: authz.Scope{TenantID: "tenant-a"},
		}},
	}
	tokenRec := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil)
	tokenReq = tokenReq.WithContext(context.WithValue(tokenReq.Context(), principalCtxKey, principal))
	a.vaultTokenLookupSelf(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("vaultTokenLookupSelf status = %d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	tokenData := decodeJSONMap(t, tokenRec.Body.Bytes())["data"].(map[string]any)
	if tokenData["display_name"] != principal.Subject || tokenData["entity_id"] != principal.Subject {
		t.Fatalf("token lookup lost principal identity: %#v", tokenData)
	}
	meta := tokenData["meta"].(map[string]any)
	if meta["tenant_id"] != principal.TenantID {
		t.Fatalf("token lookup tenant meta = %#v", meta)
	}

	forbidden := httptest.NewRecorder()
	a.vaultTokenLookupSelf(forbidden, httptest.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated token lookup status = %d", forbidden.Code)
	}
}

func TestVaultCompatBodyTTLIdempotencyAndKVReadHelpers(t *testing.T) {
	a := &API{}

	for _, tc := range []struct {
		raw     string
		seconds int
		want    time.Duration
	}{
		{raw: "90m", want: 90 * time.Minute},
		{seconds: 45, want: 45 * time.Second},
		{want: time.Hour},
	} {
		got, err := parseVaultTTL(tc.raw, tc.seconds)
		if err != nil {
			t.Fatalf("parseVaultTTL(%q, %d): %v", tc.raw, tc.seconds, err)
		}
		if got != tc.want {
			t.Fatalf("parseVaultTTL(%q, %d) = %s, want %s", tc.raw, tc.seconds, got, tc.want)
		}
	}
	for _, tc := range []struct {
		raw     string
		seconds int
	}{
		{raw: "not-a-duration"},
		{raw: "-1s"},
	} {
		if _, err := parseVaultTTL(tc.raw, tc.seconds); err == nil {
			t.Fatalf("parseVaultTTL(%q, %d) succeeded, want error", tc.raw, tc.seconds)
		}
	}

	bodyReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app", strings.NewReader(`{"data":{"k":"v"}}`))
	bodyRec := httptest.NewRecorder()
	body, ok := a.captureVaultBody(bodyRec, bodyReq)
	if !ok || !bytes.Equal(body, []byte(`{"data":{"k":"v"}}`)) {
		t.Fatalf("captureVaultBody ok=%v body=%q", ok, body)
	}
	replayed, err := io.ReadAll(bodyReq.Body)
	if err != nil || !bytes.Equal(replayed, body) {
		t.Fatalf("captureVaultBody did not restore request body: %q %v", replayed, err)
	}

	nilBodyReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app", nil)
	nilBodyReq.Body = nil
	nilBodyRec := httptest.NewRecorder()
	if _, ok := a.captureVaultBody(nilBodyRec, nilBodyReq); ok || nilBodyRec.Code != http.StatusBadRequest {
		t.Fatalf("nil body capture ok=%v status=%d", ok, nilBodyRec.Code)
	}

	largeReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app", strings.NewReader(strings.Repeat("x", defaultRESTJSONBodyLimit+1)))
	largeRec := httptest.NewRecorder()
	if _, ok := a.captureVaultBody(largeRec, largeReq); ok || largeRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body capture ok=%v status=%d", ok, largeRec.Code)
	}

	idemReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app", nil)
	idemReq.Header.Set("Idempotency-Key", " explicit-key ")
	if got, err := vaultIdempotencyKey(idemReq); err != nil || got != "explicit-key" {
		t.Fatalf("explicit vault idempotency key = %q", got)
	}
	idemReq.Header.Del("Idempotency-Key")
	first, firstErr := vaultIdempotencyKey(idemReq)
	second, secondErr := vaultIdempotencyKey(idemReq)
	if firstErr == nil || secondErr == nil || first != "" || second != "" ||
		!strings.Contains(firstErr.Error(), "Idempotency-Key") || !strings.Contains(secondErr.Error(), "Idempotency-Key") {
		t.Fatalf("missing Vault idempotency header did not fail closed: %q %q errors=%v/%v", first, second, firstErr, secondErr)
	}

	for raw, want := range map[string]bool{
		`{"a":1}`: true,
		` { } `:   true,
		`[1,2]`:   false,
		`nope`:    false,
		`"str"`:   false,
	} {
		if got := rawJSONObject([]byte(raw)); got != want {
			t.Fatalf("rawJSONObject(%q) = %v, want %v", raw, got, want)
		}
	}

	if vaultStatus(errStatus(http.StatusTeapot, "short")) != http.StatusTeapot {
		t.Fatal("vaultStatus did not preserve apiError status")
	}
	if vaultStatus(errors.New("plain")) != http.StatusForbidden {
		t.Fatal("vaultStatus should map plain errors to forbidden")
	}

	errRec := httptest.NewRecorder()
	writeVaultError(errRec, 0, "")
	if errRec.Code != http.StatusInternalServerError {
		t.Fatalf("writeVaultError default status = %d", errRec.Code)
	}
	errBody := decodeJSONMap(t, errRec.Body.Bytes())
	if got := errBody["errors"].([]any)[0]; got != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("writeVaultError default detail = %#v", got)
	}

	updated := time.Date(2026, 7, 1, 1, 2, 3, 4, time.UTC)
	for _, tc := range []struct {
		name  string
		value []byte
		want  string
	}{
		{name: "object", value: []byte(`{"password":"redacted"}`), want: "password"},
		{name: "bytes", value: []byte("plain\nsecret"), want: "value"},
	} {
		rec := httptest.NewRecorder()
		a.writeVaultKVRead(rec, store.Secret{Name: "app", Version: 3, UpdatedAt: updated}, tc.value)
		if rec.Code != http.StatusOK {
			t.Fatalf("writeVaultKVRead(%s) status = %d body=%s", tc.name, rec.Code, rec.Body.String())
		}
		body := decodeJSONMap(t, rec.Body.Bytes())
		data := body["data"].(map[string]any)
		secretData := data["data"].(map[string]any)
		if _, ok := secretData[tc.want]; !ok {
			t.Fatalf("writeVaultKVRead(%s) data = %#v, want key %q", tc.name, secretData, tc.want)
		}
		meta := data["metadata"].(map[string]any)
		if meta["version"].(float64) != 3 || meta["created_time"] == "" {
			t.Fatalf("writeVaultKVRead(%s) metadata = %#v", tc.name, meta)
		}
	}
}

func decodeJSONMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode JSON object: %v\n%s", err, raw)
	}
	return out
}
