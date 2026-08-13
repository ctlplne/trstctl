// SPDX-License-Identifier: MPL-2.0

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cli"
)

// TestEveryAPIOperationHasACLICommand is the S7.1 acceptance: every core API
// operation has a CLI command.
func TestEveryAPIOperationHasACLICommand(t *testing.T) {
	have := map[string]bool{}
	for _, c := range cli.Commands() {
		have[c.Method+" "+c.Path] = true
	}
	for _, r := range api.New(nil, nil, nil).Routes() {
		if r.Path == "/api/v1/openapi.json" {
			continue // the spec endpoint is not a core operation
		}
		if r.UnavailableReason != "" {
			continue // explicitly unavailable compatibility routes must not look callable in the CLI
		}
		if !have[r.Method+" "+r.Path] {
			t.Errorf("no CLI command for API operation %s %s", r.Method, r.Path)
		}
	}
}

func TestDiscoverySegmentCreateEnablesHeadlessSourceWorkflowAUD118(t *testing.T) {
	segmentBody := `{"name":"edge-prod","ranges":["10.24.0.0/16"],"staleness_hours":24,"excluded":false}`
	sourceBody := `{"kind":"network","name":"edge-tls","config":{"segment":"edge-prod","targets":["10.24.1.10:443"]}}`
	var (
		segmentCreated bool
		segmentKey     string
		sourceKey      string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Authorization") != "Bearer discovery-token" || r.Header.Get("X-Tenant-ID") != "tenant-a" {
			t.Errorf("auth headers = Authorization %q tenant %q", r.Header.Get("Authorization"), r.Header.Get("X-Tenant-ID"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		switch r.URL.Path {
		case "/api/v1/discovery/segments":
			if r.Method != http.MethodPost || !sameJSON(body, []byte(segmentBody)) {
				t.Errorf("segment request = %s %s body=%s", r.Method, r.URL.Path, body)
			}
			segmentKey = r.Header.Get("Idempotency-Key")
			segmentCreated = true
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"segment-1","name":"edge-prod","ranges":["10.24.0.0/16"]}`)
		case "/api/v1/discovery/sources":
			if !segmentCreated {
				t.Error("source create arrived before segment declaration")
			}
			if r.Method != http.MethodPost || !sameJSON(body, []byte(sourceBody)) {
				t.Errorf("source request = %s %s body=%s", r.Method, r.URL.Path, body)
			}
			sourceKey = r.Header.Get("Idempotency-Key")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"source-1","kind":"network","name":"edge-tls"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	env := cli.Env{Server: srv.URL, Token: "discovery-token", Tenant: "tenant-a", HTTPClient: srv.Client()}

	if code, _, stderr := run(t, []string{"discovery", "segments", "create", "-f", "-"}, env, segmentBody); code != 0 {
		t.Fatalf("segment create exit = %d, stderr = %q", code, stderr)
	}
	if code, _, stderr := run(t, []string{"discovery", "sources", "create", "-f", "-"}, env, sourceBody); code != 0 {
		t.Fatalf("source create exit = %d, stderr = %q", code, stderr)
	}
	if segmentKey == "" || sourceKey == "" || segmentKey == sourceKey {
		t.Fatalf("mutation keys = segment %q source %q; want two unique non-empty keys", segmentKey, sourceKey)
	}
}

func TestDiscoverySegmentCreatePropagatesStructuredFailureAUD118(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusUnprocessableEntity,
		`{"type":"https://trstctl.dev/problems/invalid-segment","title":"Invalid segment","status":422,"detail":"range is outside the approved estate"}`,
		&captured)
	env := cli.Env{Server: srv.URL, Token: "discovery-token", Tenant: "tenant-a", HTTPClient: srv.Client()}

	code, stdout, stderr := run(t, []string{"discovery", "segments", "create", "-f", "-"}, env,
		`{"name":"outside","ranges":["203.0.113.0/24"]}`)
	var problem map[string]any
	decodeErr := json.Unmarshal([]byte(stdout), &problem)
	if code != 1 || decodeErr != nil || problem["type"] != "https://trstctl.dev/problems/invalid-segment" ||
		problem["detail"] != "range is outside the approved estate" || !strings.Contains(stderr, "server returned status 422") {
		t.Fatalf("failure = exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if captured.Path != "/api/v1/discovery/segments" || captured.Header.Get("Idempotency-Key") == "" {
		t.Fatalf("captured failure request = %s key=%q", captured.Path, captured.Header.Get("Idempotency-Key"))
	}
}

func TestCryptoReadinessActionAndExportCommandsShareHeadlessSurfaceAUD65(t *testing.T) {
	actionBody := `{"name":"Payments crypto blocker","owner":"payments-team","deadline":"2026-12-01T00:00:00Z","wave":"wave-1","readiness_criteria":["owner approved"],"finding_ids":["finding-1"]}`
	var action capture
	actionServer := mockServer(t, http.StatusCreated,
		`{"id":"campaign-1","status":"open","findings":[{"finding_id":"finding-1","readiness_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
		&action)
	actionEnv := cli.Env{Server: actionServer.URL, Token: "risk-token", Tenant: "tenant-a", HTTPClient: actionServer.Client()}
	code, stdout, stderr := run(t, []string{"graph", "crypto-readiness", "actions", "create", "-f", "-"}, actionEnv, actionBody)
	if code != 0 || !strings.Contains(stdout, `"readiness_digest"`) {
		t.Fatalf("action command = exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if action.Method != http.MethodPost || action.Path != "/api/v1/graph/crypto-readiness/actions" ||
		action.Header.Get("Idempotency-Key") == "" || !sameJSON(action.Body, []byte(actionBody)) {
		t.Fatalf("action request = %s %s key=%q body=%s", action.Method, action.Path,
			action.Header.Get("Idempotency-Key"), action.Body)
	}

	var exported capture
	exportServer := mockServer(t, http.StatusOK,
		`{"dataset_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","csv":"sequence,dataset_digest\\n","ndjson":"","signed_export":"header.payload.signature"}`,
		&exported)
	exportEnv := cli.Env{Server: exportServer.URL, Token: "audit-token", Tenant: "tenant-a", HTTPClient: exportServer.Client()}
	code, stdout, stderr = run(t, []string{"graph", "crypto-readiness", "export"}, exportEnv, "")
	if code != 0 || !strings.Contains(stdout, `"signed_export"`) {
		t.Fatalf("export command = exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if exported.Method != http.MethodGet || exported.Path != "/api/v1/graph/crypto-readiness/export" || exported.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("export request = %s %s key=%q", exported.Method, exported.Path, exported.Header.Get("Idempotency-Key"))
	}
}

func sameJSON(left, right []byte) bool {
	var l, r any
	return json.Unmarshal(left, &l) == nil && json.Unmarshal(right, &r) == nil && reflect.DeepEqual(l, r)
}

func TestExecutableMigrationCommandsCoverEveryDurableControlAUD40(t *testing.T) {
	want := map[string]string{
		"POST /api/v1/migrations/runs":               "migrations start",
		"GET /api/v1/migrations/runs":                "migrations list",
		"GET /api/v1/migrations/runs/{id}":           "migrations show",
		"POST /api/v1/migrations/runs/{id}/pause":    "migrations pause",
		"POST /api/v1/migrations/runs/{id}/resume":   "migrations resume",
		"POST /api/v1/migrations/runs/{id}/rollback": "migrations rollback",
	}
	for _, command := range cli.Commands() {
		key := command.Method + " " + command.Path
		if names, ok := want[key]; ok && strings.Join(command.Name, " ") == names {
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing executable migration CLI controls: %+v", want)
	}
}

func TestCARetirementCommandRequiresForceAndCarriesExactCommandAUD42(t *testing.T) {
	var captured capture
	srv := mockServer(t, http.StatusAccepted,
		`{"key_id":"ca-old","command_event_id":"vdec-retirement-command-1","status":"pending","ledger_position":41,"final_epoch":7}`,
		&captured)
	env := cli.Env{Server: srv.URL, Token: "retirement-token", Tenant: "tenant-a", HTTPClient: srv.Client()}
	body := `{"final_epoch":7,"confirm_irreversible":true,"approvals":["operator-a","operator-b"]}`

	code, _, stderr := run(t, []string{"ca", "keys", "retire", "ca-old", "-f", "-"}, env, body)
	if code == 0 || !strings.Contains(stderr, "--force") {
		t.Fatalf("unconfirmed irreversible command = exit %d stderr=%q", code, stderr)
	}

	code, stdout, stderr := run(t, []string{"ca", "keys", "retire", "ca-old", "--force", "-f", "-"}, env, body)
	if code != 0 {
		t.Fatalf("confirmed retirement = exit %d stderr=%q", code, stderr)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/ca/keys/ca-old/retirement" ||
		captured.Header.Get("Idempotency-Key") == "" || !sameJSON(captured.Body, []byte(body)) {
		t.Fatalf("captured retirement = %s %s key=%q body=%s", captured.Method, captured.Path,
			captured.Header.Get("Idempotency-Key"), captured.Body)
	}
	if !strings.Contains(stdout, `"command_event_id": "vdec-retirement-command-1"`) {
		t.Fatalf("stdout lost durable command identity: %s", stdout)
	}
}

// capture records the request the CLI sent.
type capture struct {
	Method  string
	Path    string
	RawPath string
	Query   string
	Header  http.Header
	Body    []byte
}

func mockServer(t *testing.T, status int, respBody string, cap *capture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.Method, cap.Path, cap.RawPath, cap.Query, cap.Header, cap.Body = r.Method, r.URL.Path, r.URL.RawPath, r.URL.RawQuery, r.Header, b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, args []string, env cli.Env, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = cli.Run(context.Background(), args, env, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestListSendsAuthAndPrintsJSON(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"certificates":[]}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}

	code, stdout, _ := run(t, []string{"certificates", "list"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/certificates" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-1" {
		t.Errorf("X-Tenant-ID = %q", cap.Header.Get("X-Tenant-ID"))
	}
	var j any
	if err := json.Unmarshal([]byte(stdout), &j); err != nil {
		t.Errorf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

func TestOutboxReconciliationConflictsListIsReadOnlyAndTenantAuthenticated(t *testing.T) {
	var cap capture
	srv := mockServer(t, http.StatusOK, `{"items":[],"guidance":"keep the historical command"}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-incidents", Tenant: "tenant-a", HTTPClient: srv.Client()}

	code, stdout, stderr := run(t, []string{"incidents", "outbox-reconciliation-conflicts", "list"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/incidents/outbox-reconciliation-conflicts" || cap.Query != "" {
		t.Fatalf("request = %s %s?%s, want exact read-only quarantine route", cap.Method, cap.Path, cap.Query)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-incidents" {
		t.Fatalf("Authorization = %q, want Bearer tok-incidents", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-a" {
		t.Fatalf("X-Tenant-ID = %q, want tenant-a", cap.Header.Get("X-Tenant-ID"))
	}
	if len(cap.Body) != 0 || cap.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("read-only quarantine command sent mutation material: body=%q idempotency=%q", cap.Body, cap.Header.Get("Idempotency-Key"))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if decoded["guidance"] != "keep the historical command" {
		t.Fatalf("stdout lost recovery guidance: %s", stdout)
	}
}

func TestNHIInventoryCommandSendsAuthAndPrintsJSON(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[],"summary":{"total":0},"coverage":[]}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}

	code, stdout, _ := run(t, []string{"nhi", "inventory"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/nhi/inventory" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-1" {
		t.Errorf("X-Tenant-ID = %q", cap.Header.Get("X-Tenant-ID"))
	}
	var j any
	if err := json.Unmarshal([]byte(stdout), &j); err != nil {
		t.Errorf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

func TestACMEARIPostureCommandSendsAuthAndPrintsJSON(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"served":true,"publication_status":"served","scheduler_status":"enabled","items":[]}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-ari", Tenant: "tenant-ari", HTTPClient: srv.Client()}

	code, stdout, stderr := run(t, []string{"acme", "ari", "posture", "--limit", "7", "--cursor", "opaque-next"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/acme/ari/posture" || cap.Query != "cursor=opaque-next&limit=7" {
		t.Errorf("request = %s %s?%s, want paginated GET /api/v1/acme/ari/posture", cap.Method, cap.Path, cap.Query)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-ari" {
		t.Errorf("Authorization = %q, want Bearer tok-ari", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-ari" {
		t.Errorf("X-Tenant-ID = %q, want tenant-ari", cap.Header.Get("X-Tenant-ID"))
	}
	if len(cap.Body) != 0 || cap.Header.Get("Idempotency-Key") != "" {
		t.Errorf("read-only ARI command sent mutation material: body=%q idempotency=%q", cap.Body, cap.Header.Get("Idempotency-Key"))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if decoded["publication_status"] != "served" || decoded["scheduler_status"] != "enabled" {
		t.Fatalf("stdout lost ARI posture: %s", stdout)
	}
}

func TestRevocationHealthCommandIsReadOnlyAndPreservesSignedEvidence(t *testing.T) {
	var cap capture
	srv := mockServer(t, http.StatusOK, `{"items":[{"endpoint":"https://ca.example/ocsp","status":"fresh","signature_verified":true,"evidence_digest":"sha256:abc"}],"guidance":"Signed relay observations report endpoint health."}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-revocation", Tenant: "tenant-revocation", HTTPClient: srv.Client()}

	code, stdout, stderr := run(t, []string{"revocation", "health"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/revocation/health" || cap.Query != "" {
		t.Fatalf("request = %s %s?%s, want exact read-only revocation-health route", cap.Method, cap.Path, cap.Query)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-revocation" || cap.Header.Get("X-Tenant-ID") != "tenant-revocation" {
		t.Fatalf("request lost tenant authentication: authorization=%q tenant=%q", cap.Header.Get("Authorization"), cap.Header.Get("X-Tenant-ID"))
	}
	if len(cap.Body) != 0 || cap.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("read-only revocation-health command sent mutation material: body=%q idempotency=%q", cap.Body, cap.Header.Get("Idempotency-Key"))
	}
	var decoded struct {
		Items []struct {
			Status            string `json:"status"`
			SignatureVerified bool   `json:"signature_verified"`
			EvidenceDigest    string `json:"evidence_digest"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if len(decoded.Items) != 1 || decoded.Items[0].Status != "fresh" || !decoded.Items[0].SignatureVerified || decoded.Items[0].EvidenceDigest != "sha256:abc" {
		t.Fatalf("stdout lost signed revocation evidence: %s", stdout)
	}
}

func TestEnrollmentDiagnosticCommandsPreserveExactAndRedactedEvidenceAUD49(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		method     string
		path       string
		response   string
		wantKey    bool
		wantOutput string
	}{
		{
			name: "exact signed result", args: []string{"endpoints", "verifications", "get", "verify/aud49"},
			method: http.MethodGet, path: "/api/v1/endpoints/verifications/verify/aud49",
			response:   `{"endpoint_id":"verify/aud49","status":"verified","evidence_digest":"sha256:signed"}`,
			wantOutput: `"evidence_digest": "sha256:signed"`,
		},
		{
			name: "aggregate-only support addendum", args: []string{"enrollment", "diagnostics", "support-addendum"},
			method: http.MethodGet, path: "/api/v1/enrollment/diagnostics/support-addendum",
			response:   `{"schema_version":1,"unknown_count":0,"rows":[{"protocol":"est","cause":"template_acl_denied","actionable":true,"count":2}]}`,
			wantOutput: `"cause": "template_acl_denied"`,
		},
		{
			name: "prove fixed mutation", args: []string{"enrollment", "diagnostics", "prove-fixed", "diagnostic/aud49"},
			method: http.MethodPost, path: "/api/v1/enrollment/diagnostics/diagnostic/aud49/prove-fixed",
			response: `{"diagnostic_id":"diagnostic/aud49","verification_endpoint_id":"verify-1","status":"queued","queued_at":"2026-08-13T00:00:00Z","result_path":"/api/v1/endpoints/verifications/verify-1"}`,
			wantKey:  true, wantOutput: `"status": "queued"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, test.response, &captured)
			code, stdout, stderr := run(t, test.args, cli.Env{
				Server: server.URL, Token: "aud49-token", Tenant: "tenant-a", HTTPClient: server.Client(),
			}, "")
			if code != 0 {
				t.Fatalf("exit = %d stderr=%s", code, stderr)
			}
			if captured.Method != test.method || captured.Path != test.path || len(captured.Body) != 0 {
				t.Fatalf("request = %s %s body=%q", captured.Method, captured.Path, captured.Body)
			}
			if strings.Contains(test.path, "/verify/aud49") && captured.RawPath != "/api/v1/endpoints/verifications/verify%2Faud49" ||
				strings.Contains(test.path, "/diagnostic/aud49/") && captured.RawPath != "/api/v1/enrollment/diagnostics/diagnostic%2Faud49/prove-fixed" {
				t.Fatalf("escaped path = %q, want the identifier kept in one segment", captured.RawPath)
			}
			if (captured.Header.Get("Idempotency-Key") != "") != test.wantKey {
				t.Fatalf("Idempotency-Key = %q, want mutation=%t", captured.Header.Get("Idempotency-Key"), test.wantKey)
			}
			if !strings.Contains(stdout, test.wantOutput) {
				t.Fatalf("stdout lost evidence: %s", stdout)
			}
		})
	}
}

func TestRevocationCachesCommandIsReadOnlyAndPreservesSignedMetadataAUD39(t *testing.T) {
	var cap capture
	srv := mockServer(t, http.StatusOK, `{"observed":true,"items":[{"agent_id":"relay-1","segment":"plant-a","cache_id":"issuer-a","protocol":"ocsp","status":"fresh","signature_verified":true,"signer_fingerprint":"sha256:abc","cached_responses":2}],"summary":{"caches":1,"fresh":1}}`, &cap)
	env := cli.Env{Server: srv.URL, Token: "tok-revocation", Tenant: "tenant-revocation", HTTPClient: srv.Client()}

	code, stdout, stderr := run(t, []string{"revocation", "caches"}, env, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/revocation/caches" || cap.Query != "" {
		t.Fatalf("request = %s %s?%s, want exact read-only revocation-cache route", cap.Method, cap.Path, cap.Query)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-revocation" || cap.Header.Get("X-Tenant-ID") != "tenant-revocation" {
		t.Fatalf("request lost tenant authentication: authorization=%q tenant=%q", cap.Header.Get("Authorization"), cap.Header.Get("X-Tenant-ID"))
	}
	if len(cap.Body) != 0 || cap.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("read-only revocation-cache command sent mutation material: body=%q idempotency=%q", cap.Body, cap.Header.Get("Idempotency-Key"))
	}
	var decoded struct {
		Observed bool `json:"observed"`
		Items    []struct {
			Segment           string `json:"segment"`
			Status            string `json:"status"`
			SignatureVerified bool   `json:"signature_verified"`
			SignerFingerprint string `json:"signer_fingerprint"`
			CachedResponses   int    `json:"cached_responses"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if !decoded.Observed || len(decoded.Items) != 1 || decoded.Items[0].Segment != "plant-a" ||
		decoded.Items[0].Status != "fresh" || !decoded.Items[0].SignatureVerified ||
		decoded.Items[0].SignerFingerprint != "sha256:abc" || decoded.Items[0].CachedResponses != 2 {
		t.Fatalf("stdout lost signed segment-local revocation-cache metadata: %s", stdout)
	}
	if strings.Contains(stdout, "upstream") || strings.Contains(stdout, "request_der") || strings.Contains(stdout, "response_der") {
		t.Fatalf("stdout leaked relay-local revocation material: %s", stdout)
	}
}

func TestGetSubstitutesPathParam(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"id":"abc-123"}`, &cap)
	code, _, _ := run(t, []string{"owners", "get", "abc-123"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Path != "/api/v1/owners/abc-123" {
		t.Errorf("path = %q, want /api/v1/owners/abc-123", cap.Path)
	}
}

func TestCreateSendsBodyFromStdin(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"id":"new"}`, &cap)
	body := `{"kind":"workload","name":"svc"}`
	code, _, _ := run(t, []string{"owners", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/owners" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestAuditFeedCommandsExposeHeadlessCollectorWorkflowAUD52(t *testing.T) {
	var configured capture
	setServer := mockServer(t, http.StatusOK, `{"id":"feed-52"}`, &configured)
	body := `{"name":"soc","provider":"splunk-hec","endpoint_url":"https://splunk.example.test/services/collector/event","token_ref":"env:SPLUNK_HEC_TOKEN","interval_seconds":300,"batch_size":100,"enabled":true}`
	code, _, stderr := run(t,
		[]string{"audit", "feeds", "set", "52525252-5252-4525-8525-525252525252", "-f", "-"},
		cli.Env{Server: setServer.URL, HTTPClient: setServer.Client(), IdempotencyKey: "audit-feed-set-52"}, body)
	if code != 0 {
		t.Fatalf("audit feeds set exit=%d stderr=%q", code, stderr)
	}
	if configured.Method != http.MethodPut || configured.Path != "/api/v1/audit/feeds/52525252-5252-4525-8525-525252525252" ||
		configured.Header.Get("Idempotency-Key") != "audit-feed-set-52" || !sameJSON(configured.Body, []byte(body)) {
		t.Fatalf("set request=%s %s key=%q body=%s", configured.Method, configured.Path,
			configured.Header.Get("Idempotency-Key"), configured.Body)
	}

	var listed capture
	listServer := mockServer(t, http.StatusOK, `{"items":[],"count":0}`, &listed)
	code, _, stderr = run(t, []string{"audit", "feeds", "list"}, cli.Env{Server: listServer.URL, HTTPClient: listServer.Client()}, "")
	if code != 0 {
		t.Fatalf("audit feeds list exit=%d stderr=%q", code, stderr)
	}
	if listed.Method != http.MethodGet || listed.Path != "/api/v1/audit/feeds" || listed.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("list request=%s %s key=%q", listed.Method, listed.Path, listed.Header.Get("Idempotency-Key"))
	}
}

func TestOwnershipReadinessCommandsAUD44(t *testing.T) {
	var calls []capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		calls = append(calls, capture{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	env := cli.Env{Server: srv.URL, Token: "owner-token", Tenant: "tenant-44", HTTPClient: srv.Client()}

	commands := []struct {
		args  []string
		stdin string
	}{
		{args: []string{"owners", "attest", "owner-44"}},
		{args: []string{"owners", "exceptions", "list", "identity-44"}},
		{args: []string{"owners", "exceptions", "grant", "identity-44", "-f", "-"}, stdin: `{"reason":"incident recovery","expires_at":"2026-08-13T10:00:00Z"}`},
		{args: []string{"owners", "exceptions", "revoke", "identity-44", "exception-44", "--force", "-f", "-"}, stdin: `{"reason":"owner re-attested"}`},
	}
	for _, command := range commands {
		if code, _, stderr := run(t, command.args, env, command.stdin); code != 0 {
			t.Fatalf("%v exit = %d, stderr = %q", command.args, code, stderr)
		}
	}
	if len(calls) != 4 {
		t.Fatalf("calls = %d, want 4", len(calls))
	}
	wants := []struct {
		method string
		path   string
		body   string
		mutate bool
	}{
		{method: http.MethodPost, path: "/api/v1/owners/owner-44/attest", mutate: true},
		{method: http.MethodGet, path: "/api/v1/identities/identity-44/ownership-exceptions"},
		{method: http.MethodPost, path: "/api/v1/identities/identity-44/ownership-exceptions", body: commands[2].stdin, mutate: true},
		{method: http.MethodPost, path: "/api/v1/identities/identity-44/ownership-exceptions/exception-44/revoke", body: commands[3].stdin, mutate: true},
	}
	for i, want := range wants {
		got := calls[i]
		if got.Method != want.method || got.Path != want.path {
			t.Errorf("call %d = %s %s, want %s %s", i, got.Method, got.Path, want.method, want.path)
		}
		if want.body != "" && !sameJSON(got.Body, []byte(want.body)) {
			t.Errorf("call %d body = %s, want %s", i, got.Body, want.body)
		}
		if want.mutate && got.Header.Get("Idempotency-Key") == "" {
			t.Errorf("call %d mutation has no Idempotency-Key", i)
		}
		if !want.mutate && got.Header.Get("Idempotency-Key") != "" {
			t.Errorf("call %d read sent Idempotency-Key %q", i, got.Header.Get("Idempotency-Key"))
		}
		if got.Header.Get("Authorization") != "Bearer owner-token" || got.Header.Get("X-Tenant-ID") != "tenant-44" {
			t.Errorf("call %d lost authentication: authorization=%q tenant=%q", i, got.Header.Get("Authorization"), got.Header.Get("X-Tenant-ID"))
		}
	}
}

func TestDestructiveCommandRequiresForce(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"revoked":1}`, &cap)
	body := `{"ids":["identity-1"]}`

	code, _, stderr := run(t, []string{"identities", "bulk-revoke", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "destructive") || !strings.Contains(stderr, "--force") {
		t.Fatalf("stderr = %q, want destructive --force guidance", stderr)
	}
	if cap.Method != "" {
		t.Fatalf("destructive command reached server without force: %s %s", cap.Method, cap.Path)
	}
}

func TestDestructiveCommandSucceedsWithForce(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"revoked":1}`, &cap)
	body := `{"ids":["identity-1"]}`

	code, _, stderr := run(t, []string{"identities", "bulk-revoke", "--force", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/identities/bulk-revoke" {
		t.Fatalf("request = %s %s, want POST /api/v1/identities/bulk-revoke", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("destructive mutation should still send an Idempotency-Key")
	}
}

func TestCommandHelpIncludesExampleForEveryAPIOperation(t *testing.T) {
	for _, cmd := range cli.Commands() {
		if strings.Join(cmd.Name, " ") == "run" {
			continue
		}
		args := append(append([]string{}, cmd.Name...), "--help")
		code, stdout, stderr := run(t, args, cli.Env{}, "")
		if code != 0 {
			t.Fatalf("%s --help exit = %d, stderr = %q", strings.Join(cmd.Name, " "), code, stderr)
		}
		if !strings.Contains(stdout, "Usage: trstctl "+strings.Join(cmd.Name, " ")) {
			t.Errorf("%s --help missing usage: %q", strings.Join(cmd.Name, " "), stdout)
		}
		if !strings.Contains(stdout, "Example: trstctl "+strings.Join(cmd.Name, " ")) {
			t.Errorf("%s --help missing example: %q", strings.Join(cmd.Name, " "), stdout)
		}
		if cmd.Destructive() && !strings.Contains(stdout, "--force") {
			t.Errorf("%s --help missing --force warning in usage/example: %q", strings.Join(cmd.Name, " "), stdout)
		}
	}
}

func TestAttestedIssuanceCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","credential_id":"cred:test","subject":"ns/default/sa/web","not_after":"2026-06-24T12:00:00Z","attestation":{"id":"att:k8s","method":"k8s_sat","subject":"ns/default/sa/web","issuer":"kubernetes","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &cap)
	body := `{"method":"k8s_sat","payload_base64":"c2F0","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","ttl_seconds":600}`
	code, _, _ := run(t, []string{"workloads", "attested-issuance", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/workloads/attested-issuance" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("attested issuance mutation should send an Idempotency-Key")
	}
}

func TestCAAuthorityIssueIntermediateCSRCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","serial":"01","not_after":"2026-06-24T12:00:00Z"}`, &cap)
	body := `{"ceremony_id":"ceremony-1","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","spec":{"common_name":"SPIRE Server CA","ttl_seconds":3600,"max_path_len":0}}`
	code, _, _ := run(t, []string{"ca", "authorities", "issue-intermediate-csr", "root-1", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/root-1/intermediates/csr" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("intermediate CSR issuance mutation should send an Idempotency-Key")
	}
}

func TestCAAuthorityRotateCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"issue_path":"/api/v1/ca/authorities/ca-old/issue","active_issue_path":"/api/v1/ca/authorities/ca-new/issue"}`, &cap)
	body := `{"successor_id":"ca-new","reason":"planned overlap"}`
	code, _, _ := run(t, []string{"ca", "authorities", "rotate", "ca-old", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/ca-old/rotate" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CA rotation mutation should send an Idempotency-Key")
	}
}

func TestCAAuthorityRekeyCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"issue_path":"/api/v1/ca/authorities/ca-old/issue","active_issue_path":"/api/v1/ca/authorities/ca-new/issue"}`, &cap)
	body := `{"ceremony_id":"ceremony-1","ttl_seconds":15552000,"reason":"planned renewal"}`
	code, _, _ := run(t, []string{"ca", "authorities", "rekey", "ca-old", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/ca/authorities/ca-old/rekey" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CA re-key mutation should send an Idempotency-Key")
	}
}

func TestBrokerAgentIdentityCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"agent_id":"agent-7","node_id":"wl:agent-7","subject":"agent-7","credential_id":"cred:test","certificate_id":"cert:test","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","scopes":["mcp:graph.read"],"not_after":"2026-06-24T12:00:00Z","attestation":{"id":"att:broker","method":"stub_broker","subject":"agent-7","issuer":"broker","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &cap)
	body := `{"agent_id":"agent-7","method":"stub_broker","payload_base64":"Z2VudWluZQ==","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","scopes":["mcp:graph.read"],"ttl_seconds":600}`
	code, _, _ := run(t, []string{"broker", "agent-identities", "issue", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/broker/agent-identities" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("broker identity issuance mutation should send an Idempotency-Key")
	}
}

func TestEphemeralCommandsSendBodiesAndIdempotencyKeys(t *testing.T) {
	var issueCap capture
	issueSrv := mockServer(t, 202, `{"state":"awaiting_approval","request_id":"jit-agent-7","subject":"jit-agent-7","required_approvals":1,"approvals":0,"expires_at":"2026-06-24T12:00:00Z","attestation":{"id":"att:jit","method":"stub_ephemeral","subject":"jit-agent-7","issuer":"jit","expires_at":"2026-06-24T12:00:00Z","verified_at":"2026-06-24T11:50:00Z"}}`, &issueCap)
	issueBody := `{"request_id":"jit-agent-7","method":"stub_ephemeral","payload_base64":"Z2VudWluZQ==","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0DrbFLt03cHuBfOfvt/wL6+9Yv5mzn4XLu9WLCrCx0o=\n-----END PUBLIC KEY-----\n","ttl_seconds":120}`
	code, _, _ := run(t, []string{"ephemeral", "issue", "-f", "-"}, cli.Env{Server: issueSrv.URL, HTTPClient: issueSrv.Client()}, issueBody)
	if code != 0 {
		t.Fatalf("issue exit = %d", code)
	}
	if issueCap.Method != "POST" || issueCap.Path != "/api/v1/ephemeral" {
		t.Errorf("issue request = %s %s", issueCap.Method, issueCap.Path)
	}
	if strings.TrimSpace(string(issueCap.Body)) != issueBody {
		t.Errorf("issue body = %q, want %q", issueCap.Body, issueBody)
	}
	if issueCap.Header.Get("Idempotency-Key") == "" {
		t.Error("ephemeral issue mutation should send an Idempotency-Key")
	}

	var approveCap capture
	approveSrv := mockServer(t, 200, `{"id":"019fec49-6641-7131-ae7f-17f7ea4b5e0e","intent_digest":"sha256:ephemeral","resource":"jit-agent-7","action":"issue","approver":"ra-1","approvals":1,"approval_count":1,"required_approvals":1,"status":"approved"}`, &approveCap)
	approveBody := `{"action":"issue","request_id":"019fec49-6641-7131-ae7f-17f7ea4b5e0e","intent_digest":"sha256:ephemeral"}`
	code, _, _ = run(t, []string{"ephemeral", "approve", "019fec49-6641-7131-ae7f-17f7ea4b5e0e", "-f", "-"}, cli.Env{Server: approveSrv.URL, HTTPClient: approveSrv.Client()}, approveBody)
	if code != 0 {
		t.Fatalf("approve exit = %d", code)
	}
	if approveCap.Method != "POST" || approveCap.Path != "/api/v1/ephemeral/019fec49-6641-7131-ae7f-17f7ea4b5e0e/approvals" {
		t.Errorf("approve request = %s %s", approveCap.Method, approveCap.Path)
	}
	if strings.TrimSpace(string(approveCap.Body)) != approveBody {
		t.Errorf("approve body = %q, want %q", approveCap.Body, approveBody)
	}
	if approveCap.Header.Get("Idempotency-Key") == "" {
		t.Error("ephemeral approve mutation should send an Idempotency-Key")
	}
}

func TestAccessSessionCommandsSendBodiesQueriesAndIdempotencyKeys(t *testing.T) {
	var openCap capture
	openSrv := mockServer(t, 201, `{"id":"pam:session-1","target_type":"postgres","target_id":"prod-db","status":"active"}`, &openCap)
	openBody := `{"target_type":"postgres","target_id":"prod-db","role":"read_only","reason":"incident cleanup","attestation":{"method":"stub","subject":"ops@example.com","payload_base64":"Z2VudWluZQ=="}}`
	code, _, _ := run(t, []string{"access", "sessions", "open", "-f", "-"}, cli.Env{Server: openSrv.URL, HTTPClient: openSrv.Client()}, openBody)
	if code != 0 {
		t.Fatalf("open exit = %d", code)
	}
	if openCap.Method != "POST" || openCap.Path != "/api/v1/access/sessions" {
		t.Errorf("open request = %s %s", openCap.Method, openCap.Path)
	}
	if strings.TrimSpace(string(openCap.Body)) != openBody {
		t.Errorf("open body = %q, want %q", openCap.Body, openBody)
	}
	if openCap.Header.Get("Idempotency-Key") == "" {
		t.Error("access session open should send an Idempotency-Key")
	}

	var listCap capture
	listSrv := mockServer(t, 200, `{"sessions":[]}`, &listCap)
	code, _, _ = run(t, []string{"access", "sessions", "list", "--limit", "3", "--cursor", "next"}, cli.Env{Server: listSrv.URL, HTTPClient: listSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/access/sessions" || listCap.Query != "cursor=next&limit=3" {
		t.Errorf("list request = %s %s?%s", listCap.Method, listCap.Path, listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("access session list must not send an Idempotency-Key")
	}

	var getCap capture
	getSrv := mockServer(t, 200, `{"id":"pam:session-1"}`, &getCap)
	code, _, _ = run(t, []string{"access", "sessions", "get", "pam:session-1"}, cli.Env{Server: getSrv.URL, HTTPClient: getSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("get exit = %d", code)
	}
	if getCap.Method != "GET" || getCap.Path != "/api/v1/access/sessions/pam:session-1" {
		t.Errorf("get request = %s %s", getCap.Method, getCap.Path)
	}
}

func TestBreakglassReconcileCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"reconciled":1}`, &cap)
	body := `{"bundles":[{"request_id":"bg-1","subject":"svc.example","cert_der":"Y2VydA==","reason":"restore production","approvals":["alice"],"issued_at":"2026-06-25T17:00:00Z","signature":"c2ln"}]}`
	code, _, _ := run(t, []string{"breakglass", "reconcile", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/breakglass/reconcile" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("break-glass reconcile mutation should send an Idempotency-Key")
	}
}

func TestBreakglassIssueCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"reconciled":1,"audit_event_type":"breakglass.issued"}`, &cap)
	body := `{"ceremony_id":"11111111-1111-4111-8111-111111111111","request_id":"bg-online-1","subject":"svc.example","csr_der":"Y3Ny","reason":"restore production","ttl_seconds":900}`
	code, _, _ := run(t, []string{"breakglass", "issue", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/breakglass/issue" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("break-glass issue mutation should send an Idempotency-Key")
	}
}

func TestServiceNowTicketCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 202, `{"id":"ticket-1","status":"queued"}`, &cap)
	body := `{"instance_url":"https://example.service-now.com","table":"incident","token_ref":"env:TRSTCTL_SERVICENOW_TOKEN","short_description":"Rotate exposed TLS private key"}`
	code, _, _ := run(t, []string{"itsm", "servicenow", "tickets", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/itsm/servicenow/tickets" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("ServiceNow ticket mutation should send an Idempotency-Key")
	}
}

func TestFleetReissuanceCommandsSendBodiesQueriesAndIdempotencyKeys(t *testing.T) {
	var startCap capture
	startSrv := mockServer(t, 201, `{"id":"fleet-1","status":"executed"}`, &startCap)
	startBody := `{"issuer_id":"issuer-1","replacement_authority_id":"ca-2","mode":"live","reason":"compromised intermediate","cohorts":[{"id":"canary","ordinal":1,"members":[{"identity_id":"identity-1","agent_id":"agent-1","trust_anchor_path":"/etc/trstctl/next-root.pem"}]}]}`
	code, _, _ := run(t, []string{"incidents", "fleet-reissuance", "start", "-f", "-"}, cli.Env{Server: startSrv.URL, HTTPClient: startSrv.Client()}, startBody)
	if code != 0 {
		t.Fatalf("start exit = %d", code)
	}
	if startCap.Method != "POST" || startCap.Path != "/api/v1/incidents/fleet-reissuance-runs" {
		t.Errorf("start request = %s %s", startCap.Method, startCap.Path)
	}
	if strings.TrimSpace(string(startCap.Body)) != startBody {
		t.Errorf("start body = %q, want %q", startCap.Body, startBody)
	}
	if startCap.Header.Get("Idempotency-Key") == "" {
		t.Error("fleet reissuance start mutation should send an Idempotency-Key")
	}

	var listCap capture
	listSrv := mockServer(t, 200, `{"items":[]}`, &listCap)
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "list", "--issuer_id", "issuer-1", "--limit", "5"}, cli.Env{Server: listSrv.URL, HTTPClient: listSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/incidents/fleet-reissuance-runs" {
		t.Errorf("list request = %s %s", listCap.Method, listCap.Path)
	}
	if !strings.Contains(listCap.Query, "issuer_id=issuer-1") || !strings.Contains(listCap.Query, "limit=5") {
		t.Errorf("list query = %q, want issuer_id and limit", listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("fleet reissuance list must not send an Idempotency-Key")
	}

	var pauseCap capture
	pauseSrv := mockServer(t, 200, `{"id":"fleet-1","status":"paused"}`, &pauseCap)
	pauseBody := `{"reason":"operator inspection"}`
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "pause", "fleet-1", "-f", "-"}, cli.Env{Server: pauseSrv.URL, HTTPClient: pauseSrv.Client()}, pauseBody)
	if code != 0 {
		t.Fatalf("pause exit = %d", code)
	}
	if pauseCap.Method != "POST" || pauseCap.Path != "/api/v1/incidents/fleet-reissuance-runs/fleet-1/pause" {
		t.Errorf("pause request = %s %s", pauseCap.Method, pauseCap.Path)
	}
	if strings.TrimSpace(string(pauseCap.Body)) != pauseBody {
		t.Errorf("pause body = %q, want %q", pauseCap.Body, pauseBody)
	}
	if pauseCap.Header.Get("Idempotency-Key") == "" {
		t.Error("fleet reissuance pause mutation should send an Idempotency-Key")
	}

	var evidenceCap capture
	evidenceSrv := mockServer(t, 200, `{"run_id":"fleet-1"}`, &evidenceCap)
	code, _, _ = run(t, []string{"incidents", "fleet-reissuance", "evidence", "fleet-1"}, cli.Env{Server: evidenceSrv.URL, HTTPClient: evidenceSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("evidence exit = %d", code)
	}
	if evidenceCap.Method != "GET" || evidenceCap.Path != "/api/v1/incidents/fleet-reissuance-runs/fleet-1/evidence" {
		t.Errorf("evidence request = %s %s", evidenceCap.Method, evidenceCap.Path)
	}
	if evidenceCap.Header.Get("Idempotency-Key") != "" {
		t.Error("fleet reissuance evidence export must not send an Idempotency-Key")
	}
}

func TestManagedOfferingCommandsSendStatusAndProvisionTenant(t *testing.T) {
	var statusCap capture
	statusSrv := mockServer(t, 200, `{"served":true,"deployment_model":"managed_provider","provider_plane_mode":"enabled"}`, &statusCap)
	code, _, _ := run(t, []string{"managed-offering", "status"}, cli.Env{Server: statusSrv.URL, HTTPClient: statusSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	if statusCap.Method != "GET" || statusCap.Path != "/api/v1/managed-offering/status" {
		t.Errorf("status request = %s %s", statusCap.Method, statusCap.Path)
	}
	if statusCap.Header.Get("Idempotency-Key") != "" {
		t.Error("status command must not send an Idempotency-Key")
	}

	var provisionCap capture
	provisionSrv := mockServer(t, 201, `{"tenant_id":"22222222-2222-4222-8222-222222222222","managed":true}`, &provisionCap)
	body := `{"tenant_id":"22222222-2222-4222-8222-222222222222","name":"Acme Hosted","region":"us-east-1","data_residency":"US","plan":"enterprise","support_tier":"24x7","slo_tier":"99.95"}`
	code, _, _ = run(t, []string{"managed-offering", "tenants", "provision", "-f", "-"}, cli.Env{Server: provisionSrv.URL, HTTPClient: provisionSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("provision exit = %d", code)
	}
	if provisionCap.Method != "POST" || provisionCap.Path != "/api/v1/managed-offering/tenants" {
		t.Errorf("provision request = %s %s", provisionCap.Method, provisionCap.Path)
	}
	if strings.TrimSpace(string(provisionCap.Body)) != body {
		t.Errorf("body = %q, want %q", provisionCap.Body, body)
	}
	if provisionCap.Header.Get("Idempotency-Key") == "" {
		t.Error("managed offering provision mutation should send an Idempotency-Key")
	}
}

func TestEnterpriseSupportCommandSendsReadOnlyStatusRequest(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"served":true,"capability":"CAP-MODEL-04","support_mode":"enabled"}`, &cap)
	code, _, _ := run(t, []string{"support", "enterprise"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/support/enterprise" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "" {
		t.Error("enterprise support status command must not send an Idempotency-Key")
	}
}

func TestPlatformDistributionCommandSendsReadOnlyStatusRequest(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"served":true,"capability":"CAP-MODEL-01","run_modes":[]}`, &cap)
	code, _, _ := run(t, []string{"platform", "distribution"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/platform/distribution" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "" {
		t.Error("platform distribution command must not send an Idempotency-Key")
	}
}

func TestTenantKeyDomainCommandsUseServedTenantScopedLifecycle(t *testing.T) {
	var statusCapture capture
	statusServer := mockServer(t, http.StatusOK, `{"served":true,"state":"partial"}`, &statusCapture)
	code, _, stderr := run(t,
		[]string{"platform", "tenant-key-domain", "status"},
		cli.Env{Server: statusServer.URL, HTTPClient: statusServer.Client()}, "",
	)
	if code != 0 {
		t.Fatalf("status exit = %d stderr=%s", code, stderr)
	}
	if statusCapture.Method != http.MethodGet || statusCapture.Path != "/api/v1/platform/tenant-key-domain" {
		t.Fatalf("status request = %s %s", statusCapture.Method, statusCapture.Path)
	}
	if statusCapture.Header.Get("Idempotency-Key") != "" || len(statusCapture.Body) != 0 {
		t.Fatalf("read-only status sent mutation material: key=%q body=%q", statusCapture.Header.Get("Idempotency-Key"), statusCapture.Body)
	}

	var migrateCapture capture
	migrateServer := mockServer(t, http.StatusOK, `{"served":true,"state":"partial"}`, &migrateCapture)
	migrateBody := `{"wrapper_kind":"local_file","wrapper_id":"tenant-a-custody"}`
	code, _, stderr = run(t,
		[]string{"platform", "tenant-key-domain", "migrate", "-f", "-"},
		cli.Env{Server: migrateServer.URL, HTTPClient: migrateServer.Client(), IdempotencyKey: "tenant-domain-migrate-cli"},
		migrateBody,
	)
	if code != 0 {
		t.Fatalf("migrate exit = %d stderr=%s", code, stderr)
	}
	if migrateCapture.Method != http.MethodPost || migrateCapture.Path != "/api/v1/platform/tenant-key-domain/migrate" ||
		strings.TrimSpace(string(migrateCapture.Body)) != migrateBody ||
		migrateCapture.Header.Get("Idempotency-Key") != "tenant-domain-migrate-cli" {
		t.Fatalf("migrate request = %s %s key=%q body=%q", migrateCapture.Method, migrateCapture.Path, migrateCapture.Header.Get("Idempotency-Key"), migrateCapture.Body)
	}

	for _, mutation := range []struct {
		name string
		path string
	}{
		{name: "seal", path: "/api/v1/platform/tenant-key-domain/seal"},
		{name: "unseal", path: "/api/v1/platform/tenant-key-domain/unseal"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			var captured capture
			server := mockServer(t, http.StatusOK, `{"accepted":true}`, &captured)
			key := "tenant-domain-" + mutation.name + "-cli"
			code, _, stderr := run(t,
				[]string{"platform", "tenant-key-domain", mutation.name},
				cli.Env{Server: server.URL, HTTPClient: server.Client(), IdempotencyKey: key}, "",
			)
			if code != 0 {
				t.Fatalf("exit = %d stderr=%s", code, stderr)
			}
			if captured.Method != http.MethodPost || captured.Path != mutation.path ||
				captured.Header.Get("Idempotency-Key") != key || len(captured.Body) != 0 {
				t.Fatalf("request = %s %s key=%q body=%q", captured.Method, captured.Path, captured.Header.Get("Idempotency-Key"), captured.Body)
			}
		})
	}
}

func TestMachineLoginCommandSendsCredentialBody(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"session_id":"sess-1","principal":"spiffe://example/workload","method":"token","scopes":[],"expires_at":"2026-06-17T12:00:00Z"}`, &cap)
	body := `{"credential":"machine-token","method":"token"}`
	code, _, _ := run(t, []string{"secrets", "login", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/login" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("machine login mutation should send an Idempotency-Key")
	}
}

func TestConnectorRotationCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"key":"db/reporting","old_ref":"version:1","new_ref":"version:2","completed":false,"queued":true}`, &cap)
	body := `{"provider":"connector:ci","key":"db/reporting","old_ref":"version:1","remote_key":"DB_PASSWORD"}`
	code, _, _ := run(t, []string{"secrets", "rotations", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/rotations" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("connector rotation mutation should send an Idempotency-Key")
	}
}

func TestSecretRotationScheduleCommandsSendPathsAndIdempotencyKeys(t *testing.T) {
	var createCap capture
	srv := mockServer(t, 201, `{"id":"11111111-1111-1111-1111-111111111111","name":"reporting-hourly","provider":"connector:ci","key":"db/reporting","old_ref":"version:1","interval_seconds":3600,"enabled":true,"next_run_at":"2026-07-01T00:00:00Z","last_run_status":"","created_at":"2026-07-01T00:00:00Z","updated_at":"2026-07-01T00:00:00Z"}`, &createCap)
	body := `{"name":"reporting-hourly","provider":"connector:ci","key":"db/reporting","old_ref":"version:1","interval_seconds":3600}`
	code, _, _ := run(t, []string{"secrets", "rotation-schedules", "create", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("create exit = %d", code)
	}
	if createCap.Method != "POST" || createCap.Path != "/api/v1/secrets/rotation-schedules" {
		t.Errorf("create request = %s %s", createCap.Method, createCap.Path)
	}
	if strings.TrimSpace(string(createCap.Body)) != body {
		t.Errorf("create body = %q, want %q", createCap.Body, body)
	}
	if createCap.Header.Get("Idempotency-Key") == "" {
		t.Error("rotation schedule create should send an Idempotency-Key")
	}

	var listCap capture
	srv = mockServer(t, 200, `{"items":[]}`, &listCap)
	code, _, _ = run(t, []string{"secrets", "rotation-schedules", "list", "--limit", "10"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if listCap.Method != "GET" || listCap.Path != "/api/v1/secrets/rotation-schedules" || listCap.Query != "limit=10" {
		t.Errorf("list request = %s %s?%s", listCap.Method, listCap.Path, listCap.Query)
	}
	if listCap.Header.Get("Idempotency-Key") != "" {
		t.Error("rotation schedule list must not send an Idempotency-Key")
	}

	var runDueCap capture
	srv = mockServer(t, 200, `{"ran":0,"runs":[]}`, &runDueCap)
	code, _, _ = run(t, []string{"secrets", "rotation-schedules", "run-due"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("run-due exit = %d", code)
	}
	if runDueCap.Method != "POST" || runDueCap.Path != "/api/v1/secrets/rotation-schedules/run-due" {
		t.Errorf("run-due request = %s %s", runDueCap.Method, runDueCap.Path)
	}
	if runDueCap.Header.Get("Idempotency-Key") == "" {
		t.Error("rotation schedule run-due should send an Idempotency-Key")
	}
}

func TestSecretSyncCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD","enqueued":true,"delivered":true}`, &cap)
	body := `{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}`
	code, _, _ := run(t, []string{"secrets", "syncs", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/syncs" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("secret sync mutation should send an Idempotency-Key")
	}
}

func TestSecretScanCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"run_id":"1f95f7db-4a45-40fe-bb8f-9b7dfc8f6ad8","scanner":"gitleaks","engine_version":"v8.27.2","rules_active":213,"findings_count":1,"findings":[]}`, &cap)
	body := `{"path":"."}`
	code, _, _ := run(t, []string{"secrets", "scans", "run", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/secrets/scans" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if ct := cap.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("secret scan mutation should send an Idempotency-Key")
	}
}

func TestSecretRepositoryScanCommandsMapToServedRoutes(t *testing.T) {
	var posture capture
	postureSrv := mockServer(t, 200, `{"capability":"CAP-SCAN-01","served":true}`, &posture)
	code, _, _ := run(t, []string{"secrets", "scans", "repositories"}, cli.Env{Server: postureSrv.URL, HTTPClient: postureSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("posture exit = %d", code)
	}
	if posture.Method != "GET" || posture.Path != "/api/v1/secrets/scans/repositories" {
		t.Errorf("posture request = %s %s", posture.Method, posture.Path)
	}

	var webhook capture
	webhookSrv := mockServer(t, 202, `{"capability":"CAP-SCAN-01","queued":true}`, &webhook)
	body := `{"repository":"acme/payments","checkout_path":"."}`
	code, _, _ = run(t, []string{"secrets", "scans", "repositories", "webhook", "github", "-f", "-"}, cli.Env{Server: webhookSrv.URL, HTTPClient: webhookSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("webhook exit = %d", code)
	}
	if webhook.Method != "POST" || webhook.Path != "/api/v1/secrets/scans/repositories/github/webhook" {
		t.Errorf("webhook request = %s %s", webhook.Method, webhook.Path)
	}
	if strings.TrimSpace(string(webhook.Body)) != body {
		t.Errorf("webhook body = %q, want %q", webhook.Body, body)
	}
	if webhook.Header.Get("Idempotency-Key") == "" {
		t.Error("repository webhook mutation should send an Idempotency-Key")
	}
}

func TestThirdPartySecretScanCommandsMapToServedRoutes(t *testing.T) {
	var posture capture
	postureSrv := mockServer(t, 200, `{"capability":"CAP-SCAN-04","served":true}`, &posture)
	code, _, _ := run(t, []string{"secrets", "scans", "third-party"}, cli.Env{Server: postureSrv.URL, HTTPClient: postureSrv.Client()}, "")
	if code != 0 {
		t.Fatalf("posture exit = %d", code)
	}
	if posture.Method != "GET" || posture.Path != "/api/v1/secrets/scans/third-party" {
		t.Errorf("posture request = %s %s", posture.Method, posture.Path)
	}

	var ingest capture
	ingestSrv := mockServer(t, 202, `{"capability":"CAP-SCAN-04","queued":true}`, &ingest)
	body := `{"source":"acme/slack","artifact_path":"/tmp/slack-export.jsonl"}`
	code, _, _ = run(t, []string{"secrets", "scans", "third-party", "ingest", "slack", "-f", "-"}, cli.Env{Server: ingestSrv.URL, HTTPClient: ingestSrv.Client()}, body)
	if code != 0 {
		t.Fatalf("ingest exit = %d", code)
	}
	if ingest.Method != "POST" || ingest.Path != "/api/v1/secrets/scans/third-party/slack/ingest" {
		t.Errorf("ingest request = %s %s", ingest.Method, ingest.Path)
	}
	if strings.TrimSpace(string(ingest.Body)) != body {
		t.Errorf("ingest body = %q, want %q", ingest.Body, body)
	}
	if ingest.Header.Get("Idempotency-Key") == "" {
		t.Error("third-party ingest mutation should send an Idempotency-Key")
	}
}

func TestSecretScanStagedDiffRunsLocallyWithoutServerAndRedacts(t *testing.T) {
	repo := initCLIGitRepo(t)
	writeCLIGitFile(t, repo, "app.env", "API_KEY=abc123-secret-value\n")
	gitCLI(t, repo, "add", "app.env")
	fake := fakeGitleaksBinary(t, `[{"RuleID":"generic-api-key","File":"app.env","StartLine":1,"Secret":"abc123-secret-value","Match":"API_KEY=abc123-secret-value"}]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "staged-diff", "--repo", repo, "--gitleaks-bin", fake}, cli.Env{}, "")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when findings are present; stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"mode": "staged"`, `"files_scanned": 1`, `"findings_count": 1`, `"credential_ref": "generic-api-key@app.env"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "abc123-secret-value") || strings.Contains(stderr, "abc123-secret-value") {
		t.Fatalf("staged-diff leaked raw secret value:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "secret finding") {
		t.Fatalf("stderr = %q, want finding failure summary", stderr)
	}
}

func TestSecretScanStagedDiffSupportsCIDiffMode(t *testing.T) {
	repo := initCLIGitRepo(t)
	writeCLIGitFile(t, repo, "README.md", "base\n")
	gitCLI(t, repo, "add", "README.md")
	gitCLI(t, repo, "commit", "-m", "base")
	base := strings.TrimSpace(gitCLIOutput(t, repo, "rev-parse", "HEAD"))
	writeCLIGitFile(t, repo, "ci.env", "CI_TOKEN=abc123-secret-value\n")
	gitCLI(t, repo, "add", "ci.env")
	gitCLI(t, repo, "commit", "-m", "head")
	head := strings.TrimSpace(gitCLIOutput(t, repo, "rev-parse", "HEAD"))
	fake := fakeGitleaksBinary(t, `[{"RuleID":"generic-api-key","File":"ci.env","StartLine":1,"Secret":"abc123-secret-value"}]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "staged-diff", "--repo", repo, "--base", base, "--head", head, "--gitleaks-bin", fake, "--advisory"}, cli.Env{}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr)
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"mode": "ci_diff"`, `"files": [`, `"ci.env"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "abc123-secret-value") || strings.Contains(stderr, "abc123-secret-value") {
		t.Fatalf("CI diff scan leaked raw secret value:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

func TestSecretScanPreCommitInstallWritesHook(t *testing.T) {
	repo := initCLIGitRepo(t)
	fake := fakeGitleaksBinary(t, `[]`)

	code, stdout, stderr := run(t, []string{"secrets", "scans", "pre-commit", "install", "--repo", repo, "--gitleaks-bin", fake}, cli.Env{}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr)
	}
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hookPath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("hook mode = %v, want executable", info.Mode())
	}
	hook := string(data)
	for _, want := range []string{"secrets scans staged-diff", "--repo", repo, "--gitleaks-bin", fake} {
		if !strings.Contains(hook, want) {
			t.Errorf("hook missing %q:\n%s", want, hook)
		}
	}
	for _, want := range []string{`"capability": "CAP-SCAN-02"`, `"installed": true`, `"hook_path":`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunInjectsFetchedSecretsIntoChildEnvWithoutLoggingValues(t *testing.T) {
	envPath, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env command not available")
	}
	var cap capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.Method, cap.Path, cap.Query, cap.Header, cap.Body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header, b
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/secrets/store/db/password" {
			http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"name":"db/password","value":"s3cr3t","version":1}`)
	}))
	t.Cleanup(srv.Close)

	code, stdout, stderr := run(t, []string{"run", "--secret", "DB_PASSWORD=db/password", "--", envPath}, cli.Env{Server: srv.URL, Token: "tok-123", Tenant: "tenant-1", HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if cap.Method != http.MethodGet || cap.Path != "/api/v1/secrets/store/db/password" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Authorization") != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", cap.Header.Get("Authorization"))
	}
	if cap.Header.Get("X-Tenant-ID") != "tenant-1" {
		t.Errorf("X-Tenant-ID = %q", cap.Header.Get("X-Tenant-ID"))
	}
	if !strings.Contains(stdout, "DB_PASSWORD=s3cr3t") {
		t.Fatalf("stdout does not include injected secret env var:\n%s", stdout)
	}
	if strings.Contains(stderr, "s3cr3t") {
		t.Fatalf("stderr leaked secret material: %q", stderr)
	}
}

func TestQueryFlag(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{}`, &cap)
	code, _, _ := run(t, []string{"certificates", "list", "--limit", "5"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Query != "limit=5" {
		t.Errorf("query = %q, want limit=5", cap.Query)
	}
}

func TestCBOMScanCommandSendsBodyAndIdempotencyKey(t *testing.T) {
	var cap capture
	srv := mockServer(t, 201, `{"items":[],"migration_progress":{"total":0,"post_quantum_ready":0,"quantum_vulnerable":0,"percent_ready":100}}`, &cap)
	body := `{"tls_endpoints":["payments.internal:443"],"host_configs":["/etc/nginx/site.conf"]}`
	code, _, _ := run(t, []string{"cbom", "scan", "-f", "-"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, body)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/cbom/scans" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != body {
		t.Errorf("body = %q, want %q", cap.Body, body)
	}
	if cap.Header.Get("Idempotency-Key") == "" {
		t.Error("CBOM scan mutation should send an Idempotency-Key")
	}
}

func TestCBOMAssetsCommandReadsInventory(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[],"migration_progress":{"total":0,"post_quantum_ready":0,"quantum_vulnerable":0,"percent_ready":100}}`, &cap)
	code, stdout, _ := run(t, []string{"cbom", "assets"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/cbom/assets" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	var j any
	if err := json.Unmarshal([]byte(stdout), &j); err != nil {
		t.Errorf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

func TestConnectorsOutboxCircuitsCommand(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"circuits":[]}`, &cap)
	code, _, _ := run(t, []string{"connectors", "outbox-circuits"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/connectors/outbox-circuits" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
}

func TestNotificationCommandsSendPathsQueriesAndIdempotencyKeys(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"items":[]}`, &cap)
	env := cli.Env{Server: srv.URL, HTTPClient: srv.Client(), IdempotencyKey: "notif-cli-idem"}

	code, _, _ := run(t, []string{"notifications", "channels"}, env, "")
	if code != 0 {
		t.Fatalf("channels exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-channels" {
		t.Errorf("channels request = %s %s", cap.Method, cap.Path)
	}

	channelBody := `{"id":"webhook","channel_type":"webhook","label":"Tenant webhook","endpoint_url":"https://hooks.example.test/trstctl","credential_ref":"secret://notifications/webhook/hmac-key","enabled":true}`
	code, _, _ = run(t, []string{"notifications", "channels", "create", "-f", "-"}, env, channelBody)
	if code != 0 {
		t.Fatalf("channel create exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-channels" {
		t.Errorf("channel create request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != channelBody {
		t.Errorf("channel create body = %q, want %q", cap.Body, channelBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel create Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "channels", "get", "webhook"}, env, "")
	if code != 0 {
		t.Fatalf("channel get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "channels", "update", "webhook", "-f", "-"}, env, channelBody)
	if code != 0 {
		t.Fatalf("channel update exit = %d", code)
	}
	if cap.Method != "PUT" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel update request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != channelBody {
		t.Errorf("channel update body = %q, want %q", cap.Body, channelBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel update Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "channels", "delete", "webhook", "--force"}, env, "")
	if code != 0 {
		t.Fatalf("channel delete exit = %d", code)
	}
	if cap.Method != "DELETE" || cap.Path != "/api/v1/notification-channels/webhook" {
		t.Errorf("channel delete request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel delete Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	testBody := `{"severity":"critical","credential_ref":"secret://notifications/slack/raw-webhook-url"}`
	code, _, _ = run(t, []string{"notifications", "channels", "test", "slack", "-f", "-"}, env, testBody)
	if code != 0 {
		t.Fatalf("channel test exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-channels/slack/test" {
		t.Errorf("channel test request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != testBody {
		t.Errorf("channel test body = %q, want %q", cap.Body, testBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("channel test Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	policyBody := `{"name":"Expiry escalation","default_channels":["slack"],"channels_by_severity":{"critical":["slack"]}}`
	code, _, _ = run(t, []string{"notifications", "routing-policies", "create", "-f", "-"}, env, policyBody)
	if code != 0 {
		t.Fatalf("routing policy create exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notification-routing-policies" {
		t.Errorf("routing policy create request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != policyBody {
		t.Errorf("routing policy create body = %q, want %q", cap.Body, policyBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy create Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "list"}, env, "")
	if code != 0 {
		t.Fatalf("routing policy list exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-routing-policies" {
		t.Errorf("routing policy list request = %s %s", cap.Method, cap.Path)
	}

	const policyID = "11111111-1111-4111-8111-111111111111"
	code, _, _ = run(t, []string{"notifications", "routing-policies", "get", policyID}, env, "")
	if code != 0 {
		t.Fatalf("routing policy get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "update", policyID, "-f", "-"}, env, policyBody)
	if code != 0 {
		t.Fatalf("routing policy update exit = %d", code)
	}
	if cap.Method != "PUT" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy update request = %s %s", cap.Method, cap.Path)
	}
	if strings.TrimSpace(string(cap.Body)) != policyBody {
		t.Errorf("routing policy update body = %q, want %q", cap.Body, policyBody)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy update Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "routing-policies", "delete", policyID, "--force"}, env, "")
	if code != 0 {
		t.Fatalf("routing policy delete exit = %d", code)
	}
	if cap.Method != "DELETE" || cap.Path != "/api/v1/notification-routing-policies/"+policyID {
		t.Errorf("routing policy delete request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("routing policy delete Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "list", "--status", "dead", "--limit", "10"}, env, "")
	if code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notifications" {
		t.Errorf("list request = %s %s", cap.Method, cap.Path)
	}
	if !strings.Contains(cap.Query, "status=dead") || !strings.Contains(cap.Query, "limit=10") {
		t.Errorf("list query = %q, want status and limit", cap.Query)
	}

	code, _, _ = run(t, []string{"notifications", "get", "42"}, env, "")
	if code != 0 {
		t.Fatalf("get exit = %d", code)
	}
	if cap.Method != "GET" || cap.Path != "/api/v1/notifications/42" {
		t.Errorf("get request = %s %s", cap.Method, cap.Path)
	}

	code, _, _ = run(t, []string{"notifications", "read", "42"}, env, "")
	if code != 0 {
		t.Fatalf("read exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notifications/42/read" {
		t.Errorf("read request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("read Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}

	code, _, _ = run(t, []string{"notifications", "requeue", "42"}, env, "")
	if code != 0 {
		t.Fatalf("requeue exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/notifications/42/requeue" {
		t.Errorf("requeue request = %s %s", cap.Method, cap.Path)
	}
	if cap.Header.Get("Idempotency-Key") != "notif-cli-idem" {
		t.Errorf("requeue Idempotency-Key = %q", cap.Header.Get("Idempotency-Key"))
	}
}

func TestGraphQueryWrapsCypher(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"rows":[]}`, &cap)
	code, _, _ := run(t, []string{"graph", "query", "MATCH (n) RETURN n"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if cap.Method != "POST" || cap.Path != "/api/v1/graph/query" {
		t.Errorf("request = %s %s", cap.Method, cap.Path)
	}
	var got struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(cap.Body, &got); err != nil || got.Query != "MATCH (n) RETURN n" {
		t.Errorf("body = %q, want a {query} wrapper", cap.Body)
	}
}

func TestErrorExitCode(t *testing.T) {
	var cap capture
	srv := mockServer(t, 404, `{"detail":"not found"}`, &cap)
	code, _, stderr := run(t, []string{"owners", "get", "missing"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code == 0 {
		t.Error("a 404 should exit non-zero")
	}
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "404") {
		t.Errorf("stderr should explain the error: %q", stderr)
	}
}

func TestMissingServerErrors(t *testing.T) {
	code, _, _ := run(t, []string{"owners", "list"}, cli.Env{}, "")
	if code == 0 {
		t.Error("missing --server should exit non-zero")
	}
}

func TestUnknownCommandErrors(t *testing.T) {
	code, _, _ := run(t, []string{"bogus", "thing"}, cli.Env{Server: "http://x"}, "")
	if code == 0 {
		t.Error("unknown command should exit non-zero")
	}
}

func initCLIGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitCLI(t, repo, "init")
	gitCLI(t, repo, "config", "user.email", "test@example.com")
	gitCLI(t, repo, "config", "user.name", "trstctl test")
	return repo
}

func writeCLIGitFile(t *testing.T, repo, name, body string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitCLI(t *testing.T, repo string, args ...string) {
	t.Helper()
	_ = gitCLIOutput(t, repo, args...)
}

func gitCLIOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func fakeGitleaksBinary(t *testing.T, reportJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gitleaks")
	script := `#!/bin/sh
set -eu
report=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then
    shift
    report="$1"
  fi
  shift || true
done
if [ -z "$report" ]; then
  echo "missing --report-path" >&2
  exit 2
fi
cat > "$report" <<'JSON'
` + reportJSON + `
JSON
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	return path
}
