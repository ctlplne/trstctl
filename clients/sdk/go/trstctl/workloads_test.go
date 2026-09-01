// SPDX-License-Identifier: MPL-2.0

package trstctl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkloadSDKUsesExactRoutesWireShapesAndIdempotency(t *testing.T) {
	proof := []byte("signed-workload-proof")
	task := []byte("signed-task-envelope")
	wantProof := append([]byte(nil), proof...)
	wantTask := append([]byte(nil), task...)
	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if r.Body != nil && r.Body != http.NoBody {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode %s %s request: %v", r.Method, r.URL.Path, err)
			}
		}
		assertEncoded := func(field string, want []byte) {
			t.Helper()
			if got := body[field]; got != base64.StdEncoding.EncodeToString(want) {
				t.Errorf("%s %s %s = %v, want one canonical base64 encoding", r.Method, r.URL.Path, field, got)
			}
		}

		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/broker/agent-identities/preview":
			if got := r.Header.Get("Idempotency-Key"); got != "" {
				t.Errorf("broker preview sent Idempotency-Key %q; effect-free preview must not reserve a mutation key", got)
			}
			assertEncoded("payload_base64", proof)
			assertEncoded("task_envelope_base64", task)
			writeJSON(w, http.StatusOK, map[string]any{"ready": true, "effect_free": true})
		case "POST /api/v1/broker/agent-identities":
			if got := r.Header.Get("Idempotency-Key"); got != "broker-stable-key" {
				t.Errorf("broker issue Idempotency-Key = %q", got)
			}
			assertEncoded("payload_base64", proof)
			assertEncoded("task_envelope_base64", task)
			writeJSON(w, http.StatusCreated, map[string]any{
				"agent_id": "agent-7", "node_id": "node-7", "subject": "verified-agent",
				"credential_id": "cred-7", "certificate_id": "11111111-1111-1111-1111-111111111111",
				"certificate_pem": "PUBLIC CERTIFICATE", "scopes": []string{"inventory:read"},
				"not_after": "2026-09-01T00:10:00Z", "attestation": testAttestation(),
				"spiffe_id": "spiffe://trust.example/tenant/t/agent/agent-7",
			})
		case "POST /api/v1/workloads/attested-issuance/preview":
			if got := r.Header.Get("Idempotency-Key"); got != "" {
				t.Errorf("attested preview sent Idempotency-Key %q", got)
			}
			assertEncoded("payload_base64", proof)
			writeJSON(w, http.StatusOK, map[string]any{"ready": true, "effect_free": true})
		case "POST /api/v1/workloads/attested-issuance":
			if got := r.Header.Get("Idempotency-Key"); got != "attested-stable-key" {
				t.Errorf("attested issue Idempotency-Key = %q", got)
			}
			assertEncoded("payload_base64", proof)
			writeJSON(w, http.StatusCreated, map[string]any{
				"certificate_pem": "PUBLIC CERTIFICATE", "credential_id": "cred-attested",
				"subject": "verified-workload", "not_after": "2026-09-01T00:10:00Z",
				"attestation": testAttestation(),
			})
		case "POST /api/v1/ephemeral/preview":
			if got := r.Header.Get("Idempotency-Key"); got != "" {
				t.Errorf("ephemeral preview sent Idempotency-Key %q", got)
			}
			assertEncoded("payload_base64", proof)
			writeJSON(w, http.StatusOK, map[string]any{"ready": true, "effect_free": true, "request_id": "request-7"})
		case "POST /api/v1/ephemeral":
			assertEncoded("payload_base64", proof)
			switch r.Header.Get("Idempotency-Key") {
			case "ephemeral-pending-key":
				writeJSON(w, http.StatusAccepted, map[string]any{
					"state": "awaiting_approval", "request_id": "request-7",
					"approval_request_id": "22222222-2222-2222-2222-222222222222",
					"intent_digest":       "digest-7", "subject": "verified-workload",
					"required_approvals": 1, "approvals": 0,
					"expires_at": "2026-09-01T00:05:00Z", "attestation": testAttestation(),
				})
			case "ephemeral-issued-key":
				writeJSON(w, http.StatusCreated, map[string]any{
					"state": "issued", "request_id": "request-7",
					"approval_request_id": "22222222-2222-2222-2222-222222222222",
					"intent_digest":       "digest-7", "subject": "verified-workload",
					"required_approvals": 1, "approvals": 1,
					"expires_at": "2026-09-01T00:05:00Z", "attestation": testAttestation(),
					"certificate_pem": "PUBLIC CERTIFICATE", "credential_id": "cred-ephemeral",
					"certificate_id": "33333333-3333-3333-3333-333333333333",
					"not_after":      "2026-09-01T00:10:00Z",
					"spiffe_id":      "spiffe://trust.example/tenant/t/ephemeral/verified-workload",
				})
			default:
				t.Errorf("ephemeral issue Idempotency-Key = %q", r.Header.Get("Idempotency-Key"))
				writeJSON(w, http.StatusBadRequest, map[string]any{"title": "bad key"})
			}
		case "POST /api/v1/ephemeral/22222222-2222-2222-2222-222222222222/approvals":
			if got := r.Header.Get("Idempotency-Key"); got != "approval-stable-key" {
				t.Errorf("approval Idempotency-Key = %q", got)
			}
			if body["request_id"] != "22222222-2222-2222-2222-222222222222" || body["intent_digest"] != "digest-7" || body["action"] != "issue" {
				t.Errorf("approval body = %#v", body)
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id": "22222222-2222-2222-2222-222222222222", "intent_digest": "digest-7",
				"resource": "ephemeral", "action": "issue", "approver": "approver-8",
				"approvals": 1, "approval_count": 1, "required_approvals": 1, "status": "approved",
			})
		case "GET /api/v1/broker/agent-identities":
			if got := r.URL.Query(); got.Get("limit") != "17" || got.Get("cursor") != "cursor-1" || got.Get("q") != "agent-7" || got.Get("method") != "k8s_sat" || got.Get("state") != "valid" {
				t.Errorf("broker history query = %q", got.Encode())
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"items": []any{map[string]any{
					"certificate_id": "11111111-1111-1111-1111-111111111111", "fingerprint": "sha256:abc",
					"certificate_subject": "verified-agent", "serial": "7", "recorded_at": "2026-08-31T23:00:00Z",
					"lifecycle_status": "active", "state": "valid", "state_reason": "inside validity window",
					"metadata_state": "recorded", "generated_at": "2026-08-31T23:01:00Z", "projection_state": "current",
					"spiffe_id": "spiffe://trust.example/tenant/t/agent/agent-7",
				}},
				"next_cursor": "cursor-2", "generated_at": "2026-08-31T23:01:00Z",
				"projection_state": "current", "history_scope": "broker_issued_certificates",
			})
		case "GET /api/v1/broker/agent-identities/11111111-1111-1111-1111-111111111111":
			writeJSON(w, http.StatusOK, map[string]any{
				"certificate_id": "11111111-1111-1111-1111-111111111111", "fingerprint": "sha256:abc",
				"certificate_subject": "verified-agent", "serial": "7", "recorded_at": "2026-08-31T23:00:00Z",
				"lifecycle_status": "active", "state": "valid", "state_reason": "inside validity window",
				"metadata_state": "unavailable", "generated_at": "2026-08-31T23:01:00Z", "projection_state": "current",
			})
		default:
			t.Errorf("unexpected SDK request %s %s", r.Method, r.URL.RequestURI())
			writeJSON(w, http.StatusNotFound, map[string]any{"title": "not found"})
		}
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token", WithRetry(RetryPolicy{MaxAttempts: 1}))
	ctx := context.Background()
	brokerRequest := BrokerAgentIdentityRequest{
		AgentID: "agent-7", Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY",
		Scopes: []string{"inventory:read"}, TaskEnvelope: task, TTLSeconds: 600,
	}
	if preview, err := client.PreviewBrokerAgentIdentity(ctx, brokerRequest); err != nil || !preview.Ready || !preview.EffectFree {
		t.Fatalf("PreviewBrokerAgentIdentity = %#v, %v", preview, err)
	}
	broker, err := client.IssueBrokerAgentIdentityKeyed(ctx, brokerRequest, "broker-stable-key")
	if err != nil {
		t.Fatalf("IssueBrokerAgentIdentityKeyed: %v", err)
	}
	if broker.SPIFFEID == nil || *broker.SPIFFEID != "spiffe://trust.example/tenant/t/agent/agent-7" {
		t.Fatalf("broker spiffe_id = %#v", broker.SPIFFEID)
	}

	attestedRequest := AttestedSVIDRequest{Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY", TTLSeconds: 600}
	if preview, err := client.PreviewAttestedSVID(ctx, attestedRequest); err != nil || !preview.Ready || !preview.EffectFree {
		t.Fatalf("PreviewAttestedSVID = %#v, %v", preview, err)
	}
	attested, err := client.IssueAttestedSVIDKeyed(ctx, attestedRequest, "attested-stable-key")
	if err != nil || attested.CredentialID != "cred-attested" || attested.SPIFFEID != nil {
		t.Fatalf("IssueAttestedSVIDKeyed = %#v, %v", attested, err)
	}

	ephemeralRequest := EphemeralCredentialRequest{
		RequestID: "request-7", Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY", TTLSeconds: 600,
	}
	if preview, err := client.PreviewEphemeralCredential(ctx, ephemeralRequest); err != nil || !preview.Ready || !preview.EffectFree {
		t.Fatalf("PreviewEphemeralCredential = %#v, %v", preview, err)
	}
	pending, err := client.IssueEphemeralCredentialKeyed(ctx, ephemeralRequest, "ephemeral-pending-key")
	if err != nil || !pending.IsPending() || pending.IsIssued() {
		t.Fatalf("pending IssueEphemeralCredentialKeyed = %#v, %v", pending, err)
	}
	approval, err := client.ApproveEphemeralCredentialKeyed(ctx, pending.ApprovalRequestID, EphemeralApprovalRequest{
		Action: "issue", RequestID: pending.ApprovalRequestID, IntentDigest: pending.IntentDigest,
	}, "approval-stable-key")
	if err != nil || approval.Status != "approved" {
		t.Fatalf("ApproveEphemeralCredentialKeyed = %#v, %v", approval, err)
	}
	issued, err := client.IssueEphemeralCredentialKeyed(ctx, ephemeralRequest, "ephemeral-issued-key")
	if err != nil || !issued.IsIssued() || issued.IsPending() || issued.SPIFFEID == nil {
		t.Fatalf("issued IssueEphemeralCredentialKeyed = %#v, %v", issued, err)
	}

	page, err := client.ListBrokerAgentIdentities(ctx, BrokerAgentIdentityListOptions{
		Limit: 17, Cursor: "cursor-1", Query: "agent-7", Method: "k8s_sat", State: "valid",
	})
	if err != nil || len(page.Items) != 1 || page.Items[0].SPIFFEID == nil || page.NextCursor != "cursor-2" || page.ProjectionState != "current" {
		t.Fatalf("ListBrokerAgentIdentities = %#v, %v", page, err)
	}
	history, err := client.GetBrokerAgentIdentity(ctx, "11111111-1111-1111-1111-111111111111")
	if err != nil || history.SPIFFEID != nil || history.MetadataState != "unavailable" {
		t.Fatalf("GetBrokerAgentIdentity = %#v, %v", history, err)
	}

	if !bytes.Equal(proof, wantProof) || !bytes.Equal(task, wantTask) {
		t.Fatal("SDK modified caller-owned proof or task-envelope bytes")
	}
	if calls != 10 {
		t.Fatalf("SDK request count = %d, want 10", calls)
	}
}

func TestWorkloadSDKRejectsUnexpectedSuccessStatusEmptyBodyAndStateMismatch(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		call   func(*Client) error
	}{
		{
			name: "broker issue returned 200 instead of 201", status: http.StatusOK, body: `{}`,
			call: func(c *Client) error {
				_, err := c.IssueBrokerAgentIdentityKeyed(context.Background(), BrokerAgentIdentityRequest{}, "stable-key")
				return err
			},
		},
		{
			name: "attested preview returned 201 instead of 200", status: http.StatusCreated, body: `{}`,
			call: func(c *Client) error {
				_, err := c.PreviewAttestedSVID(context.Background(), AttestedSVIDRequest{})
				return err
			},
		},
		{
			name: "broker issue returned an empty 201", status: http.StatusCreated, body: ``,
			call: func(c *Client) error {
				_, err := c.IssueBrokerAgentIdentityKeyed(context.Background(), BrokerAgentIdentityRequest{}, "stable-key")
				return err
			},
		},
		{
			name: "ephemeral 202 claimed issued", status: http.StatusAccepted, body: `{"state":"issued"}`,
			call: func(c *Client) error {
				_, err := c.IssueEphemeralCredentialKeyed(context.Background(), EphemeralCredentialRequest{}, "stable-key")
				return err
			},
		},
		{
			name: "ephemeral 201 claimed awaiting approval", status: http.StatusCreated, body: `{"state":"awaiting_approval"}`,
			call: func(c *Client) error {
				_, err := c.IssueEphemeralCredentialKeyed(context.Background(), EphemeralCredentialRequest{}, "stable-key")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			client := New(srv.URL, "trst_test-token", WithRetry(RetryPolicy{MaxAttempts: 1}))
			err := tt.call(client)
			if err == nil {
				t.Fatal("unexpected server success shape was accepted")
			}
			var contractErr *ResponseContractError
			if !errors.As(err, &contractErr) {
				t.Fatalf("error = %T %v, want *ResponseContractError", err, err)
			}
			if contractErr.Status != tt.status {
				t.Fatalf("contract error status = %d, want %d", contractErr.Status, tt.status)
			}
			if got, ok := AsResponseContractError(err); !ok || got != contractErr {
				t.Fatalf("AsResponseContractError = %#v, %v", got, ok)
			}
		})
	}
}

func TestSensitiveWorkloadRequestRefusesRedirectAndPreservesCallerBytes(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		writeJSON(w, http.StatusCreated, map[string]any{"credential_id": "unexpected"})
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	proof := []byte("one-time-proof")
	wantProof := append([]byte(nil), proof...)
	client := New(source.URL, "trst_test-token", WithRetry(RetryPolicy{MaxAttempts: 1}))
	_, err := client.IssueAttestedSVIDKeyed(context.Background(), AttestedSVIDRequest{
		Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY",
	}, "stable-key")
	if err == nil {
		t.Fatal("sensitive issuance followed a redirect")
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target received %d proof-bearing requests, want 0", redirected.Load())
	}
	if !bytes.Equal(proof, wantProof) {
		t.Fatal("redirect refusal modified caller-owned proof bytes")
	}
}

func TestSensitiveWorkloadRequestBodiesAreWipedAcrossRetries(t *testing.T) {
	proof := []byte("retryable-sensitive-proof")
	wantProof := append([]byte(nil), proof...)
	wantEncoded := base64.StdEncoding.EncodeToString(proof)
	var attempts int
	var bodies []*wipingReadCloser
	var keys []string
	var wireBodies []string

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		body, ok := req.Body.(*wipingReadCloser)
		if !ok {
			t.Fatalf("request body = %T, want *wipingReadCloser", req.Body)
		}
		wire, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		bodies = append(bodies, body)
		keys = append(keys, req.Header.Get("Idempotency-Key"))
		wireBodies = append(wireBodies, string(wire))
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     http.Header{"Content-Type": []string{"application/problem+json"}, "Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader(`{"title":"retry"}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{
				"certificate_pem":"PUBLIC CERTIFICATE","credential_id":"cred-1",
				"subject":"verified","not_after":"2026-09-01T00:10:00Z",
				"attestation":{"id":"a","method":"k8s_sat","subject":"verified","selectors":[],"verified_at":"2026-08-31T23:00:00Z"}
			}`)),
			Request: req,
		}, nil
	})
	client := New("https://control.example", "trst_test-token",
		WithHTTPClient(&http.Client{Transport: transport}),
		WithRetry(RetryPolicy{MaxAttempts: 2, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}),
	)
	if _, err := client.IssueAttestedSVIDKeyed(context.Background(), AttestedSVIDRequest{
		Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY",
	}, "same-key-on-retry"); err != nil {
		t.Fatalf("IssueAttestedSVIDKeyed after retry: %v", err)
	}
	if attempts != 2 || len(bodies) != 2 {
		t.Fatalf("attempts=%d bodies=%d, want two", attempts, len(bodies))
	}
	for i, body := range bodies {
		if !allZero(body.data) {
			t.Fatalf("attempt %d retained SDK-owned JSON bytes after request completion", i+1)
		}
		if !strings.Contains(wireBodies[i], wantEncoded) {
			t.Fatalf("attempt %d wire body did not contain canonical base64 proof", i+1)
		}
		if keys[i] != "same-key-on-retry" {
			t.Fatalf("attempt %d Idempotency-Key = %q", i+1, keys[i])
		}
	}
	if !bytes.Equal(proof, wantProof) {
		t.Fatal("retry handling modified caller-owned proof bytes")
	}
}

func TestEffectFreeWorkloadPreviewRetriesWithoutMutationKey(t *testing.T) {
	proof := []byte("preview-proof")
	var attempts int
	var keys []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		keys = append(keys, req.Header.Get("Idempotency-Key"))
		_, _ = io.Copy(io.Discard, req.Body)
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     http.Header{"Content-Type": []string{"application/problem+json"}, "Retry-After": []string{"0"}},
				Body:       io.NopCloser(strings.NewReader(`{"title":"retry"}`)), Request: req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ready":true,"effect_free":true}`)), Request: req,
		}, nil
	})
	client := New("https://control.example", "trst_test-token",
		WithHTTPClient(&http.Client{Transport: transport}),
		WithRetry(RetryPolicy{MaxAttempts: 2, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}),
	)
	preview, err := client.PreviewAttestedSVID(context.Background(), AttestedSVIDRequest{
		Method: "k8s_sat", Payload: proof, PublicKeyPEM: "PUBLIC KEY",
	})
	if err != nil || !preview.Ready || !preview.EffectFree {
		t.Fatalf("PreviewAttestedSVID after retry = %#v, %v", preview, err)
	}
	if attempts != 2 {
		t.Fatalf("preview attempts = %d, want 2", attempts)
	}
	for attempt, key := range keys {
		if key != "" {
			t.Fatalf("effect-free preview attempt %d sent Idempotency-Key %q", attempt+1, key)
		}
	}
}

func TestBrokerAgentIdentityIteratorPreservesHistoryFilters(t *testing.T) {
	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("limit") != "1" || query.Get("q") != "agent" || query.Get("method") != "k8s_sat" || query.Get("state") != "valid" {
			t.Errorf("iterator changed filters: %q", query.Encode())
		}
		cursor := query.Get("cursor")
		cursors = append(cursors, cursor)
		item := map[string]any{
			"certificate_id": "certificate-" + strconv.Itoa(len(cursors)), "fingerprint": "sha256:abc",
			"certificate_subject": "verified-agent", "serial": strconv.Itoa(len(cursors)),
			"recorded_at": "2026-08-31T23:00:00Z", "lifecycle_status": "active",
			"state": "valid", "state_reason": "inside validity window", "metadata_state": "recorded",
			"generated_at": "2026-08-31T23:01:00Z", "projection_state": "current",
		}
		next := ""
		if cursor == "" {
			next = "cursor-2"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": []any{item}, "next_cursor": next, "generated_at": "2026-08-31T23:01:00Z",
			"projection_state": "current", "history_scope": "broker_issued_certificates",
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token")
	iterator := client.BrokerAgentIdentities(BrokerAgentIdentityListOptions{
		Limit: 1, Query: "agent", Method: "k8s_sat", State: "valid",
	})
	items, err := iterator.Collect(context.Background())
	if err != nil {
		t.Fatalf("BrokerAgentIdentities.Collect: %v", err)
	}
	if len(items) != 2 || strings.Join(cursors, ",") != ",cursor-2" {
		t.Fatalf("items=%d cursors=%v, want two pages with unchanged filters", len(items), cursors)
	}
}

func TestKeyedWorkloadMutationRejectsEmptyKeyBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	client := New("https://control.example", "trst_test-token", WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("transport should not run")
		}),
	}))
	_, err := client.IssueBrokerAgentIdentityKeyed(context.Background(), BrokerAgentIdentityRequest{}, "  ")
	if err == nil || !strings.Contains(err.Error(), "Idempotency-Key") {
		t.Fatalf("empty keyed mutation error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("transport calls = %d, want 0", calls.Load())
	}
}

func testAttestation() map[string]any {
	return map[string]any{
		"id": "attestation-7", "method": "k8s_sat", "subject": "verified-workload",
		"selectors": []string{"namespace:payments"}, "verified_at": "2026-08-31T23:00:00Z",
	}
}

func allZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
