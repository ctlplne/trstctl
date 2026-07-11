// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type rightSizeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f rightSizeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestConnectorRightSizeMutatesAndIndependentlyReadsBackScopes(t *testing.T) {
	const (
		tenantID = "d0d00000-0000-4000-8000-000000000201"
		endpoint = "https://entitlements.example.test"
	)
	readback := []byte(`{"scopes":["read"]}`)
	calls := 0
	cleaned := false
	var responseBodies []*retainingCredentialResponseBody
	runtime := &connectorRightSizeRuntime{
		bindings: map[string]config.ConnectorRightSizeBinding{
			rightSizeBindingKey(tenantID, "least-privilege"): {
				TenantID: tenantID, Connector: "least-privilege", Endpoint: endpoint, TokenRef: "secret://right-size/token",
			},
		},
		credential: func(_ context.Context, gotTenant, ref string) ([]byte, func(), error) {
			if gotTenant != tenantID || ref != "secret://right-size/token" {
				t.Fatalf("credential lookup = tenant %q ref %q", gotTenant, ref)
			}
			value := []byte("right-size-token")
			return value, func() { secret.Wipe(value); cleaned = true }, nil
		},
		client: &http.Client{Transport: rightSizeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.URL.String() != endpoint+"/v1/entitlements/service-1" {
				t.Fatalf("request URL = %q", request.URL)
			}
			if request.Header.Get("Authorization") != "Bearer right-size-token" || request.Header.Get("Idempotency-Key") != "event-1" || request.Header.Get("X-Trstctl-Tenant") != tenantID {
				t.Fatalf("request headers do not carry the bound credential/idempotency/tenant")
			}
			switch request.Method {
			case http.MethodPatch:
				body, err := io.ReadAll(request.Body)
				if err != nil || !bytes.Contains(body, []byte(`"remove_scopes":["write"]`)) || !bytes.Contains(body, []byte(`"recommended_scopes":["read"]`)) {
					t.Fatalf("mutation body = %s err=%v", body, err)
				}
				responseBody := newRetainingCredentialResponseBody([]byte(`{"status":"applied","mutation_id":"mutation-1","removed_scopes":["write"],"rollback_ref":"rollback-1"}`))
				responseBodies = append(responseBodies, responseBody)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: responseBody}, nil
			case http.MethodGet:
				body := newRetainingCredentialResponseBody(readback)
				responseBodies = append(responseBodies, body)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
			default:
				t.Fatalf("unexpected method %s", request.Method)
				return nil, nil
			}
		})},
	}
	delta, err := json.Marshal(connectorRightSizeScopeDelta{RemoveScopes: []string{"write"}, RecommendedScopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := runtime.Mutate(context.Background(), orchestrator.Message{
		TenantID: tenantID, Destination: orchestrator.DestinationConnectorRightSize, IdempotencyKey: "event-1",
	}, projections.RemediationPlaybookRunRecorded{
		Action: "right_size", Connector: "least-privilege", Target: "service-1", ScopeDelta: delta,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || mutation.MutationID != "mutation-1" || mutation.RollbackRef != "rollback-1" || mutation.ReadbackDigest != crypto.SHA256Hex(readback) {
		t.Fatalf("mutation = %+v calls=%d", mutation, calls)
	}
	if !cleaned {
		t.Fatal("right-size credential was not destroyed after readback")
	}
	for _, body := range responseBodies {
		body.assertObservedBytesWiped(t)
	}
}

func TestReadRightSizeResponseWipesRejectedBody(t *testing.T) {
	body := newRetainingCredentialResponseBody([]byte(`{"echo":"Bearer receiver-controlled-secret"}`))
	_, err := readRightSizeResponse(&http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Body:       body,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("rejected right-size response error = %v", err)
	}
	body.assertObservedBytesWiped(t)
}

func TestConnectorRightSizeRejectsEscapedCredentialEchoesBeforeRetention(t *testing.T) {
	const tenantID = "d0d00000-0000-4000-8000-000000000203"
	for _, test := range []struct {
		name      string
		echoOnGet bool
	}{
		{name: "mutation receipt", echoOnGet: false},
		{name: "readback", echoOnGet: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The receiver encodes the quote and backslash as Unicode escapes, so
			// a raw bytes.Contains(body, token) check cannot see the credential.
			// The response fields must be decoded into wipeable byte slices first.
			tokenLiteral := []byte("receiver-token\"\\suffix")
			var responseBodies []*retainingCredentialResponseBody
			calls := 0
			cleaned := false
			runtime := &connectorRightSizeRuntime{
				bindings: map[string]config.ConnectorRightSizeBinding{
					rightSizeBindingKey(tenantID, "least-privilege"): {
						TenantID: tenantID, Connector: "least-privilege", Endpoint: "https://entitlements.example.test", TokenRef: "secret://token",
					},
				},
				credential: func(context.Context, string, string) ([]byte, func(), error) {
					value := append([]byte(nil), tokenLiteral...)
					return value, func() { secret.Wipe(value); cleaned = true }, nil
				},
				client: &http.Client{Transport: rightSizeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					var responseBody []byte
					switch request.Method {
					case http.MethodPatch:
						if test.echoOnGet {
							responseBody = []byte(`{"status":"applied","mutation_id":"mutation-3","removed_scopes":["write"],"rollback_ref":"rollback-3"}`)
						} else {
							responseBody = []byte(`{"status":"applied","mutation_id":"receiver-token\u0022\u005csuffix","removed_scopes":["write"],"rollback_ref":"rollback-3"}`)
						}
					case http.MethodGet:
						responseBody = []byte(`{"scopes":["receiver-token\u0022\u005csuffix"]}`)
					default:
						t.Fatalf("unexpected method %s", request.Method)
					}
					body := newRetainingCredentialResponseBody(responseBody)
					responseBodies = append(responseBodies, body)
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
				})},
			}
			delta := json.RawMessage(`{"remove_scopes":["write"],"recommended_scopes":["read"]}`)
			_, err := runtime.Mutate(context.Background(), orchestrator.Message{
				TenantID: tenantID, Destination: orchestrator.DestinationConnectorRightSize, IdempotencyKey: "event-3",
			}, projections.RemediationPlaybookRunRecorded{
				Action: "right_size", Connector: "least-privilege", Target: "service-3", ScopeDelta: delta,
			})
			if err == nil || !strings.Contains(err.Error(), "reflected the request credential") {
				t.Fatalf("credential echo error = %v", err)
			}
			wantCalls := 1
			if test.echoOnGet {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("HTTP calls = %d, want %d", calls, wantCalls)
			}
			if !cleaned {
				t.Fatal("right-size credential was not destroyed after echo rejection")
			}
			for _, body := range responseBodies {
				body.assertObservedBytesWiped(t)
			}
		})
	}
}

func TestConnectorRightSizeRejectsStaleReadback(t *testing.T) {
	const tenantID = "d0d00000-0000-4000-8000-000000000202"
	runtime := &connectorRightSizeRuntime{
		bindings: map[string]config.ConnectorRightSizeBinding{
			rightSizeBindingKey(tenantID, "least-privilege"): {
				TenantID: tenantID, Connector: "least-privilege", Endpoint: "https://entitlements.example.test", TokenRef: "secret://token",
			},
		},
		credential: func(context.Context, string, string) ([]byte, func(), error) {
			return []byte("token"), func() {}, nil
		},
		client: &http.Client{Transport: rightSizeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPatch {
				return rightSizeHTTPResponse(http.StatusOK, `{"status":"applied","mutation_id":"mutation-2","removed_scopes":["write"],"rollback_ref":"rollback-2"}`), nil
			}
			return rightSizeHTTPResponse(http.StatusOK, `{"scopes":["read","write"]}`), nil
		})},
	}
	delta := json.RawMessage(`{"remove_scopes":["write"],"recommended_scopes":["read"]}`)
	_, err := runtime.Mutate(context.Background(), orchestrator.Message{
		TenantID: tenantID, Destination: orchestrator.DestinationConnectorRightSize, IdempotencyKey: "event-2",
	}, projections.RemediationPlaybookRunRecorded{
		Action: "right_size", Connector: "least-privilege", Target: "service-2", ScopeDelta: delta,
	})
	if err == nil || !strings.Contains(err.Error(), "still contains removed scope") {
		t.Fatalf("stale readback error = %v", err)
	}
}

func rightSizeHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
