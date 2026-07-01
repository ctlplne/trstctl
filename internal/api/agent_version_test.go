package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/protocol"
)

// stubEnroller is a minimal BootstrapEnroller that accepts any token and returns a
// fixed chain, so the version-negotiation logic (SCHEMA-003) can be tested without
// the real enrollment authority.
type stubEnroller struct{}

func (stubEnroller) EnrollBootstrap(_ context.Context, _ []byte, _ []byte) ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), nil
}
func (stubEnroller) CABundlePEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
}

func enrollServer(t *testing.T) *httptest.Server {
	t.Helper()
	a := api.New(nil, nil, nil, api.WithAgentEnroller(stubEnroller{}))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv
}

func postEnroll(t *testing.T, url string, hdr map[string]string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"token": "tok",
		"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})
	req, err := http.NewRequest(http.MethodPost, url+"/enroll/bootstrap", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /enroll/bootstrap: %v", err)
	}
	return resp
}

// TestPriorReleaseAgentRequestStillAccepted is the SCHEMA-003 acceptance: a request
// from a prior-release agent that predates the version handshake (it sends NO
// X-Trstctl-Agent-Protocol header) is still accepted, so a rolling fleet upgrade
// does not break already-deployed agents. The pre-fix server made no version
// decision at all; this proves the new handshake is additive and backward-compatible
// while still echoing the server protocol so an agent can detect skew.
func TestPriorReleaseAgentRequestStillAccepted(t *testing.T) {
	srv := enrollServer(t)

	// A frozen prior-release request: plain JSON, no version/protocol headers.
	resp := postEnroll(t, srv.URL, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prior-release agent (no version header) got %d, want 200 (handshake must be additive)", resp.StatusCode)
	}
	// The server always advertises its protocol version, so an agent can detect skew.
	if got := resp.Header.Get(protocol.HeaderServerProtocol); got != strconv.Itoa(protocol.Version) {
		t.Errorf("server protocol header = %q, want %d", got, protocol.Version)
	}
}

// TestCurrentAgentProtocolAccepted: a request carrying the current protocol version
// is accepted (the happy path of the handshake).
func TestCurrentAgentProtocolAccepted(t *testing.T) {
	srv := enrollServer(t)
	resp := postEnroll(t, srv.URL, map[string]string{
		protocol.HeaderAgentProtocol: strconv.Itoa(protocol.Version),
		protocol.HeaderAgentVersion:  "v9.9.9",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("current-protocol agent got %d, want 200", resp.StatusCode)
	}
}

// TestUnsupportedAgentProtocolRejected: a request whose protocol is outside the
// supported window is rejected with a clear 400, rather than failing opaquely later
// (SCHEMA-003). This is the decision the pre-fix server never made.
func TestUnsupportedAgentProtocolRejected(t *testing.T) {
	srv := enrollServer(t)
	// One beyond MaxSupportedVersion is out of the window.
	resp := postEnroll(t, srv.URL, map[string]string{
		protocol.HeaderAgentProtocol: strconv.Itoa(protocol.MaxSupportedVersion + 1),
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported-protocol agent got %d, want 400", resp.StatusCode)
	}
}
