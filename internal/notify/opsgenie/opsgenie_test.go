package opsgenie_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/opsgenie"
)

const testKey = "genie-key-do-not-log"

func newChannel(t *testing.T, srv *fakeOG, apiKey string) *opsgenie.Channel {
	t.Helper()
	return opsgenie.New(apiKey,
		opsgenie.WithEndpoint(srv.URL()),
		opsgenie.WithHTTPClient(srv.Client()))
}

// TestOpsGenieConforms drives the channel through the shared notification conformance
// harness (notify.Conform) against the key-verifying double: it must report a name and
// deliver a well-formed alert without error, and the double must have served the call.
func TestOpsGenieConforms(t *testing.T) {
	srv := newFakeOG(testKey)
	defer srv.Close()
	c := newChannel(t, srv, testKey)

	if got := c.Name(); got != "opsgenie" {
		t.Fatalf("Name() = %q, want %q", got, "opsgenie")
	}
	if err := notify.Conform(context.Background(), c); err != nil {
		t.Fatalf("OpsGenie channel failed notification conformance: %v", err)
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
	// The conformance probe carries a Subject; FormatMessage of it must reach OpsGenie as
	// the alert message.
	if msg := srv.LastMessage(); !strings.Contains(msg, "conformance.example") {
		t.Fatalf("delivered message = %q, want it to contain the alert subject", msg)
	}
}

// TestBadKeyRejected: a wrong API key must fail closed at the GenieKey auth check (the
// double verifies the header the way the real API does, rejecting a mismatch with a 401),
// not silently succeed.
func TestBadKeyRejected(t *testing.T) {
	srv := newFakeOG(testKey)
	defer srv.Close()
	c := newChannel(t, srv, "wrong-key")

	err := c.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=example",
	})
	if err == nil {
		t.Fatal("notify with a wrong key succeeded; GenieKey auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 auth rejection, got: %v", err)
	}
}

// TestKeyNeverLogged (AN-8): a returned error must never leak the API key, even on the
// failure path.
func TestKeyNeverLogged(t *testing.T) {
	srv := newFakeOG(testKey)
	defer srv.Close()
	const secret = "ultra-secret-genie-key"
	c := newChannel(t, srv, secret)

	err := c.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=example",
		Detail:  "leak probe",
	})
	if err == nil {
		t.Fatal("expected an error from the mismatched key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the API key: %v", err)
	}
}

// TestNotifySendsMessageAndDescription verifies the happy path puts FormatMessage(alert)
// in message and alert.Detail in description, and that a valid GenieKey is accepted.
func TestNotifySendsMessageAndDescription(t *testing.T) {
	srv := newFakeOG(testKey)
	defer srv.Close()
	c := newChannel(t, srv, testKey)

	alert := notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=service.example",
		Serial:  "0A1B2C",
		Detail:  "expires in 7 days",
	}
	if err := c.Notify(context.Background(), alert); err != nil {
		t.Fatalf("notify with a good key failed: %v", err)
	}
	if got, want := srv.LastMessage(), notify.FormatMessage(alert); got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got := srv.LastDescription(); got != "expires in 7 days" {
		t.Fatalf("description = %q, want the alert detail", got)
	}
}

func TestDefaultClientRejectsUnsafeEndpoints(t *testing.T) {
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"}
	for _, target := range []string{
		"http://api.opsgenie.com/v2/alerts",
		"https://localhost/v2/alerts",
		"https://127.0.0.1/v2/alerts",
		"https://10.0.0.5/v2/alerts",
		"https://169.254.169.254/latest/meta-data/",
	} {
		ch := opsgenie.New(testKey, opsgenie.WithEndpoint(target))
		err := ch.Notify(context.Background(), alert)
		if err == nil {
			t.Fatalf("default OpsGenie client delivered to unsafe endpoint %s", target)
		}
		if !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Fatalf("default OpsGenie client error for %s = %v, want SSRF block", target, err)
		}
		if strings.Contains(err.Error(), target) {
			t.Fatalf("unsafe endpoint error leaked target URL: %v", err)
		}
	}
}

// --- fakeOG: a faithful in-process double of the OpsGenie Alert API ------------------
//
// It verifies the Authorization GenieKey header the way the real service does (rejecting a
// missing or wrong key with a 401 JSON error so an auth bug in the channel is caught here),
// accepts a create-alert POST, and captures the decoded message and description so a test
// can assert what the channel sent. Its error body never echoes the key, so surfacing it as
// the channel's error text cannot leak credentials (AN-8). No crypto/* (AN-3) — GenieKey
// auth needs none.

type fakeOG struct {
	srv *httptest.Server
	key string

	mu          sync.Mutex
	calls       int
	lastMessage string
	lastDesc    string
}

func newFakeOG(key string) *fakeOG {
	s := &fakeOG{key: key}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeOG) URL() string { return s.srv.URL }

func (s *fakeOG) Client() *http.Client { return s.srv.Client() }

func (s *fakeOG) Close() { s.srv.Close() }

// Calls is the number of authenticated requests served.
func (s *fakeOG) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// LastMessage / LastDescription return the most recently captured create-alert fields.
func (s *fakeOG) LastMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastMessage
}

func (s *fakeOG) LastDescription() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastDesc
}

func (s *fakeOG) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "GenieKey "+s.key {
		s.fail(w, http.StatusUnauthorized, "could not authenticate")
		return
	}
	if r.Method != http.MethodPost {
		s.fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Message     string `json:"message"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed alert")
		return
	}

	s.mu.Lock()
	s.calls++
	s.lastMessage = req.Message
	s.lastDesc = req.Description
	s.mu.Unlock()

	// OpsGenie returns 202 Accepted with a request-status envelope.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"result":    "Request will be processed",
		"requestId": "fake-request-id",
	})
}

// fail mirrors an OpsGenie error envelope. It deliberately never echoes the key, so
// surfacing this body as the channel's error text cannot leak credentials (AN-8).
func (s *fakeOG) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": msg,
		"took":    0.0,
	})
}
