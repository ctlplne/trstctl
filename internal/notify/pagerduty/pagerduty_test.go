package pagerduty_test

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
	"trstctl.com/trstctl/internal/notify/pagerduty"
)

const testRoutingKey = "pd-routing-key-do-not-log"

func newChannel(t *testing.T, srv *fakePD, routingKey string) *pagerduty.Channel {
	t.Helper()
	return pagerduty.New(routingKey,
		pagerduty.WithEndpoint(srv.URL()),
		pagerduty.WithHTTPClient(srv.Client()))
}

// TestPagerDutyConforms drives the channel through the shared notification conformance
// harness against the routing-key-verifying double: it must report a name and deliver a
// well-formed alert without error.
func TestPagerDutyConforms(t *testing.T) {
	srv := newFakePD(testRoutingKey)
	defer srv.Close()
	c := newChannel(t, srv, testRoutingKey)

	if err := notify.Conform(context.Background(), c); err != nil {
		t.Fatalf("PagerDuty channel failed conformance: %v", err)
	}
	if c.Name() != "pagerduty" {
		t.Fatalf("Name() = %q, want %q", c.Name(), "pagerduty")
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no triggered events")
	}
	if got := srv.LastSummary(); got == "" {
		t.Fatal("double captured no summary from the conformance alert")
	}
}

// TestBadRoutingKeyRejected: a wrong routing key must fail closed at the double's check
// (which verifies routing_key like the real Events API), not silently succeed.
func TestBadRoutingKeyRejected(t *testing.T) {
	srv := newFakePD(testRoutingKey)
	defer srv.Close()
	c := newChannel(t, srv, "wrong-routing-key")

	err := c.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=example",
	})
	if err == nil {
		t.Fatal("Notify with a wrong routing key succeeded; routing key was not enforced")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("want a 400 rejection, got: %v", err)
	}
}

// TestRoutingKeyNeverLogged (AN-8): a returned error must never leak the routing key,
// even on the failure path.
func TestRoutingKeyNeverLogged(t *testing.T) {
	srv := newFakePD(testRoutingKey)
	defer srv.Close()
	const secret = "ultra-secret-routing-key"
	c := newChannel(t, srv, secret)

	err := c.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=example",
	})
	if err == nil {
		t.Fatal("expected an error from the mismatched routing key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the routing key: %v", err)
	}
}

func TestDefaultClientRejectsUnsafeEndpoints(t *testing.T) {
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"}
	for _, target := range []string{
		"http://events.pagerduty.com/v2/enqueue",
		"https://localhost/v2/enqueue",
		"https://127.0.0.1/v2/enqueue",
		"https://10.0.0.5/v2/enqueue",
		"https://169.254.169.254/latest/meta-data/",
	} {
		ch := pagerduty.New(testRoutingKey, pagerduty.WithEndpoint(target))
		err := ch.Notify(context.Background(), alert)
		if err == nil {
			t.Fatalf("default PagerDuty client delivered to unsafe endpoint %s", target)
		}
		if !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Fatalf("default PagerDuty client error for %s = %v, want SSRF block", target, err)
		}
		if strings.Contains(err.Error(), target) {
			t.Fatalf("unsafe endpoint error leaked target URL: %v", err)
		}
	}
}

// --- fakePD: an in-process double of the PagerDuty Events API v2 enqueue endpoint ------
//
// It verifies the routing_key in the request body the way the real service does
// (rejecting a mismatch with a 400 JSON error so a missing/wrong-key bug in the channel
// is caught here), captures the payload summary so a test can assert what the channel
// rendered, and returns the 202 envelope a successful enqueue yields. Its error body
// deliberately never echoes the routing key, so surfacing it as the channel's error text
// cannot leak credentials (AN-8). No crypto/* (AN-3) — routing-key auth needs none.

type fakePD struct {
	srv        *httptest.Server
	routingKey string

	mu          sync.Mutex
	calls       int
	lastSummary string
}

func newFakePD(routingKey string) *fakePD {
	s := &fakePD{routingKey: routingKey}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakePD) URL() string { return s.srv.URL }

func (s *fakePD) Client() *http.Client { return s.srv.Client() }

func (s *fakePD) Close() { s.srv.Close() }

// Calls is the number of accepted (correctly-keyed) events served.
func (s *fakePD) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// LastSummary returns the payload summary of the most recently accepted event.
func (s *fakePD) LastSummary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSummary
}

func (s *fakePD) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		RoutingKey  string `json:"routing_key"`
		EventAction string `json:"event_action"`
		Payload     struct {
			Summary  string `json:"summary"`
			Source   string `json:"source"`
			Severity string `json:"severity"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed event")
		return
	}
	if req.RoutingKey != s.routingKey {
		s.fail(w, http.StatusBadRequest, "invalid routing key")
		return
	}
	if req.EventAction != "trigger" {
		s.fail(w, http.StatusBadRequest, "unsupported event action")
		return
	}

	s.mu.Lock()
	s.calls++
	s.lastSummary = req.Payload.Summary
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "success",
		"message":   "Event processed",
		"dedup_key": "trstctl-dedup",
	})
}

// fail mirrors a PagerDuty error envelope. It deliberately never echoes the routing key,
// so surfacing this body as the channel's error text cannot leak credentials (AN-8).
func (s *fakePD) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "invalid event",
		"message": msg,
		"errors":  []string{msg},
	})
}
