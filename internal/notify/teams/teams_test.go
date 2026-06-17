package teams_test

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
	"trstctl.com/trstctl/internal/notify/teams"
)

// TestTeamsConforms drives the channel through the shared notification conformance
// harness: it must report a name and deliver a well-formed alert without error, against
// the in-process Teams webhook double.
func TestTeamsConforms(t *testing.T) {
	srv := newFakeTeams()
	defer srv.Close()
	ch := teams.New(srv.URL(), teams.WithHTTPClient(srv.Client()))

	if err := notify.Conform(context.Background(), ch); err != nil {
		t.Fatalf("Teams channel failed notification conformance: %v", err)
	}
	if ch.Name() != "msteams" {
		t.Fatalf("Name() = %q, want %q", ch.Name(), "msteams")
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no posts")
	}
}

// TestDeliversCard proves Notify posts a well-formed MessageCard whose text is the
// formatted alert line, so the alert's subject reaches the channel.
func TestDeliversCard(t *testing.T) {
	srv := newFakeTeams()
	defer srv.Close()
	ch := teams.New(srv.URL(), teams.WithHTTPClient(srv.Client()))

	const subject = "cn=web.example.com"
	alert := notify.Alert{
		Kind:     notify.KindCertificateExpiry,
		TenantID: "t-1",
		Subject:  subject,
		Serial:   "0a:0b:0c",
	}
	if err := ch.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	card := srv.LastCard(t)
	if card.Type != "MessageCard" {
		t.Errorf("@type = %q, want MessageCard", card.Type)
	}
	if card.Context != "http://schema.org/extensions" {
		t.Errorf("@context = %q, want http://schema.org/extensions", card.Context)
	}
	if card.Summary != "trstctl alert" {
		t.Errorf("summary = %q, want %q", card.Summary, "trstctl alert")
	}
	if !strings.Contains(card.Text, subject) {
		t.Errorf("card text %q does not contain the alert subject %q", card.Text, subject)
	}
	// The card text is the shared formatted line, so it should match FormatMessage.
	if card.Text != notify.FormatMessage(alert) {
		t.Errorf("card text = %q, want FormatMessage output %q", card.Text, notify.FormatMessage(alert))
	}
}

// TestWebhookNotLeakedOnError (AN-8): a non-2xx response must surface the service's
// error body but never the secret webhook URL, even on the failure path.
func TestWebhookNotLeakedOnError(t *testing.T) {
	srv := newFakeTeams()
	srv.FailNext(http.StatusBadRequest, "Bad payload received by the webhook.")
	defer srv.Close()

	// A webhook URL with a guessable secret token in it, so a leak is detectable.
	const secret = "super-secret-webhook-token-do-not-log"
	ch := teams.New(srv.URL()+"/"+secret, teams.WithHTTPClient(srv.Client()))

	err := ch.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=leak.example",
	})
	if err == nil {
		t.Fatal("expected an error from the non-2xx response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("want a 400 status in the error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Bad payload") {
		t.Errorf("error should surface the Teams response body, got: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the webhook URL secret: %v", err)
	}
}

func TestDefaultClientRejectsUnsafeWebhookEndpoints(t *testing.T) {
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"}
	for _, target := range []string{
		"http://outlook.office.example/webhook/SuperSecretToken",
		"https://localhost/webhook/SuperSecretToken",
		"https://127.0.0.1/webhook/SuperSecretToken",
		"https://10.0.0.5/webhook/SuperSecretToken",
		"https://169.254.169.254/latest/meta-data/SuperSecretToken",
	} {
		ch := teams.New(target)
		err := ch.Notify(context.Background(), alert)
		if err == nil {
			t.Fatalf("default Teams client delivered to unsafe endpoint %s", target)
		}
		if !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Fatalf("default Teams client error for %s = %v, want SSRF block", target, err)
		}
		if strings.Contains(err.Error(), target) || strings.Contains(err.Error(), "SuperSecretToken") {
			t.Fatalf("unsafe endpoint error leaked target URL/secret: %v", err)
		}
	}
}

// --- fakeTeams: an in-process double of a Teams incoming webhook --------------------
//
// A real Teams incoming webhook accepts a POSTed MessageCard and replies 200 with the
// literal body "1" on success, or a 4xx with a plain-text error on a bad payload. This
// double captures the last posted card so a test can assert its shape, counts posts, and
// can be told to fail the next post (to exercise the error path). It never echoes the
// request URL in any response, so surfacing its body as the channel's error text cannot
// leak the webhook URL (AN-8). No crypto/* (AN-3) — there is nothing to sign.

type fakeTeams struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    int
	lastBody []byte
	failNext bool
	failCode int
	failBody string
}

func newFakeTeams() *fakeTeams {
	s := &fakeTeams{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeTeams) URL() string { return s.srv.URL }

func (s *fakeTeams) Client() *http.Client { return s.srv.Client() }

func (s *fakeTeams) Close() { s.srv.Close() }

// Calls is the number of posts served.
func (s *fakeTeams) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// FailNext makes the next post respond with status code and body.
func (s *fakeTeams) FailNext(code int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = true
	s.failCode = code
	s.failBody = body
}

// LastCard decodes the most recently posted MessageCard.
func (s *fakeTeams) LastCard(t *testing.T) capturedCard {
	t.Helper()
	s.mu.Lock()
	raw := append([]byte(nil), s.lastBody...)
	s.mu.Unlock()
	var c capturedCard
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode captured card %q: %v", raw, err)
	}
	return c
}

func (s *fakeTeams) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	s.mu.Lock()
	s.calls++
	s.lastBody = body
	failNext, failCode, failBody := s.failNext, s.failCode, s.failBody
	s.failNext = false
	s.mu.Unlock()

	if failNext {
		// Plain-text error, like a real webhook; it never echoes the request URL.
		w.WriteHeader(failCode)
		_, _ = io.WriteString(w, failBody)
		return
	}
	// A real Teams webhook returns 200 with the literal body "1" on success.
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "1")
}

// capturedCard mirrors the MessageCard wire shape the channel posts.
type capturedCard struct {
	Type    string `json:"@type"`
	Context string `json:"@context"`
	Summary string `json:"summary"`
	Text    string `json:"text"`
}
