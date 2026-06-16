package slack_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/slack"
)

// TestSlackConforms drives the channel through the shared notification conformance
// harness (the analogue of connector/DNS-01 conformance): construct the channel against
// the double's webhook URL with the double's client, then assert notify.Conform passes
// and that the double actually served the post.
func TestSlackConforms(t *testing.T) {
	srv := newFakeSlack()
	defer srv.Close()
	ch := slack.New(srv.WebhookURL(), slack.WithHTTPClient(srv.Client()))

	if err := notify.Conform(context.Background(), ch); err != nil {
		t.Fatalf("slack channel failed notification conformance: %v", err)
	}
	if srv.Posts() == 0 {
		t.Fatal("conformance ran but the double received no webhook post")
	}
	if ch.Name() != "slack" {
		t.Fatalf("Name() = %q, want %q", ch.Name(), "slack")
	}
}

// TestDeliversFormattedText proves the channel POSTs the shared FormatMessage rendering
// as the Slack "text" field: the captured payload must carry the alert subject.
func TestDeliversFormattedText(t *testing.T) {
	srv := newFakeSlack()
	defer srv.Close()
	ch := slack.New(srv.WebhookURL(), slack.WithHTTPClient(srv.Client()))

	const subject = "cn=web.example.com"
	alert := notify.Alert{
		Kind:     notify.KindCertificateExpiry,
		TenantID: "t-1",
		Subject:  subject,
		Serial:   "0A1B2C",
	}
	if err := ch.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	text := srv.LastText()
	if !strings.Contains(text, subject) {
		t.Fatalf("posted text %q does not contain the alert subject %q", text, subject)
	}
	// It must be the shared rendering, not some ad-hoc string.
	if want := notify.FormatMessage(alert); text != want {
		t.Fatalf("posted text = %q, want the shared FormatMessage rendering %q", text, want)
	}
}

// TestUnknownPathRejected: a post to a path the double does not recognise comes back 404,
// and the channel surfaces that as an error rather than treating it as delivered. This
// pins down the "any 2xx is success, everything else is an error" contract.
func TestUnknownPathRejected(t *testing.T) {
	srv := newFakeSlack()
	defer srv.Close()
	ch := slack.New(srv.URL()+"/nope", slack.WithHTTPClient(srv.Client()))

	err := ch.Notify(context.Background(), notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"})
	if err == nil {
		t.Fatal("post to an unknown webhook path succeeded; non-2xx was not treated as failure")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("want a 404 in the error, got: %v", err)
	}
}

// TestWebhookNotLeakedOnError (AN-8): point the channel at a path the double answers with
// 500 and assert the returned error carries neither the secret webhook path nor the full
// webhook URL — the URL is the credential and must never appear in surfaced errors.
func TestWebhookNotLeakedOnError(t *testing.T) {
	srv := newFakeSlack()
	defer srv.Close()
	const secretPath = "/services/T00000000/B00000000/SuperSecretWebhookToken"
	webhook := srv.URL() + secretPath
	ch := slack.New(webhook, slack.WithHTTPClient(srv.Client()))

	err := ch.Notify(context.Background(), notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"})
	if err == nil {
		t.Fatal("expected an error from the 500 response")
	}
	if strings.Contains(err.Error(), secretPath) {
		t.Fatalf("error leaked the secret webhook path: %v", err)
	}
	if strings.Contains(err.Error(), webhook) {
		t.Fatalf("error leaked the full webhook URL: %v", err)
	}
}

// TestWebhookNotLeakedOnTransportError (AN-8): even when the HTTP doer itself fails (the
// response never arrives, so there is no body to surface), the error must not echo the
// webhook URL. The standard library's *url.Error embeds the request URL, so this guards
// the transport-error path specifically.
func TestWebhookNotLeakedOnTransportError(t *testing.T) {
	const webhook = "https://hooks.slack.example/services/T0/B0/SuperSecretToken"
	ch := slack.New(webhook, slack.WithHTTPClient(failingDoer{}))

	err := ch.Notify(context.Background(), notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=x"})
	if err == nil {
		t.Fatal("expected an error from the failing transport")
	}
	if strings.Contains(err.Error(), webhook) || strings.Contains(err.Error(), "SuperSecretToken") {
		t.Fatalf("transport error leaked the webhook URL/secret: %v", err)
	}
}

// failingDoer always returns a *url.Error that embeds the request URL (exactly what
// net/http does on a dial failure), so the test can prove the channel scrubs it.
type failingDoer struct{}

func (failingDoer) Do(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: errors.New("connection refused")}
}

// --- fakeSlack: a minimal in-process double of a Slack incoming webhook ---------------
//
// It accepts a POST to the configured webhook path, decodes the {"text":...} body, records
// it, and answers 200 (the empty-bodied "ok" a real webhook returns). It answers 404 for
// any other path and 500 for any path under /services that is not the registered webhook,
// so the leak-on-error test has a non-2xx, body-bearing failure to surface. The error
// bodies deliberately never contain the request URL, mirroring Slack — surfacing them
// cannot leak the webhook (AN-8). No crypto/* (AN-3): a webhook needs none.

const webhookPath = "/services/T11111111/B22222222/registeredWebhookToken"

type fakeSlack struct {
	srv *httptest.Server

	mu    sync.Mutex
	texts []string
	posts int
}

func newFakeSlack() *fakeSlack {
	s := &fakeSlack{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeSlack) URL() string { return s.srv.URL }

// WebhookURL is the full URL of the one registered, working webhook.
func (s *fakeSlack) WebhookURL() string { return s.srv.URL + webhookPath }

func (s *fakeSlack) Client() *http.Client { return s.srv.Client() }

func (s *fakeSlack) Close() { s.srv.Close() }

// Posts is the number of accepted webhook posts.
func (s *fakeSlack) Posts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts
}

// LastText returns the "text" of the most recently accepted post.
func (s *fakeSlack) LastText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.texts) == 0 {
		return ""
	}
	return s.texts[len(s.texts)-1]
}

func (s *fakeSlack) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == webhookPath:
		s.accept(w, r)
	case strings.HasPrefix(r.URL.Path, "/services/"):
		// A plausible-looking but unregistered webhook: fail with a body that, like
		// Slack, never echoes the request URL.
		http.Error(w, "no_service", http.StatusInternalServerError)
	default:
		http.Error(w, "404 page not found", http.StatusNotFound)
	}
}

func (s *fakeSlack) accept(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var p struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "invalid_payload", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.texts = append(s.texts, p.Text)
	s.posts++
	s.mu.Unlock()

	// A real incoming webhook replies "ok" with 200.
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}
