package email_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/email"
)

// fakeSender is an in-process double of an SMTP relay: instead of dialing a server it
// captures the (from, to, msg) of the last send so a test can assert on the rendered
// message, and can be told to return an error to exercise the failure path. No socket is
// opened and no live SMTP server is needed (the Sender seam is exactly this swap point).
type fakeSender struct {
	mu    sync.Mutex
	calls int
	from  string
	to    []string
	msg   []byte
	err   error // returned from Send when non-nil, to drive the error path
}

func (f *fakeSender) Send(_ context.Context, from string, to []string, msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.from = from
	f.to = append([]string(nil), to...)
	f.msg = append([]byte(nil), msg...)
	return f.err
}

func (f *fakeSender) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSender) Message() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.msg)
}

// TestEmailConforms drives the channel through the shared notification conformance harness:
// it must report a name and deliver a well-formed alert without error, against the fake
// Sender (no live SMTP server).
func TestEmailConforms(t *testing.T) {
	fake := &fakeSender{}
	ch := email.New("smtp.example:587", "alerts@trstctl.example", []string{"oncall@example.com"}, email.WithSender(fake))

	if err := notify.Conform(context.Background(), ch); err != nil {
		t.Fatalf("email channel failed notification conformance: %v", err)
	}
	if ch.Name() != "email" {
		t.Fatalf("Name() = %q, want %q", ch.Name(), "email")
	}
	if fake.Calls() == 0 {
		t.Fatal("conformance ran but the fake sender received no message")
	}
}

// TestDeliversSubjectAndBody proves Notify renders the alert into the message: the captured
// message carries the Subject header built from FormatMessage and the body carries the
// alert detail, so the alert reaches the recipient intact.
func TestDeliversSubjectAndBody(t *testing.T) {
	fake := &fakeSender{}
	ch := email.New("smtp.example:587", "alerts@trstctl.example", []string{"oncall@example.com"}, email.WithSender(fake))

	const detail = "renew within 7 days"
	alert := notify.Alert{
		Kind:     notify.KindCertificateExpiry,
		TenantID: "t-1",
		Subject:  "cn=web.example.com",
		Serial:   "0a:0b:0c",
		Detail:   detail,
	}
	if err := ch.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	msg := fake.Message()
	wantSubject := "Subject: " + notify.FormatMessage(alert)
	if !strings.Contains(msg, wantSubject) {
		t.Errorf("message does not contain the formatted Subject line.\n got: %q\nwant substring: %q", msg, wantSubject)
	}
	// The body is the alert detail, separated from the headers by a blank line.
	if !strings.Contains(msg, "\r\n\r\n"+detail) {
		t.Errorf("message body does not carry the alert detail.\n got: %q\nwant detail: %q", msg, detail)
	}
	// Sanity: the recipient address reaches the To header.
	if !strings.Contains(msg, "To: oncall@example.com") {
		t.Errorf("message does not address the recipient.\n got: %q", msg)
	}
}

// TestPasswordNeverLogged (AN-8): with PLAIN auth configured, a send failure must surface
// the cause but never the SMTP password — even on the error path. The fake sender is forced
// to fail, the password is set via WithAuth, and the returned error must not contain it.
func TestPasswordNeverLogged(t *testing.T) {
	const password = "super-secret-smtp-password-do-not-log"
	fake := &fakeSender{err: errors.New("535 5.7.8 authentication failed")}
	ch := email.New(
		"smtp.example:587",
		"alerts@trstctl.example",
		[]string{"oncall@example.com"},
		email.WithSender(fake),
		email.WithAuth("smtp-user", password),
	)

	err := ch.Notify(context.Background(), notify.Alert{
		Kind:    notify.KindCertificateExpiry,
		Subject: "cn=leak.example",
		Detail:  "auth should fail",
	})
	if err == nil {
		t.Fatal("expected an error from the failing sender")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error should surface the SMTP failure cause, got: %v", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("error leaked the SMTP password: %v", err)
	}
}
