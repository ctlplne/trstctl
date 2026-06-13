// Package email is the email (SMTP) notification channel (S10.8), built from the same
// notification template as every other channel: it implements notify.Notifier and
// self-validates against the notify.Conform harness (the notification analogue of the
// connector SDK, S5.5). It delivers an Alert as an RFC 5322 message sent to a fixed
// recipient list through an SMTP relay.
//
// SMTP is not HTTP, so the outbound seam is a Sender (deliver a message to recipients)
// rather than the HTTPDoer the chat/webhook channels use: production dials the relay over
// net/smtp, and tests inject a fake Sender — no live SMTP server is needed and no socket
// is opened in a unit test. This is the same least-privilege seam pattern the connector
// SDK and the other channels follow: the channel does exactly one thing — render and send
// one message.
//
// The SMTP password (when PLAIN auth is configured) is a secret: it is held opaquely,
// never logged, and never written into error text (AN-8 lineage — the same rule the Teams
// channel follows for its webhook URL and PagerDuty for its routing key). net/smtp's own
// errors describe the protocol exchange and do not echo the password, so they are wrapped
// without further sanitisation; the password is set on the auth value and nowhere else.
//
// No cryptographic operation happens here, so this package imports no crypto/* (AN-3);
// there is nothing to route through the crypto boundary. When the channel is driven from
// the notification dispatcher, the outbox provides at-least-once delivery (AN-6) and
// Notify is safe to call more than once for the same alert (re-sending a notification mail
// is acceptable), and never panics on a sparse alert. The message body is the alert detail
// and the subject is notify.FormatMessage(alert) — the same plain-text line every channel
// reuses.
package email

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"trustctl.io/trustctl/internal/notify"
)

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// Sender is the minimal outbound seam: deliver a fully-rendered RFC 5322 message from
// from to the recipients in to. Production uses a net/smtp-backed sender; tests inject a
// fake that captures the call, so no live SMTP server is required.
type Sender interface {
	Send(ctx context.Context, from string, to []string, msg []byte) error
}

// Channel delivers alerts as email through an SMTP relay. The recipient list and sender
// address are fixed at construction; the message is rendered per alert. Any SMTP password
// lives only inside the Sender and is never held or logged here (AN-8).
type Channel struct {
	from   string
	to     []string
	sender Sender
}

// Option configures a Channel.
type Option func(*Channel)

// WithSender injects the outbound Sender. Tests pass a fake that captures the message;
// production omits this and gets the default net/smtp sender bound to the relay address.
func WithSender(s Sender) Option {
	return func(c *Channel) { c.sender = s }
}

// WithAuth configures SMTP PLAIN authentication on the default net/smtp sender. The
// password is stored only inside the sender's auth value and is never logged or surfaced
// in errors (AN-8). It has no effect once WithSender has replaced the default sender (a
// fake sender does not authenticate), so the order of options does not matter in tests.
func WithAuth(username, password string) Option {
	return func(c *Channel) {
		if rs, ok := c.sender.(*realSender); ok {
			rs.auth = smtp.PlainAuth("", username, password, hostOf(rs.addr))
		}
	}
}

// New returns an email channel that sends from from to the recipients in to through the
// SMTP relay at addr (host:port). By default it dials addr with net/smtp; pass
// WithSender to inject a fake (tests) and WithAuth to enable PLAIN authentication.
func New(addr, from string, to []string, opts ...Option) *Channel {
	c := &Channel{
		from:   from,
		to:     append([]string(nil), to...),
		sender: &realSender{addr: addr, from: from},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "email" }

// Notify renders the alert as an RFC 5322 message and sends it through the Sender. The
// subject is notify.FormatMessage(alert) (the shared plain-text summary line) and the body
// is the alert detail. A Sender error is returned wrapped; net/smtp errors describe the
// protocol exchange and never echo a configured password (AN-8). Delivery is at-least-once
// (the outbox may retry, AN-6), so this is safe to call more than once for the same alert
// and never panics on a sparse alert.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	msg := buildMessage(c.from, c.to, notify.FormatMessage(alert), alert.Detail)
	if err := c.sender.Send(ctx, c.from, c.to, msg); err != nil {
		// net/smtp's error text describes the SMTP exchange and does not contain the
		// auth password, so it is wrapped as-is; the password is never part of it (AN-8).
		return fmt.Errorf("email: send alert: %w", err)
	}
	return nil
}

// buildMessage renders a minimal RFC 5322 message: From/To/Subject headers, a blank line,
// then the body. Headers are CRLF-terminated as the SMTP DATA payload expects. Newlines in
// the single-line subject and header fields are stripped so the alert text cannot inject
// extra headers.
func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(headerSafe(from))
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(headerSafe(strings.Join(to, ", ")))
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(headerSafe(subject))
	b.WriteString("\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// headerSafe strips CR and LF from a header value so alert-derived text (subject,
// addresses) cannot smuggle additional headers into the message (header injection).
func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// hostOf returns the host portion of a host:port relay address, used as the PLAIN auth
// host. If addr has no port it is returned unchanged.
func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// realSender is the production Sender: it delivers via net/smtp.SendMail, dialing the
// relay at addr. When auth is non-nil the message is sent with SMTP PLAIN authentication.
// The auth value holds the password opaquely; it is never logged (AN-8).
type realSender struct {
	addr string
	from string
	auth smtp.Auth // nil unless WithAuth was set; carries the password opaquely (AN-8)
}

// Send delivers msg to to through the relay. context cancellation is checked before the
// call; net/smtp.SendMail itself is not context-aware, so this is best-effort cancellation.
func (s *realSender) Send(ctx context.Context, from string, to []string, msg []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// net/smtp.SendMail dials addr, optionally STARTTLS-upgrades, authenticates with
	// s.auth when non-nil, and sends. Its errors describe the SMTP exchange and never
	// contain the auth password (AN-8).
	return smtp.SendMail(s.addr, s.auth, from, to, msg)
}
