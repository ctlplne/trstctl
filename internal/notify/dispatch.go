package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// S10.2 — the notification template. notify already defines the Alert vocabulary and
// the notification.* outbox destinations (the producer side); this adds the consumer
// side: a Notifier interface every channel implements, a Dispatcher that delivers a
// notification.* outbox entry to the registered channels (AN-6), and a conformance
// harness each channel self-validates against — the notification analogue of the
// connector SDK (S5.5).

// Notifier delivers an Alert to one channel (Slack, Teams, PagerDuty, OpsGenie, a
// generic webhook, email, ...).
type Notifier interface {
	// Name identifies the channel.
	Name() string
	// Notify delivers the alert. Delivery is at-least-once (the outbox may retry), so
	// Notify must be safe to call more than once for the same alert and must never
	// panic on a sparse alert.
	Notify(ctx context.Context, alert Alert) error
}

// Dispatcher fans a notification.* outbox entry out to its registered channels. It is
// the outbox handler for the notification surface: the producer enqueued the Alert in
// the same transaction as the state change that raised it, and this delivers it. One
// failing channel does not suppress the others; a returned error tells the outbox to
// retry (at-least-once).
type Dispatcher struct {
	channels []Notifier
}

// NewDispatcher builds a Dispatcher over the given channels.
func NewDispatcher(channels ...Notifier) *Dispatcher {
	return &Dispatcher{channels: append([]Notifier(nil), channels...)}
}

// Register adds a channel.
func (d *Dispatcher) Register(n Notifier) { d.channels = append(d.channels, n) }

// Dispatch decodes an Alert from a notification.* outbox payload and delivers it to
// every registered channel, accumulating per-channel failures.
func (d *Dispatcher) Dispatch(ctx context.Context, payload []byte) error {
	var alert Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return fmt.Errorf("notify: malformed alert payload: %w", err)
	}
	var failed []string
	for _, ch := range d.channels {
		if err := ch.Notify(ctx, alert); err != nil {
			failed = append(failed, ch.Name()+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("notify: %d channel(s) failed: %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

// FormatMessage renders an alert as a short human-readable line for chat/email
// channels. It is deliberately plain text so every channel can reuse it.
func FormatMessage(a Alert) string {
	var b strings.Builder
	switch a.Kind {
	case KindCertificateExpiry:
		b.WriteString("Certificate expiring")
	case KindUnexpectedIssuance:
		b.WriteString("Unexpected certificate issuance")
	default:
		b.WriteString("trstctl alert")
		if a.Kind != "" {
			b.WriteString(" (" + a.Kind + ")")
		}
	}
	if a.Subject != "" {
		b.WriteString(": " + a.Subject)
	}
	if a.Serial != "" {
		b.WriteString(" [serial " + a.Serial + "]")
	}
	if !a.NotAfter.IsZero() {
		b.WriteString(" — not after " + a.NotAfter.UTC().Format("2006-01-02"))
	}
	if a.Detail != "" {
		b.WriteString(" — " + a.Detail)
	}
	return b.String()
}

// Conform exercises a Notifier: it must report a name and deliver a well-formed alert
// without error. A channel plugin self-validates by passing this (the role connector
// conformance plays for deployment connectors).
func Conform(ctx context.Context, n Notifier) error {
	if n == nil {
		return fmt.Errorf("notify: Conform: nil notifier")
	}
	if n.Name() == "" {
		return fmt.Errorf("notify: Conform: notifier reports no name")
	}
	alert := Alert{
		Kind:     KindCertificateExpiry,
		TenantID: "t-conformance",
		Subject:  "cn=conformance.example",
		Detail:   "notification conformance probe",
	}
	if err := n.Notify(ctx, alert); err != nil {
		return fmt.Errorf("notify: channel %q failed to deliver a valid alert: %w", n.Name(), err)
	}
	return nil
}
