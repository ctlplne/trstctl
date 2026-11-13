// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// The Provider's PSA tickets (MSP-3): a mapped customer's alerts of the
// ticketed kinds open a service ticket under its company in each PSA target
// that opens tickets, later alerts of the same subject add notes, and the
// close sweep closes a ticket once its condition clears. The core outbox
// performs and records every PSA call; these only decide what to queue.

// TicketQueuer is the core command side tickets drive.
type TicketQueuer interface {
	QueuePSATicketAlert(ctx context.Context, tenantID string, a orchestrator.PSATicketAlert) (string, error)
	QueuePSATicketClose(ctx context.Context, tenantID, targetID, alertKey string, generation int, reason string) (bool, error)
}

type ticketQueuerBox struct{ q TicketQueuer }

// TicketTargets are the configured targets that open tickets.
func TicketTargets(sync config.ProviderBillingSync) []config.ProviderBillingTarget {
	var out []config.ProviderBillingTarget
	for _, t := range sync.Targets {
		if len(t.TicketKinds()) > 0 {
			out = append(out, t)
		}
	}
	return out
}

// TicketAlertKey names the subject an alert is about, or "" for an alert no
// ticket follows.
func TicketAlertKey(a notify.Alert) string {
	var subject string
	switch a.Kind {
	case notify.KindCertificateExpiry:
		subject = a.CertificateID
	case notify.KindRenewalFailed:
		subject = a.IdentityID
	case notify.KindRevocationHealth:
		if a.CertificateID != "" && a.EndpointAddress != "" {
			subject = a.CertificateID + "|" + a.EndpointAddress
		}
	case notify.KindCredentialDrift:
		subject = a.Subject
	}
	subject = strings.TrimSpace(subject)
	if subject == "" || len(a.Kind)+1+len(subject) > 400 {
		return ""
	}
	return a.Kind + ":" + subject
}

// TicketText is an alert's ticket summary and note. They name the alert's
// subject and what to do; the owner's contact details stay in trstctl.
func TicketText(a notify.Alert) (summary, note string) {
	severity := a.Severity
	if severity == "" {
		severity = notify.AlertSeverityWarning
	}
	var b strings.Builder
	switch a.Kind {
	case notify.KindCertificateExpiry:
		if a.ThresholdDays != nil {
			summary = fmt.Sprintf("Certificate expires in %d days: %s", *a.ThresholdDays, a.Subject)
		} else {
			summary = "Certificate expiring: " + a.Subject
		}
		fmt.Fprintf(&b, "Certificate %s (serial %s) expires %s.", a.Subject, a.Serial, a.NotAfter.UTC().Format(time.RFC3339))
	case notify.KindRenewalFailed:
		summary = "Renewal failed: " + a.Subject
		fmt.Fprintf(&b, "The renewal of %s failed.", a.Subject)
	case notify.KindRevocationHealth:
		summary = fmt.Sprintf("Revocation endpoint %s: %s", a.Mismatch, a.EndpointAddress)
		fmt.Fprintf(&b, "Certificate %s (serial %s) tells relying parties to check %s, which is %s.", a.Subject, a.Serial, a.EndpointAddress, a.Mismatch)
	case notify.KindCredentialDrift:
		summary = "Credential drift: " + a.Subject
		fmt.Fprintf(&b, "The credential at %s no longer matches what trstctl deployed.", a.Subject)
	default:
		summary = a.Kind + ": " + a.Subject
	}
	if d := strings.TrimSpace(a.Detail); d != "" {
		b.WriteString("\n" + d)
	}
	fmt.Fprintf(&b, "\nAlert: %s, severity %s.", a.Kind, severity)
	return summary, b.String()
}

// TicketObserver turns a mapped customer's alerts into ticket work. It is an
// alert observer of the core notification surface.
type TicketObserver struct {
	Store   *corestore.Store
	Targets []config.ProviderBillingTarget

	queuer atomic.Pointer[ticketQueuerBox]
}

// Bind attaches the core command side once the orchestrator is assembled;
// until then alerts open no tickets.
func (o *TicketObserver) Bind(q TicketQueuer) {
	if o != nil && q != nil {
		o.queuer.Store(&ticketQueuerBox{q: q})
	}
}

// ObserveAlert queues the alert's ticket work in every target that opens
// tickets for its kind and where the customer is mapped to a company.
func (o *TicketObserver) ObserveAlert(ctx context.Context, tenantID, alertRef string, alert notify.Alert) error {
	key := TicketAlertKey(alert)
	box := o.queuer.Load()
	if key == "" || box == nil || o.Store == nil {
		return nil
	}
	summary, note := TicketText(alert)
	for _, target := range o.Targets {
		if !slices.Contains(target.TicketKinds(), alert.Kind) {
			continue
		}
		company, mapped, err := o.Store.BillingCompanyFor(ctx, tenantID, target.ID)
		if err != nil {
			return err
		}
		if !mapped {
			continue
		}
		if _, err := box.q.QueuePSATicketAlert(ctx, tenantID, orchestrator.PSATicketAlert{TargetID: target.ID, AlertKey: key,
			Kind: alert.Kind, ExternalCompanyID: company, Summary: summary, Note: note, AlertRef: alertRef}); err != nil {
			return err
		}
	}
	return nil
}

// ticketMaxClosesPerSweep bounds one close sweep (backpressure).
const ticketMaxClosesPerSweep = 500

// TicketCloser is the leader worker that closes tickets whose condition
// cleared.
type TicketCloser struct {
	Store    *corestore.Store
	Targets  []config.ProviderBillingTarget
	Interval time.Duration
	Log      *slog.Logger

	queuer atomic.Pointer[ticketQueuerBox]
}

// Bind attaches the core command side; until then a sweep does nothing.
func (c *TicketCloser) Bind(q TicketQueuer) {
	if c != nil && q != nil {
		c.queuer.Store(&ticketQueuerBox{q: q})
	}
}

// Name identifies the worker.
func (c *TicketCloser) Name() string { return "provider.psa_ticket.close_sweep" }

// Run sweeps every Interval until ctx ends.
func (c *TicketCloser) Run(ctx context.Context) error {
	interval := c.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	for {
		if _, err := c.Sweep(ctx); err != nil && ctx.Err() == nil && c.Log != nil {
			c.Log.Warn("PSA ticket close sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// Sweep queues the close of every open ticket whose condition cleared and
// reports how many it queued.
func (c *TicketCloser) Sweep(ctx context.Context) (int, error) {
	box := c.queuer.Load()
	if box == nil || c.Store == nil {
		return 0, nil
	}
	closed := 0
	var firstErr error
	for _, target := range c.Targets {
		mappings, err := c.Store.BillingCompanyMappings(ctx, target.ID)
		if err != nil {
			return closed, err
		}
		for _, m := range mappings {
			tickets, err := c.Store.OpenPSATickets(ctx, m.TenantID, target.ID)
			if err != nil {
				firstErr = errors.Join(firstErr, err)
				continue
			}
			for _, ticket := range tickets {
				if ticket.Status != corestore.PSATicketOpen {
					continue
				}
				if closed >= ticketMaxClosesPerSweep || ctx.Err() != nil {
					return closed, firstErr
				}
				cleared, reason, err := c.Store.PSATicketConditionCleared(ctx, m.TenantID, ticket.AlertKey)
				if err != nil {
					firstErr = errors.Join(firstErr, err)
					continue
				}
				if !cleared {
					continue
				}
				queued, err := box.q.QueuePSATicketClose(ctx, m.TenantID, target.ID, ticket.AlertKey, ticket.Generation, reason)
				if err != nil {
					firstErr = errors.Join(firstErr, err)
					continue
				}
				if queued {
					closed++
				}
			}
		}
	}
	return closed, firstErr
}
