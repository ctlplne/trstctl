// SPDX-License-Identifier: BUSL-1.1

// Package psa holds the vendor clients the Provider billing sync speaks to a
// PSA or billing system through (MSP-3 onward). Each client only translates:
// the billing-sync core decides which customer's period goes where, checks the
// company mapping before anything leaves, resolves the credentials for one
// delivery and records the outcome. A client never chooses a company on its
// own and never sees another customer's lines.
package psa

import (
	"context"
	"errors"
	"time"
)

// UsageLine is one metered figure of a closed period.
type UsageLine struct {
	Meter string
	Value int64
}

// UsagePeriod is one customer's closed, signed usage period, addressed to
// the company the Provider mapped it to in one system.
type UsagePeriod struct {
	CustomerID        string
	ExternalCompanyID string
	PeriodStart       time.Time
	PeriodEnd         time.Time
	Lines             []UsageLine
	EvidenceDigest    string
}

// UsageOutcome says what one push did. Set names the meters whose quantity
// this period set (or found already set to it); Kept names the meters a later
// period had already set, which an older period never overwrites.
type UsageOutcome struct {
	Set    []string
	Kept   []string
	Status int
}

// ErrBeforeWrite marks a failure the client proved before any write reached
// the system (the company, its agreement or a line could not be resolved, or
// a lookup was refused), so the period's record can say it was not
// delivered rather than that its outcome is unknown.
var ErrBeforeWrite = errors.New("psa: refused before any write")

// ErrRefused marks the system's definitive answer to a write (a 4xx other
// than 408 or 429): the same request would be refused again.
var ErrRefused = errors.New("psa: the system refused the write")

// TicketOpen opens one alert subject's service ticket under the customer's
// company. Reference is stable for the subject's ticket generation; the
// client looks for a ticket carrying it before it creates one, so a retry
// after a lost answer finds the ticket instead of opening a second.
type TicketOpen struct {
	ExternalCompanyID string
	Reference         string
	Summary           string
	Description       string
}

// TicketNote adds one alert's note to an open ticket. A note already
// carrying Reference is not added again.
type TicketNote struct {
	TicketID  string
	Reference string
	Text      string
}

// TicketClose closes a ticket with the reason its condition cleared. A
// ticket already closed, or gone, is left as it is.
type TicketClose struct {
	TicketID   string
	Reference  string
	Resolution string
}

// Client is what the billing sync needs from a PSA: usage as the customer's
// quantities, and alert tickets under the customer's company.
type Client interface {
	PushUsage(ctx context.Context, p UsagePeriod) (UsageOutcome, error)
	OpenTicket(ctx context.Context, t TicketOpen) (string, error)
	AddNote(ctx context.Context, n TicketNote) error
	CloseTicket(ctx context.Context, cl TicketClose) error
}

// NoteMarker is the line a note carries so a retry can find it.
func NoteMarker(reference string) string {
	return "[trstctl ref " + reference + "]"
}
