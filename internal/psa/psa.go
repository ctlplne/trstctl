// SPDX-License-Identifier: BUSL-1.1

// Package psa holds the vendor clients the Provider billing sync speaks to a
// PSA or billing system through (MSP-3 onward). Each client only translates:
// the billing-sync core decides which customer's period goes where, checks the
// company mapping before anything leaves, resolves the credentials for one
// delivery and records the outcome. A client never chooses a company on its
// own and never sees another customer's lines.
package psa

import (
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
