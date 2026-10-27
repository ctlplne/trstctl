// SPDX-License-Identifier: BUSL-1.1

// Package tlsvalidity encodes the CA/Browser Forum's dated maximum validity for
// publicly trusted TLS server certificates: Baseline Requirements section 6.3.2
// as it stands in the version named by Source. The maximum depends on when a
// certificate is issued, and shrinks in dated steps.
//
// A certificate's Validity Period is, per the BR's definition (from RFC 5280),
// the time from notBefore through notAfter, inclusive. Section 6.3.2 counts it
// in days of 86,400 seconds, and any amount of time beyond a whole day —
// fractional or leap seconds included — is an additional day. So a certificate
// whose notAfter is exactly 200 days after its notBefore is 200 days and one
// second long, which is 201 days: one second too long for a 200-day maximum.
package tlsvalidity

import (
	"time"
)

// Source names the requirements text this package encodes. Re-read the current
// Baseline Requirements before changing Steps, and update Source with them.
type Source struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Published string `json:"published"`
	Section   string `json:"section"`
	URL       string `json:"url"`
}

// BaselineRequirements is the version Steps encodes.
var BaselineRequirements = Source{
	Name:      "CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates",
	Version:   "2.3.1",
	Published: "2026-10-04",
	Section:   "6.3.2",
	URL:       "https://cabforum.org/working-groups/server/baseline-requirements/",
}

// Step is the maximum validity for certificates issued in one date range.
type Step struct {
	// From is the first issuance instant the step applies to (zero: no lower
	// bound); Until is the first instant it no longer applies (zero: none).
	From, Until time.Time
	// ShouldDays is the SHOULD NOT exceed bound; MaxDays the MUST NOT.
	ShouldDays, MaxDays int
}

func date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Steps is section 6.3.2's table, in order.
var Steps = []Step{
	{Until: date(2026, 3, 15), ShouldDays: 397, MaxDays: 398},
	{From: date(2026, 3, 15), Until: date(2027, 3, 15), ShouldDays: 199, MaxDays: 200},
	{From: date(2027, 3, 15), Until: date(2029, 3, 15), ShouldDays: 99, MaxDays: 100},
	{From: date(2029, 3, 15), ShouldDays: 46, MaxDays: 47},
}

// Reductions are the dated steps that shorten the maximum: every step after the
// first.
func Reductions() []Step { return append([]Step(nil), Steps[1:]...) }

// StepFor returns the step that applies to a certificate issued at issued.
func StepFor(issued time.Time) Step {
	issued = issued.UTC()
	for _, step := range Steps {
		if (step.From.IsZero() || !issued.Before(step.From)) && (step.Until.IsZero() || issued.Before(step.Until)) {
			return step
		}
	}
	return Steps[len(Steps)-1]
}

// InEffect reports whether the step applies to a certificate issued at now.
func (s Step) InEffect(now time.Time) bool {
	now = now.UTC()
	return (s.From.IsZero() || !now.Before(s.From)) && (s.Until.IsZero() || now.Before(s.Until))
}

// daySeconds is the BR's day.
const daySeconds = 86400

// ValidityDays is a certificate's Validity Period in BR days: notBefore through
// notAfter inclusive, in 86,400-second days, any remainder counting as a day.
// A notAfter before notBefore is zero days.
func ValidityDays(notBefore, notAfter time.Time) int {
	if notAfter.Before(notBefore) {
		return 0
	}
	return RequestedDays(notAfter.Sub(notBefore))
}

// RequestedDays is the Validity Period, in BR days, of a certificate whose
// notAfter is lifetime after its notBefore — what a profile requesting lifetime
// produces.
func RequestedDays(lifetime time.Duration) int {
	if lifetime < 0 {
		return 0
	}
	period := lifetime + time.Second // inclusive of the notAfter second
	days := int(period / (daySeconds * time.Second))
	if period%(daySeconds*time.Second) != 0 {
		days++
	}
	return days
}

// MaxLifetime is the longest notAfter − notBefore a certificate may have under
// the step: its MUST bound less the inclusive second.
func (s Step) MaxLifetime() time.Duration {
	return time.Duration(s.MaxDays)*daySeconds*time.Second - time.Second
}
