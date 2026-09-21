// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"time"

	"trstctl.com/trstctl/internal/notify"
)

// The CA calendar (H5).
//
// A leaf certificate that expires is a page. A root or intermediate that expires
// is an outage across every leaf beneath it, and you cannot fix it in an
// afternoon: a new root has to be distributed to every relying party first, which
// is a quarters-long program. Leaf-scale alerting — the 7/30/90-day windows the
// expiry scheduler uses — never fires early enough to start one.
//
// So CA authorities get their own clock, measured in months rather than days.
// The scheduler walks ca_authorities.not_after against the thresholds below and
// re-alerts each time an authority crosses into a tighter band, with severity
// scaled to how much runway is left. A root three years out is an item on next
// year's roadmap; the same root three months out is an incident.
//
// The second check is subtler and is the one operators miss. A CA cannot issue a
// leaf that outlives it, so as a parent's horizon closes, every leaf issued under
// it is silently truncated to the parent's not_after. Renewals keep succeeding,
// certificates keep getting shorter, and nothing complains until the validity is
// too short to be useful. CompressedValidity flags that the moment the parent's
// remaining horizon drops below the validity the tenant actually asks for.

// CAHorizonThresholdMonths are the year-scale bands a CA authority's remaining
// life is measured against, widest first. An authority alerts once per band it
// crosses, so a root announces itself three years out and then again at each
// tightening — the re-alerting the leaf-scale scheduler cannot express.
var CAHorizonThresholdMonths = []int{36, 24, 12, 6, 3}

// approxMonth is the averaged Gregorian month used to convert a duration into a
// horizon band. Band boundaries are advisory planning markers, not deadlines, so
// an averaged month is the right precision here; the exact not_after travels in
// the alert payload for anyone who needs the real date.
const approxMonth = time.Duration(30.436875 * 24 * float64(time.Hour))

// CAHorizonBand returns the tightest threshold an authority's remaining life has
// crossed, and whether any threshold applies. A zero or already-past not_after
// returns band 0, which is the expired case and the most severe.
func CAHorizonBand(now, notAfter time.Time) (months int, ok bool) {
	if notAfter.IsZero() {
		return 0, false
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return 0, true
	}
	monthsLeft := MonthsRemaining(now, notAfter)
	band, matched := 0, false
	for _, threshold := range CAHorizonThresholdMonths {
		if monthsLeft <= threshold && (!matched || threshold < band) {
			band, matched = threshold, true
		}
	}
	return band, matched
}

// MonthsRemaining reports whole months of life left, rounded down, so an
// authority sits in a band for the whole of that band rather than flickering
// across the boundary. Past or zero expiry is zero.
func MonthsRemaining(now, notAfter time.Time) int {
	if notAfter.IsZero() {
		return 0
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return int(remaining / approxMonth)
}

// CAHorizonSeverity scales alert severity to runway. The bands are not arbitrary:
// under three months there is no time to distribute a new trust anchor, so that
// is critical; a year or less is warning because a migration program has to be
// funded and staffed; beyond that it is a planning signal, not an alarm.
func CAHorizonSeverity(band int) string {
	switch {
	case band <= 3:
		return notify.AlertSeverityCritical
	case band <= 12:
		return notify.AlertSeverityWarning
	default:
		return notify.AlertSeverityLow
	}
}

// CARenewBy is the date by which an authority must be renewed or re-keyed if
// leaves issued under it are still to receive their full requested validity. It
// is the parent's not_after minus that leaf validity — past this point every new
// leaf is silently truncated, which is the compression the next function detects.
// A leafValidity of zero means the caller has no leaf-validity opinion, in which
// case the renew-by date is the expiry itself.
func CARenewBy(notAfter time.Time, leafValidity time.Duration) time.Time {
	if notAfter.IsZero() {
		return time.Time{}
	}
	if leafValidity <= 0 {
		return notAfter
	}
	return notAfter.Add(-leafValidity)
}

// CompressedValidity reports whether the authority's remaining horizon is already
// shorter than the validity leaves are supposed to get, along with the validity a
// leaf issued now would actually receive. This is the failure that hides: nothing
// errors, issuance keeps succeeding, and the certificates just keep getting
// shorter until something downstream rejects them.
func CompressedValidity(now, notAfter time.Time, leafValidity time.Duration) (compressed bool, actual time.Duration) {
	if notAfter.IsZero() || leafValidity <= 0 {
		return false, 0
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return true, 0
	}
	if remaining >= leafValidity {
		return false, leafValidity
	}
	return true, remaining
}
