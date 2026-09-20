// SPDX-License-Identifier: BUSL-1.1

package mdm

import (
	"fmt"
	"time"
)

// Renewal-window awareness for offline devices (epic I5).
//
// A SCEP-enrolled device renews by CHECKING IN: the MDM pushes the renewal
// profile when the device next appears. A device that stops checking in does
// not fail renewal — it silently never attempts one, every dashboard stays
// green, and the certificate expires on a laptop in a drawer. The check below
// is a pure function so the distinctions are testable without an MDM.

// DefaultRenewalWindowDays is the standard window when a schedule records no
// override: certificates are typically re-issued in their last 30 days.
const DefaultRenewalWindowDays = 30

// RenewalRisk says whether a device is at risk of missing its renewal, and
// why, in words an operator can act on.
//
// The distinctions ARE the feature:
//   - no certificate -> no verdict. A device with nothing to renew is not "at
//     risk"; scoring it would flood the list with devices this check cannot
//     say anything about.
//   - expired -> at risk, and said as EXPIRED, not "expiring": the failure
//     already happened.
//   - inside the window and the MDM has NOT seen the device since the window
//     opened -> at risk: the renewal profile reaches the device only when it
//     checks in, and it has not.
//   - inside the window but the device HAS checked in since it opened -> not
//     at risk: the machinery that would renew it is in contact.
func RenewalRisk(notAfter, lastSeen *time.Time, windowDays int, now time.Time) (atRisk bool, detail string) {
	if notAfter == nil {
		return false, ""
	}
	if windowDays <= 0 {
		windowDays = DefaultRenewalWindowDays
	}
	if now.After(*notAfter) {
		return true, fmt.Sprintf("certificate EXPIRED %s; the device did not renew before expiry",
			notAfter.UTC().Format("2006-01-02"))
	}
	windowStart := notAfter.Add(-time.Duration(windowDays) * 24 * time.Hour)
	if now.Before(windowStart) {
		return false, ""
	}
	if lastSeen == nil {
		return true, fmt.Sprintf("certificate expires %s and the MDM has never observed this device; "+
			"a device that does not check in cannot receive its renewal profile",
			notAfter.UTC().Format("2006-01-02"))
	}
	if lastSeen.Before(windowStart) {
		return true, fmt.Sprintf("certificate expires %s and the MDM last saw this device %s — before "+
			"the %d-day renewal window opened; a device that does not check in cannot receive its "+
			"renewal profile",
			notAfter.UTC().Format("2006-01-02"), lastSeen.UTC().Format("2006-01-02"), windowDays)
	}
	return false, ""
}
