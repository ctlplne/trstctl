// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"fmt"
	"sync/atomic"
	"time"
)

// issuanceBackdateSkewNanos is the operator-configurable NotBefore backdate
// applied to every certificate this platform issues (leaves, SVIDs, internal
// mTLS identities, CA certificates). Common CA practice backdates five
// minutes so a fresh certificate is immediately valid at verifiers with
// modest clock skew (OPS-CLOCKSKEW-001). The server assembly may override it
// once from validated configuration; the isolated signer keeps the default.
var issuanceBackdateSkewNanos atomic.Int64

const (
	defaultIssuanceBackdateSkew = 5 * time.Minute
	minIssuanceBackdateSkew     = 30 * time.Second
	maxIssuanceBackdateSkew     = time.Hour
)

// IssuanceBackdateSkew returns the active NotBefore backdate window.
func IssuanceBackdateSkew() time.Duration {
	if v := issuanceBackdateSkewNanos.Load(); v != 0 {
		return time.Duration(v)
	}
	return defaultIssuanceBackdateSkew
}

// SetIssuanceBackdateSkew configures the NotBefore backdate window from
// validated operator configuration. Values outside [30s, 1h] fail closed:
// too small re-introduces clock-skew rejections, too large widens the
// validity window a stolen key could exploit.
func SetIssuanceBackdateSkew(skew time.Duration) error {
	if skew < minIssuanceBackdateSkew || skew > maxIssuanceBackdateSkew {
		return fmt.Errorf("crypto: issuance backdate skew %v outside [%v, %v]", skew, minIssuanceBackdateSkew, maxIssuanceBackdateSkew)
	}
	issuanceBackdateSkewNanos.Store(int64(skew))
	return nil
}

// IssuanceNotBefore derives the NotBefore for a certificate issued at `now`.
func IssuanceNotBefore(now time.Time) time.Time {
	return now.Add(-IssuanceBackdateSkew())
}

// leafValidityBounds includes clock-skew backdating inside a profile's maximum
// signed validity. Keep the requested forward expiry when there is room; otherwise
// shorten it. Never remove skew protection or sign an already unusable leaf just
// to fit a profile. X.509 encodes whole seconds, so apply the cap to those bounds.
func leafValidityBounds(anchor time.Time, ttl, maximum time.Duration) (time.Time, time.Time, error) {
	notBefore := IssuanceNotBefore(anchor).Truncate(time.Second)
	notAfter := anchor.Add(ttl).Truncate(time.Second)
	if maximum > 0 {
		ceiling := notBefore.Add(maximum).Truncate(time.Second)
		if notAfter.After(ceiling) {
			notAfter = ceiling
		}
		if !notAfter.After(anchor) {
			return time.Time{}, time.Time{}, &leafProfileError{fmt.Sprintf("profile maximum validity %s leaves no usable lifetime after the %s NotBefore backdate", maximum, IssuanceBackdateSkew())}
		}
	}
	return notBefore, notAfter, nil
}
