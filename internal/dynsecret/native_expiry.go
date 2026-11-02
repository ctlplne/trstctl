// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"errors"
	"time"
)

// ErrNativeExpiryPending means a credential can't be ended before its native
// expiry: trstctl has closed the lease, and the upstream system accepts the
// credential until the expiry NativeExpiration reads from its provider
// reference. Revocation stays visibly pending until then — the catalog's
// "ttl_only" — instead of claiming an early invalidation (A239).
var ErrNativeExpiryPending = errors.New("dynsecret: the credential remains valid until its native expiry")

// NativeExpiration reads the public native expiry from the provider reference
// of a credential that can't be revoked early.
func NativeExpiration(ref string) (time.Time, bool) {
	if expiration, ok := AWSSTSExpiration(ref); ok {
		return expiration, true
	}
	if expiration, ok := OAuthExpiration(ref); ok {
		return expiration, true
	}
	if expiration, ok := GitHubAppExpiration(ref); ok {
		return expiration, true
	}
	return time.Time{}, false
}

// CheckNativeExpiration returns ErrNativeExpiryPending until ref's native
// expiry, and nil once it has passed.
func CheckNativeExpiration(ref string, now time.Time) error {
	expiration, ok := NativeExpiration(ref)
	if !ok {
		return errors.New("dynsecret: the provider reference carries no native expiry")
	}
	if now.Before(expiration) {
		return ErrNativeExpiryPending
	}
	return nil
}
