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

// The kinds of credential a native expiry belongs to (OD-5), so a lease can
// say whose expiry it waits for.
const (
	NativeExpiryAWSSession     = "aws_session"
	NativeExpiryOAuthToken     = "oauth_token"      // #nosec G101 -- a credential kind's name, no credential value (CWE-798)
	NativeExpiryGitHubAppToken = "github_app_token" // #nosec G101 -- a credential kind's name, no credential value (CWE-798)
)

// NativeExpiryKind names the credential ref's native expiry belongs to: an
// AWS STS session, an OAuth access token or a GitHub App installation token;
// "" for a reference without one.
func NativeExpiryKind(ref string) string {
	if _, ok := AWSSTSExpiration(ref); ok {
		return NativeExpiryAWSSession
	}
	if _, ok := OAuthExpiration(ref); ok {
		return NativeExpiryOAuthToken
	}
	if _, ok := GitHubAppExpiration(ref); ok {
		return NativeExpiryGitHubAppToken
	}
	return ""
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
