// SPDX-License-Identifier: MPL-2.0

package main

import (
	"strings"
	"testing"
)

// TestRedactMasksEveryCredentialForm is the regression guard for the
// datastore-credential disclosure. This string is printed to stderr on every
// start, and redact() relied on url.Redacted(), which masks only a URL's
// password component. Two real connection-string forms slipped through intact.
func TestRedactMasksEveryCredentialForm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		conn   string
		secret string
	}{
		// libpq keyword/value DSN: url.Parse does not fail on it, so Redacted()
		// returned the whole string unchanged.
		{"postgres keyword/value", "host=db.internal user=trstctl password=S3cr3tPassw0rd dbname=trstctl sslmode=require", "S3cr3tPassw0rd"},
		{"postgres passfile", "host=db user=u passfile=/etc/secret/pgpass dbname=d", "/etc/secret/pgpass"},
		{"postgres sslpassword", "host=db sslpassword=KeyPhrase123 dbname=d", "KeyPhrase123"},
		// NATS carries a token as the userinfo USERNAME, which Redacted() leaves
		// alone because it only masks the password component.
		{"nats token", "nats://S3cr3tT0ken@nats.internal:4222", "S3cr3tT0ken"},
		// The form that already worked, kept so a fix cannot regress it.
		{"url password", "postgres://trstctl:S3cr3tPassw0rd@db.internal:5432/trstctl", "S3cr3tPassw0rd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redact(tc.conn)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("redact(%q) = %q — the credential %q is printed to stderr on every start",
					tc.conn, got, tc.secret)
			}
		})
	}
}

// TestRedactKeepsTheHostVisible keeps redaction useful: an operator must still
// be able to confirm what the process points at, or they will turn it off.
func TestRedactKeepsTheHostVisible(t *testing.T) {
	for _, tc := range []struct{ conn, want string }{
		{"host=db.internal user=trstctl password=x dbname=trstctl", "db.internal"},
		{"postgres://trstctl:x@db.internal:5432/trstctl", "db.internal"},
		{"nats://token@nats.internal:4222", "nats.internal"},
	} {
		if got := redact(tc.conn); !strings.Contains(got, tc.want) {
			t.Errorf("redact(%q) = %q, want the host %q still visible", tc.conn, got, tc.want)
		}
	}
}

// TestRedactHandlesEmptyAndUnparseable pins the edges rather than leaving them
// to chance — an unparseable string must not be echoed verbatim.
func TestRedactHandlesEmptyAndUnparseable(t *testing.T) {
	if got := redact(""); got != "" {
		t.Errorf("redact(\"\") = %q, want empty", got)
	}
	if got := redact("://not a url at all"); strings.Contains(got, "not a url") {
		t.Errorf("unparseable connection string was echoed back: %q", got)
	}
}
