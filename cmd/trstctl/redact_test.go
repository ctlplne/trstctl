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

// TestRedactMasksSpacedAndQuotedDSNForms is the regression guard for AUD-201
// follow-up I1/V10. The keyword/value redactor split on strings.Fields and cut
// on the first '=', so two forms that are LEGAL per this repo's own driver
// (pgx pgconn accepts whitespace around '=' and quoted values with spaces)
// leaked to stderr on every process start: a quoted multi-word password kept
// every fragment after the first, and "password = secret" came back COMPLETELY
// unmasked. The redactor now lexes conninfo rules, and anything it cannot
// parse is redacted conservatively as a whole.
func TestRedactMasksSpacedAndQuotedDSNForms(t *testing.T) {
	const secret = "S3cr3tPassw0rd"
	for _, tc := range []struct {
		name string
		conn string
	}{
		{"plain", "host=db password=" + secret + " dbname=d"},
		{"quoted multi-word", "host=db password='" + secret + " horse battery' dbname=d"},
		{"space both sides", "host=db password = " + secret + " dbname=d"},
		{"space after equals", "host=db password= " + secret + " dbname=d"},
		{"space before equals", "host=db password =" + secret + " dbname=d"},
		{"escaped quote in value", `host=db password='it\'s ` + secret + `' dbname=d`},
		{"escaped backslash", `host=db password='` + secret + `\\' dbname=d`},
		{"leading secret pair", "password = " + secret},
		// A kv-DSN whose value contains "://" must NOT be misrouted to the URL
		// redactor, which parsed it as a bare path and echoed the credential.
		{"scheme inside value", "host=db password=a/b://" + secret + " dbname=d"},
		{"uri query password", "postgres://trstctl@db.internal:5432/trstctl?sslmode=require&password=" + secret},
		{"uri form", "postgres://trstctl:" + secret + "@db.internal:5432/trstctl"},
		{"unterminated quote", "host=db password='" + secret},
		{"dangling key", "host=db password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redact(tc.conn)
			if strings.Contains(got, secret) {
				t.Fatalf("redact(%q) = %q — the credential leaks to stderr on every start", tc.conn, got)
			}
		})
	}

	// A key that merely CONTAINS "password" is not a credential keyword and
	// must survive, so the masking is exact rather than substring-happy.
	got := redact("host=db my_password_hint=rosebud dbname=d")
	if !strings.Contains(got, "rosebud") {
		t.Fatalf("redact masked a non-credential keyword: %q", got)
	}
	// Non-secret quoted values survive verbatim so the summary stays useful.
	got = redact("host=db application_name='my app' password=hunter2")
	if !strings.Contains(got, "'my app'") || strings.Contains(got, "hunter2") {
		t.Fatalf("redact(%q) mangled non-secret values or leaked: %q", "application_name='my app'", got)
	}
}
