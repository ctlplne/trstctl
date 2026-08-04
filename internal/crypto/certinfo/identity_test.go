// SPDX-License-Identifier: MPL-2.0

package certinfo_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The comparison that makes renewal-failure detection possible (epic D2).
//
// Today's expiry alerting reads the inventory: what trstctl BELIEVES is
// deployed. A renewal that succeeds at the CA and never lands on the listener
// is invisible to it, because the inventory says the new certificate exists and
// the inventory is right — it just is not what the listener is serving. This
// comparison is the thing that can tell those apart, so its distinctions are
// the epic.

func leaf(fp string, names []string, notBefore, notAfter time.Time) certinfo.Info {
	return certinfo.Info{
		SHA256Fingerprint: fp,
		DNSNames:          names,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
	}
}

var (
	now      = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	lastWeek = now.AddDate(0, 0, -7)
	nextYear = now.AddDate(1, 0, 0)
)

// The headline case: the renewal produced a certificate the listener never got.
func TestADifferentServedCertificateIsAFingerprintMismatch(t *testing.T) {
	t.Parallel()
	got := certinfo.Compare(
		certinfo.Expectation{SHA256Fingerprint: "aa11", DNSNames: []string{"api.example.test"}},
		certinfo.Observation{
			Leaf: leaf("bb22", []string{"api.example.test"}, lastWeek, nextYear),
			At:   now,
		},
	)
	if got.Mismatch != certinfo.MismatchFingerprint {
		t.Fatalf("Mismatch = %q, want fingerprint — a listener serving a certificate other than "+
			"the one deployed is the entire failure this engine exists to catch", got.Mismatch)
	}
	if got.OK() {
		t.Error("a fingerprint mismatch reported OK")
	}
	// The detail names the served identity, because "a different certificate" is
	// not something an operator can act on.
	if !strings.Contains(got.Detail, "api.example.test") {
		t.Errorf("detail = %q; it must say what the listener is actually serving", got.Detail)
	}
}

// Expiry is its own class, and the reason is operational: an expired
// certificate that IS the expected one means the renewal never ran, while an
// expired one that is NOT expected means a renewal ran and did not land. Those
// are different incidents.
func TestAnExpiredServedCertificateIsNotReportedAsAFingerprintProblem(t *testing.T) {
	t.Parallel()
	expired := now.AddDate(0, 0, -1)
	got := certinfo.Compare(
		certinfo.Expectation{SHA256Fingerprint: "aa11"},
		certinfo.Observation{
			Leaf: leaf("aa11", []string{"api.example.test"}, lastWeek, expired),
			At:   now,
		},
	)
	if got.Mismatch != certinfo.MismatchExpired {
		t.Fatalf("Mismatch = %q, want expired", got.Mismatch)
	}
	if !strings.Contains(got.Detail, expired.Format(time.RFC3339)) {
		t.Errorf("detail = %q, want the expiry instant", got.Detail)
	}
}

// A future notBefore is a clock problem on the serving host, not a certificate
// problem. Classing it as expired would send someone to reissue a certificate
// that is perfectly good.
func TestANotYetValidCertificateHasItsOwnClass(t *testing.T) {
	t.Parallel()
	got := certinfo.Compare(
		certinfo.Expectation{SHA256Fingerprint: "aa11"},
		certinfo.Observation{
			Leaf: leaf("aa11", nil, now.AddDate(0, 0, 2), nextYear),
			At:   now,
		},
	)
	if got.Mismatch != certinfo.MismatchNotYetValid {
		t.Fatalf("Mismatch = %q, want not_yet_valid", got.Mismatch)
	}
}

// The chain is compared as an ORDERED sequence. A chain served in the wrong
// order breaks handshakes for clients that do not reorder, and calling it
// identical would hide a failure that only shows up in the field.
func TestChainOrderIsPartOfTheIdentity(t *testing.T) {
	t.Parallel()
	base := certinfo.Observation{
		Leaf: leaf("aa11", nil, lastWeek, nextYear),
		At:   now,
	}

	same := base
	same.ChainFingerprints = []string{"int1", "root1"}
	if v := certinfo.Compare(certinfo.Expectation{
		SHA256Fingerprint: "aa11", ChainFingerprints: []string{"int1", "root1"},
	}, same); !v.OK() {
		t.Fatalf("an identical chain was reported as %q: %s", v.Mismatch, v.Detail)
	}

	reordered := base
	reordered.ChainFingerprints = []string{"root1", "int1"}
	v := certinfo.Compare(certinfo.Expectation{
		SHA256Fingerprint: "aa11", ChainFingerprints: []string{"int1", "root1"},
	}, reordered)
	if v.Mismatch != certinfo.MismatchChain {
		t.Errorf("a reordered chain compared as %q; order is part of what clients build paths "+
			"from, so a chain served backwards is a real divergence", v.Mismatch)
	}
}

// DNS names are case-insensitive by definition. A comparison that called
// API.example.com different from api.example.com would raise a divergence
// nobody can fix, on every listener whose config happens to use capitals.
func TestSANComparisonIsCaseAndOrderInsensitive(t *testing.T) {
	t.Parallel()
	v := certinfo.Compare(
		certinfo.Expectation{
			SHA256Fingerprint: "aa11",
			DNSNames:          []string{"API.Example.Test", "www.example.test"},
		},
		certinfo.Observation{
			Leaf: leaf("aa11", []string{"www.example.test", "api.example.test."}, lastWeek, nextYear),
			At:   now,
		},
	)
	if !v.OK() {
		t.Fatalf("case and ordering raised %q: %s", v.Mismatch, v.Detail)
	}
}

// A check that did not run must not be reported as having passed.
//
// This is the honesty rule the whole surface depends on. An expectation with no
// SAN set means nobody supplied one — not that the SAN set is empty — and a
// verdict that claimed to have verified names it never looked at would be a
// served status claiming more than the code did.
func TestAVerdictReportsWhichChecksActuallyRan(t *testing.T) {
	t.Parallel()
	onlyFingerprint := certinfo.Compare(
		certinfo.Expectation{SHA256Fingerprint: "aa11"},
		certinfo.Observation{Leaf: leaf("aa11", []string{"api.example.test"}, lastWeek, nextYear), At: now},
	)
	if !onlyFingerprint.OK() {
		t.Fatalf("unexpected mismatch %q", onlyFingerprint.Mismatch)
	}
	if onlyFingerprint.CheckedSANs {
		t.Error("CheckedSANs is true although no expected SAN set was supplied; a verification " +
			"that reports having checked names it never received is exactly the overclaim this " +
			"engine exists to remove")
	}
	if onlyFingerprint.CheckedChain {
		t.Error("CheckedChain is true although no expected chain was supplied")
	}

	full := certinfo.Compare(
		certinfo.Expectation{
			SHA256Fingerprint: "aa11",
			DNSNames:          []string{"api.example.test"},
			ChainFingerprints: []string{"int1"},
		},
		certinfo.Observation{
			Leaf:              leaf("aa11", []string{"api.example.test"}, lastWeek, nextYear),
			ChainFingerprints: []string{"int1"},
			At:                now,
		},
	)
	if !full.CheckedSANs || !full.CheckedChain {
		t.Errorf("a full comparison reported CheckedSANs=%v CheckedChain=%v, want both true",
			full.CheckedSANs, full.CheckedChain)
	}
}

// An expectation with no fingerprint verifies nothing, and says so rather than
// passing. Returning OK here would mark every endpoint verified the moment a
// caller forgot to populate the expectation.
func TestAnEmptyExpectationFailsRatherThanPasses(t *testing.T) {
	t.Parallel()
	v := certinfo.Compare(certinfo.Expectation{}, certinfo.Observation{
		Leaf: leaf("aa11", nil, lastWeek, nextYear), At: now,
	})
	if v.OK() {
		t.Fatal("an empty expectation verified successfully, so any endpoint whose expectation " +
			"failed to load would report as verified")
	}
}

// The mismatch vocabulary is closed, because a database CHECK constraint and
// the console both render against it.
func TestMismatchVocabularyIsClosed(t *testing.T) {
	t.Parallel()
	if !certinfo.KnownMismatch(certinfo.MismatchNone) {
		t.Error("the empty mismatch must be a known value")
	}
	for _, m := range certinfo.Mismatches() {
		if !certinfo.KnownMismatch(m) {
			t.Errorf("%q is in Mismatches() but not KnownMismatch", m)
		}
		if strings.TrimSpace(string(m)) == "" {
			t.Error("a mismatch class is blank")
		}
	}
	if certinfo.KnownMismatch(certinfo.Mismatch("invented-at-a-call-site")) {
		t.Error("an unknown class was accepted; it would reach an operator as a blank cell")
	}
}

// Detail travels inside a signed statement, whose canonical encoding is
// line-based and forbids newlines in any value.
func TestVerdictDetailNeverContainsANewline(t *testing.T) {
	t.Parallel()
	cases := []certinfo.Observation{
		{Leaf: leaf("bb22", []string{"a.test\nb.test"}, lastWeek, nextYear), At: now},
		{Leaf: leaf("aa11", nil, lastWeek, now.AddDate(0, 0, -1)), At: now},
	}
	for _, obs := range cases {
		v := certinfo.Compare(certinfo.Expectation{
			SHA256Fingerprint: "aa11", DNSNames: []string{"a.test"},
		}, obs)
		if strings.ContainsAny(v.Detail, "\n\r") {
			t.Errorf("detail %q contains a newline; the signed statement's canonical encoding "+
				"is line-based and would refuse it", v.Detail)
		}
	}
}
