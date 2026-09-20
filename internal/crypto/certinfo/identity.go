// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// Comparing what a listener SERVES against what it was supposed to serve
// (epic D2).
//
// This is the primitive the verification engine is built on, and it lives here
// for the same reason everything else in this package does: comparing two
// certificates means parsing them, and AN-3 says parsing happens inside the
// boundary. The agent and the control plane both get a verdict rather than a
// certificate.
//
// The verdict is a CLASS, not a boolean, and the classes are not
// interchangeable. "This listener is serving a different certificate than the
// one we issued" and "this listener could not be reached" and "this listener is
// serving something that expired" send an operator to three different places.
// Collapsing them into "unhealthy" would rebuild exactly the blindness this
// epic exists to remove: today's expiry alerting is inventory-only, so a
// renewal that succeeded at the CA and never landed live looks identical to a
// renewal that landed. The whole point is to be able to tell those apart.

// errNoCertificate is returned when a chain carries nothing to expect.
var errNoCertificate = errors.New("certinfo: chain contains no certificate to build an expectation from")

// Mismatch is one class of divergence between expected and served identity.
type Mismatch string

const (
	// MismatchNone: the served identity matched the expectation.
	MismatchNone Mismatch = ""
	// MismatchFingerprint: a different certificate is being served. This is the
	// headline case — the renewal produced a certificate that never reached the
	// listener, or something else replaced it.
	MismatchFingerprint Mismatch = "fingerprint"
	// MismatchSANs: the right certificate by fingerprint is impossible here (a
	// fingerprint match implies identical SANs), so this means the served
	// certificate covers a different name set than expected. Distinct from a
	// fingerprint mismatch because the remedy differs: a reissue with the
	// correct SANs, not a redeploy of the one we have.
	MismatchSANs Mismatch = "sans"
	// MismatchChain: the leaf is right but the chain served with it is not what
	// was deployed. Clients that build paths differently will fail against this
	// listener while a fingerprint-only check calls it healthy.
	MismatchChain Mismatch = "chain"
	// MismatchExpired: the served certificate is outside its validity window.
	// Separate from fingerprint because an expired-but-expected certificate
	// means the renewal never ran, while an expired-and-unexpected one means a
	// renewal ran and did not land.
	MismatchExpired Mismatch = "expired"
	// MismatchNotYetValid: served certificate whose notBefore is in the future.
	// Rare, and almost always a clock problem on the serving host rather than a
	// certificate problem — worth its own class so nobody reissues over it.
	MismatchNotYetValid Mismatch = "not_yet_valid"
)

// Mismatches is the closed set, in report order.
//
// Closed on purpose: a database CHECK constraint and the console both render
// against it, and a class invented at a call site would reach an operator as a
// blank cell.
func Mismatches() []Mismatch {
	return []Mismatch{
		MismatchFingerprint, MismatchSANs, MismatchChain,
		MismatchExpired, MismatchNotYetValid,
	}
}

// KnownMismatch reports whether m is a member of the closed set (or none).
func KnownMismatch(m Mismatch) bool {
	if m == MismatchNone {
		return true
	}
	for _, known := range Mismatches() {
		if known == m {
			return true
		}
	}
	return false
}

// Expectation is what a listener is supposed to be serving.
//
// Every field is optional except the fingerprint, and an absent field is NOT
// checked rather than checked against empty. That distinction matters: a
// verification that silently passed because nobody supplied the expected SAN
// set would report "verified" for a check it never ran, which is the one thing
// this engine may not do.
type Expectation struct {
	// SHA256Fingerprint is the expected leaf fingerprint, hex, lowercase. The
	// only required field.
	SHA256Fingerprint string
	// DNSNames, when non-empty, is the expected SAN set. Order-insensitive.
	DNSNames []string
	// ChainFingerprints, when non-empty, are the expected SHA-256 fingerprints
	// of the issuers served after the leaf, in order.
	ChainFingerprints []string
}

// Observation is what the listener actually served.
type Observation struct {
	// Leaf is the served leaf, already inspected.
	Leaf Info
	// ChainFingerprints are the SHA-256 fingerprints of the certificates served
	// after the leaf, in the order presented.
	ChainFingerprints []string
	// At is when the handshake happened. Used for the validity window rather
	// than the verifier's own clock, so a result stays interpretable when it is
	// reported late.
	At time.Time
}

// Verdict is the outcome of one comparison.
type Verdict struct {
	// Mismatch is the first class that failed, in the order of Mismatches().
	// One class rather than a set: an operator needs the reason to act on, and
	// a served certificate that is both the wrong certificate AND expired is
	// acted on as the wrong certificate.
	Mismatch Mismatch
	// Detail is a short, operator-facing explanation. It never contains key
	// material and never contains a newline, so it can travel inside a signed
	// statement.
	Detail string
	// CheckedSANs and CheckedChain report which comparisons actually RAN. A
	// verdict that passed without checking the SAN set must not be presented as
	// having checked it.
	CheckedSANs  bool
	CheckedChain bool
}

// OK reports whether the served identity matched everything that was checked.
func (v Verdict) OK() bool { return v.Mismatch == MismatchNone }

// Compare classifies an observation against an expectation.
//
// Order is deliberate. Fingerprint first, because it subsumes SANs and is the
// case an operator most needs named: the listener is serving a different
// certificate. Validity next, because an expired certificate is serving traffic
// badly right now regardless of what else is true of it. Then the checks that
// only make sense once the leaf is the right one.
func Compare(want Expectation, got Observation) Verdict {
	wantFP := normalizeFingerprint(want.SHA256Fingerprint)
	gotFP := normalizeFingerprint(got.Leaf.SHA256Fingerprint)
	if wantFP == "" {
		return Verdict{
			Mismatch: MismatchFingerprint,
			Detail:   "no expected fingerprint was supplied, so nothing could be verified",
		}
	}
	if gotFP != wantFP {
		// The SAN set is reported alongside because it is what makes the
		// difference legible: "a different certificate" is not actionable,
		// "a certificate for these other names" is.
		return Verdict{
			Mismatch: MismatchFingerprint,
			Detail: "listener is serving a different certificate (" + shortFP(gotFP) +
				") than the one deployed (" + shortFP(wantFP) + "); served names: " +
				joinNames(got.Leaf.DNSNames),
		}
	}

	at := got.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if !got.Leaf.NotAfter.IsZero() && at.After(got.Leaf.NotAfter) {
		return Verdict{
			Mismatch: MismatchExpired,
			Detail:   "served certificate expired at " + got.Leaf.NotAfter.UTC().Format(time.RFC3339),
		}
	}
	if !got.Leaf.NotBefore.IsZero() && at.Before(got.Leaf.NotBefore) {
		return Verdict{
			Mismatch: MismatchNotYetValid,
			Detail:   "served certificate is not valid until " + got.Leaf.NotBefore.UTC().Format(time.RFC3339),
		}
	}

	v := Verdict{}
	if len(want.DNSNames) > 0 {
		v.CheckedSANs = true
		if missing, extra := diffNames(want.DNSNames, got.Leaf.DNSNames); len(missing) > 0 || len(extra) > 0 {
			// Reachable despite the fingerprint match only if the caller
			// supplied a SAN set that disagrees with the certificate it also
			// named — a configuration error worth reporting rather than
			// silently trusting the fingerprint.
			return Verdict{
				Mismatch:    MismatchSANs,
				CheckedSANs: true,
				Detail:      "served name set differs; missing: " + joinNames(missing) + "; unexpected: " + joinNames(extra),
			}
		}
	}
	if len(want.ChainFingerprints) > 0 {
		v.CheckedChain = true
		if !sameChain(want.ChainFingerprints, got.ChainFingerprints) {
			return Verdict{
				Mismatch:     MismatchChain,
				CheckedSANs:  v.CheckedSANs,
				CheckedChain: true,
				Detail: "served chain differs from the deployed chain (" +
					itoa(len(got.ChainFingerprints)) + " issuer(s) served, " +
					itoa(len(want.ChainFingerprints)) + " expected)",
			}
		}
	}
	return v
}

// ExpectationFromChain builds an expectation from the certificate chain that is
// about to be deployed, so the deploying agent verifies against the exact
// material it just wrote rather than against a description of it.
func ExpectationFromChain(raw []byte) (Expectation, error) {
	infos, err := InspectAll(raw)
	if err != nil {
		return Expectation{}, err
	}
	if len(infos) == 0 {
		return Expectation{}, errNoCertificate
	}
	exp := Expectation{
		SHA256Fingerprint: normalizeFingerprint(infos[0].SHA256Fingerprint),
		DNSNames:          append([]string(nil), infos[0].DNSNames...),
	}
	for _, issuer := range infos[1:] {
		exp.ChainFingerprints = append(exp.ChainFingerprints, normalizeFingerprint(issuer.SHA256Fingerprint))
	}
	return exp, nil
}

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, ":", "")))
}

// shortFP renders a fingerprint prefix for operator-facing text. Enough to tell
// two certificates apart at a glance, short enough to keep a detail line
// readable; the full value is always in the structured record beside it.
func shortFP(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "..."
}

// joinNames renders a name set for operator-facing detail text.
//
// Every name is sanitized, because a certificate is UNTRUSTED input: the SAN
// list comes off the wire from whatever the listener chose to serve, and a name
// carrying a newline would break the signed statement's line-based canonical
// encoding — the value would fake a field boundary. Refusing at the statement
// would turn a hostile certificate into a verification that cannot be
// reported, which is worse than reporting it with the control characters
// replaced.
func joinNames(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, sanitizeForStatement(n))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// sanitizeForStatement replaces anything that cannot appear in a signed
// statement value with U+FFFD, so the shape of the offending name is still
// visible to an operator reading the alert.
func sanitizeForStatement(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return '\ufffd'
		}
		return r
	}, strings.TrimSpace(s))
}

// diffNames compares two SAN sets case-insensitively and order-insensitively.
// DNS names are case-insensitive by definition, and a comparison that called
// "API.example.com" different from "api.example.com" would raise a divergence
// nobody can fix.
func diffNames(want, got []string) (missing, extra []string) {
	wantSet := map[string]bool{}
	for _, n := range want {
		if n = normalizeName(n); n != "" {
			wantSet[n] = true
		}
	}
	gotSet := map[string]bool{}
	for _, n := range got {
		if n = normalizeName(n); n != "" {
			gotSet[n] = true
		}
	}
	for n := range wantSet {
		if !gotSet[n] {
			missing = append(missing, n)
		}
	}
	for n := range gotSet {
		if !wantSet[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func normalizeName(n string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(n), ".")))
}

// sameChain compares issuer fingerprints as an ordered sequence.
//
// Ordered, not a set: a chain served in the wrong order is a real
// interoperability problem for clients that do not reorder, and calling it
// identical would hide a difference that breaks handshakes in the field.
func sameChain(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if normalizeFingerprint(want[i]) != normalizeFingerprint(got[i]) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
