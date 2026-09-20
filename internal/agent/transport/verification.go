// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The probe transcript: what a verification actually saw (epic D2).
//
// The receipt statement already reserves a field for this. Its comment says the
// evidence digest "binds the receipt to whatever transcript the agent kept" —
// and until now no producer set it, because no agent kept a transcript. This is
// that transcript.
//
// The shape is the same discipline the receipt statement uses and for the same
// reason: one field per line, fixed order, name=value, no escaping and no
// newlines in any value. Two sides must build identical bytes from identical
// facts or every signature fails and the failure looks like an attack. JSON
// would give more than one correct rendering of the same transcript, which is
// how canonicalization bugs become signature failures nobody can reproduce.
//
// What the transcript does NOT carry is the certificate. An operator does not
// need the served leaf reproduced inside a signed receipt to trust the verdict;
// they need to know that the agent looked, what it saw, and that the record
// they are reading is the one the agent signed. Fingerprints do that in 64
// bytes and cannot leak anything (AN-8's habit applied where it costs nothing).

// transcriptVersion prefixes every transcript. A change to the field set
// changes this line, so an old digest can never be mistaken for a new
// transcript's.
const transcriptVersion = "trstctl-endpoint-probe-transcript/v1"

// Vantage says where a verification was performed from.
//
// The distinction is the epic: the host agent sees its own listener from
// inside, which proves the file landed and the service reloaded; the relay sees
// it from the network as a client would, which is the only witness available
// for an appliance and the only one that proves reachability. A record that did
// not say which vantage produced it would let a passing local check stand in
// for evidence the endpoint is actually serving.
type Vantage string

const (
	// VantageLocal: the agent handshaked a listener on its own machine,
	// immediately after deploying to it.
	VantageLocal Vantage = "local"
	// VantageRelay: a network agent handshaked the endpoint across the segment.
	VantageRelay Vantage = "relay"
)

// KnownVantage reports whether v is one of the two.
func KnownVantage(v Vantage) bool { return v == VantageLocal || v == VantageRelay }

// ProbeTranscript is the record of one handshake and comparison.
type ProbeTranscript struct {
	// Address is the host:port that was dialled.
	Address string
	// Vantage is where the probe ran from.
	Vantage Vantage
	// ServerName is the SNI sent, when it differed from the address host.
	ServerName string
	// Reached says whether the TLS handshake completed at all. False means the
	// fingerprint and chain fields below are empty because nothing was served,
	// not because they matched nothing.
	Reached bool
	// Error is the dial/handshake failure, when Reached is false. Sanitized:
	// a network error string can contain arbitrary bytes.
	Error string
	// HandshakeMillis is how long the dial-and-handshake took, and
	// ChainBytes is the total DER size the endpoint served.
	//
	// M1 needs both: a PQ or hybrid combination that NEGOTIATES but triples the
	// handshake size is a different answer from one that negotiates cheaply, and
	// a readiness report that omitted cost would be recommending an outage. They
	// are zero when the handshake did not complete — zero is "not measured", not
	// "instant and free", and a reader must not average it in.
	HandshakeMillis int64
	ChainBytes      int
	// ExpectedFingerprint and ObservedFingerprint are hex SHA-256 of the leaf
	// DER. Observed is empty when the handshake failed.
	ExpectedFingerprint string
	ObservedFingerprint string
	// ExpectedSANDigest and ObservedSANDigest commit to the two name sets
	// without carrying them. Empty expected means no SAN check was asked for.
	ExpectedSANDigest string
	ObservedSANDigest string
	// ExpectedChainDigest and ObservedChainDigest commit to the issuer chains,
	// in served order.
	ExpectedChainDigest string
	ObservedChainDigest string
	// NotBeforeUnix and NotAfterUnix are the parsed peer validity window.
	// Zero is a valid Unix epoch date when ObservedFingerprint is present;
	// both are zero when no peer certificate could be parsed.
	NotBeforeUnix int64
	NotAfterUnix  int64
	// Mismatch is the verdict class, empty when the identity matched.
	Mismatch certinfo.Mismatch
	// CheckedSANs and CheckedChain record which comparisons ran, so a verdict
	// can never be read as having checked more than it did.
	CheckedSANs  bool
	CheckedChain bool
	// ObservedAtUnix is when the handshake happened, which is not when the
	// receipt was signed: a sweep can report minutes after it probed.
	ObservedAtUnix int64
}

// Canonical renders the transcript as the exact bytes that get digested.
func (t ProbeTranscript) Canonical() []byte {
	var b strings.Builder
	b.WriteString(transcriptVersion)
	b.WriteByte('\n')
	write := func(name, value string) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	write("address", t.Address)
	write("vantage", string(t.Vantage))
	write("server_name", t.ServerName)
	write("reached", strconv.FormatBool(t.Reached))
	write("handshake_ms", strconv.FormatInt(t.HandshakeMillis, 10))
	write("chain_bytes", strconv.Itoa(t.ChainBytes))
	write("error", t.Error)
	write("expected_fingerprint", t.ExpectedFingerprint)
	write("observed_fingerprint", t.ObservedFingerprint)
	write("expected_san_digest", t.ExpectedSANDigest)
	write("observed_san_digest", t.ObservedSANDigest)
	write("expected_chain_digest", t.ExpectedChainDigest)
	write("observed_chain_digest", t.ObservedChainDigest)
	write("not_before", strconv.FormatInt(t.NotBeforeUnix, 10))
	write("not_after", strconv.FormatInt(t.NotAfterUnix, 10))
	write("mismatch", string(t.Mismatch))
	write("checked_sans", strconv.FormatBool(t.CheckedSANs))
	write("checked_chain", strconv.FormatBool(t.CheckedChain))
	write("observed_at", strconv.FormatInt(t.ObservedAtUnix, 10))
	return []byte(b.String())
}

// ErrTranscriptInvalid is returned for a transcript that cannot be
// canonicalized unambiguously.
var ErrTranscriptInvalid = errors.New("transport: probe transcript is not canonicalizable")

// Validate refuses a transcript whose fields would make the canonical form
// ambiguous, and refuses a verdict that claims more than it checked.
func (t ProbeTranscript) Validate() error {
	if strings.TrimSpace(t.Address) == "" {
		return errors.New("transport: probe transcript has no address")
	}
	if !KnownVantage(t.Vantage) {
		return errors.New("transport: probe transcript has no recognised vantage")
	}
	if !certinfo.KnownMismatch(t.Mismatch) {
		return errors.New("transport: probe transcript carries an unknown mismatch class")
	}
	// A transcript that never reached the listener cannot have compared
	// anything. Letting one claim a clean verdict would turn an unreachable
	// endpoint into a verified one, which is the single worst thing this
	// surface could do.
	if !t.Reached {
		if t.Mismatch != certinfo.MismatchNone {
			return errors.New("transport: an unreached probe classified a mismatch it could not have observed")
		}
		if t.CheckedSANs || t.CheckedChain {
			return errors.New("transport: an unreached probe claims to have compared an identity")
		}
		if t.ObservedFingerprint != "" {
			return errors.New("transport: an unreached probe reported a served fingerprint")
		}
	}
	for _, v := range []string{
		t.Address, string(t.Vantage), t.ServerName, t.Error,
		t.ExpectedFingerprint, t.ObservedFingerprint,
		t.ExpectedSANDigest, t.ObservedSANDigest,
		t.ExpectedChainDigest, t.ObservedChainDigest, string(t.Mismatch),
	} {
		if strings.ContainsAny(v, "\n\r") {
			return ErrTranscriptInvalid
		}
	}
	return nil
}

// Digest is the value that goes in the receipt's evidence field.
//
// Hashing goes through internal/crypto like every other hash here (AN-3).
func (t ProbeTranscript) Digest() string {
	return crypto.SHA256Hex(t.Canonical())
}

// SANSetDigest commits to a name set independently of order and case.
//
// Order-independent because a certificate's SAN order is not meaningful and two
// listeners serving the same names in a different order are serving the same
// names. Case-normalised because DNS names are case-insensitive, and a digest
// that disagreed would raise a divergence nobody can fix.
//
// The empty set digests to the empty string rather than to the hash of nothing,
// so "no SAN expectation was supplied" and "an expectation of no names" are
// distinguishable in a transcript an operator reads.
func SANSetDigest(names []string) string {
	cleaned := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" {
			cleaned = append(cleaned, n)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	sort.Strings(cleaned)
	return crypto.SHA256Hex([]byte(strings.Join(cleaned, "\x00")))
}

// ChainDigest commits to an issuer chain IN SERVED ORDER.
//
// Ordered, unlike the SAN digest, because chain order changes how clients build
// paths: a chain served backwards breaks handshakes for implementations that do
// not reorder, and a digest that ignored order would call that identical.
func ChainDigest(fingerprints []string) string {
	if len(fingerprints) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		cleaned = append(cleaned, strings.ToLower(strings.TrimSpace(strings.ReplaceAll(fp, ":", ""))))
	}
	return crypto.SHA256Hex([]byte(strings.Join(cleaned, "\x00")))
}

// SweepDigest commits to a whole verification sweep.
//
// One digest for the report rather than one per endpoint, because the receipt
// signs once per job: an operator checking a sweep's receipt is asking whether
// THIS report is the one the agent signed, and a per-endpoint digest would not
// answer that without also committing to the set.
func SweepDigest(canonical []byte) string {
	if len(canonical) == 0 {
		return ""
	}
	return crypto.SHA256Hex(canonical)
}

// SanitizeProbeError makes a dial or handshake error safe for a signed
// statement.
//
// Network error strings are not trusted input: they can embed a server-supplied
// hostname or an arbitrary byte sequence, and a newline in one would fake a
// field boundary in the canonical encoding. Bounded too — an error is a hint
// for an operator, not a payload.
func SanitizeProbeError(err error) string {
	if err == nil {
		return ""
	}
	const max = 240
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

// Verification outcomes reported on a job.
//
// These extend the existing outcome vocabulary rather than replacing it: a
// deploy that wrote its files and then failed verification is NOT the same as a
// deploy that failed to write, and reporting both as "failed" would make the
// D4 rollback decision — which is about a bad certificate serving traffic —
// impossible to reach correctly.
const (
	// OutcomeVerifyFailed: the work was applied but the listener is not serving
	// what it should be. This is the outcome that justifies a rollback.
	OutcomeVerifyFailed = "verify_failed"
	// OutcomeVerified: the work was applied and the listener was observed
	// serving the expected identity.
	OutcomeVerified = "verified"
)
