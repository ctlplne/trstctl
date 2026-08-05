// SPDX-License-Identifier: MPL-2.0

package transport_test

import (
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func reachedTranscript() transport.ProbeTranscript {
	return transport.ProbeTranscript{
		Address:             "api.example.test:443",
		Vantage:             transport.VantageRelay,
		Reached:             true,
		ExpectedFingerprint: "aa11",
		ObservedFingerprint: "aa11",
		ObservedAtUnix:      1754308800,
	}
}

// An unreachable endpoint must never be able to report a clean verdict.
//
// This is the single worst thing this surface could do: an endpoint nobody
// could connect to, recorded as verified, is a false assurance stronger than
// the one the epic exists to remove — the inventory at least never claimed to
// have looked.
func TestAnUnreachedProbeCannotClaimAVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		mutfn func(*transport.ProbeTranscript)
	}{
		{"classified a mismatch", func(p *transport.ProbeTranscript) { p.Mismatch = certinfo.MismatchFingerprint }},
		{"claimed a SAN comparison", func(p *transport.ProbeTranscript) { p.CheckedSANs = true }},
		{"claimed a chain comparison", func(p *transport.ProbeTranscript) { p.CheckedChain = true }},
		{"reported a served fingerprint", func(p *transport.ProbeTranscript) { p.ObservedFingerprint = "bb22" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := transport.ProbeTranscript{
				Address: "unreachable.example.test:443",
				Vantage: transport.VantageRelay,
				Reached: false,
				Error:   "dial tcp: connection refused",
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("a plain unreached transcript was refused: %v", err)
			}
			tc.mutfn(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("an unreached probe that %s validated; nothing was served, so there was "+
					"nothing to compare and nothing to verify", tc.name)
			}
		})
	}
}

// The transcript is what the signature commits to, so its encoding must be
// unambiguous. A value carrying a newline could write its own field line.
func TestTranscriptRefusesValuesThatWouldFakeAFieldBoundary(t *testing.T) {
	t.Parallel()
	p := reachedTranscript()
	p.Error = "handshake failed\nmismatch="
	if err := p.Validate(); !errors.Is(err, transport.ErrTranscriptInvalid) {
		t.Fatalf("Validate() = %v, want ErrTranscriptInvalid — a newline in a value lets it "+
			"write its own line into the signed bytes", err)
	}
}

// An unknown mismatch class is refused rather than carried, because the
// database CHECK constraint and the console both render against a closed set.
func TestTranscriptRefusesAnUnknownMismatchClass(t *testing.T) {
	t.Parallel()
	p := reachedTranscript()
	p.Mismatch = certinfo.Mismatch("invented")
	if err := p.Validate(); err == nil {
		t.Fatal("an invented mismatch class validated; it would reach an operator as a blank cell")
	}
}

// Changing any observed fact changes the digest. Without this the evidence
// digest in a receipt would commit to nothing.
func TestEveryTranscriptFieldChangesTheDigest(t *testing.T) {
	t.Parallel()
	base := reachedTranscript()
	baseDigest := base.Digest()

	mutations := map[string]func(*transport.ProbeTranscript){
		"address":          func(p *transport.ProbeTranscript) { p.Address = "other.example.test:443" },
		"vantage":          func(p *transport.ProbeTranscript) { p.Vantage = transport.VantageLocal },
		"server name":      func(p *transport.ProbeTranscript) { p.ServerName = "sni.example.test" },
		"reached":          func(p *transport.ProbeTranscript) { p.Reached = false; p.ObservedFingerprint = "" },
		"observed leaf":    func(p *transport.ProbeTranscript) { p.ObservedFingerprint = "bb22" },
		"expected leaf":    func(p *transport.ProbeTranscript) { p.ExpectedFingerprint = "cc33" },
		"san digest":       func(p *transport.ProbeTranscript) { p.ObservedSANDigest = "dd44" },
		"chain digest":     func(p *transport.ProbeTranscript) { p.ObservedChainDigest = "ee55" },
		"not after":        func(p *transport.ProbeTranscript) { p.NotAfterUnix = 1 },
		"mismatch":         func(p *transport.ProbeTranscript) { p.Mismatch = certinfo.MismatchChain },
		"checked sans":     func(p *transport.ProbeTranscript) { p.CheckedSANs = true },
		"checked chain":    func(p *transport.ProbeTranscript) { p.CheckedChain = true },
		"observation time": func(p *transport.ProbeTranscript) { p.ObservedAtUnix = 1754308801 },
	}
	for name, mutate := range mutations {
		p := base
		mutate(&p)
		if p.Digest() == baseDigest {
			t.Errorf("changing the %s left the digest unchanged; the receipt's evidence field "+
				"would commit to a transcript that no longer describes what happened", name)
		}
	}
}

// The SAN digest ignores order and case, because neither changes which names a
// certificate covers — and a digest that disagreed would raise a divergence
// nobody could fix.
func TestSANDigestIgnoresOrderAndCase(t *testing.T) {
	t.Parallel()
	a := transport.SANSetDigest([]string{"api.example.test", "WWW.Example.Test."})
	b := transport.SANSetDigest([]string{"www.example.test", "API.EXAMPLE.TEST"})
	if a != b {
		t.Errorf("SAN digests differ across order and case: %q vs %q", a, b)
	}
	if transport.SANSetDigest(nil) != "" {
		t.Error("an absent SAN expectation must digest to empty, so it stays distinguishable " +
			"from an expectation of no names")
	}
	if transport.SANSetDigest([]string{"a.test"}) == transport.SANSetDigest([]string{"b.test"}) {
		t.Error("different name sets produced the same digest")
	}
}

// The chain digest RESPECTS order, unlike the SAN digest, because a chain
// served backwards breaks handshakes for clients that do not reorder.
func TestChainDigestRespectsOrder(t *testing.T) {
	t.Parallel()
	forward := transport.ChainDigest([]string{"int1", "root1"})
	backward := transport.ChainDigest([]string{"root1", "int1"})
	if forward == backward {
		t.Error("a reordered chain digested identically; order is what clients build paths from")
	}
	if transport.ChainDigest(nil) != "" {
		t.Error("an absent chain expectation must digest to empty")
	}
}

// A network error is untrusted input and is bounded and stripped before it can
// enter a signed statement.
func TestProbeErrorsAreSanitizedAndBounded(t *testing.T) {
	t.Parallel()
	if got := transport.SanitizeProbeError(nil); got != "" {
		t.Errorf("nil error sanitized to %q", got)
	}
	got := transport.SanitizeProbeError(errors.New("x509: bad\r\nmismatch=none\nfor " + strings.Repeat("a", 500)))
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("sanitized error still contains a newline: %q", got)
	}
	if len(got) > 260 {
		t.Errorf("sanitized error is %d bytes; an error is a hint, not a payload", len(got))
	}

	p := reachedTranscript()
	p.Reached = false
	p.ObservedFingerprint = ""
	p.Error = got
	if err := p.Validate(); err != nil {
		t.Errorf("a sanitized error was still refused by the statement encoding: %v", err)
	}
}

// The version prefix is load-bearing: a change to the field set must make old
// digests fail to match rather than silently mean something new.
func TestTranscriptCarriesItsVersion(t *testing.T) {
	t.Parallel()
	canonical := string(reachedTranscript().Canonical())
	if !strings.HasPrefix(canonical, "trstctl-endpoint-probe-transcript/v1\n") {
		t.Fatalf("transcript does not start with its version line: %q", canonical[:40])
	}
}

// Both vantages are recognised and nothing else is. A record that did not say
// where it was observed from would let a passing local check stand in for
// evidence the endpoint is reachable.
func TestVantageVocabularyIsClosed(t *testing.T) {
	t.Parallel()
	if !transport.KnownVantage(transport.VantageLocal) || !transport.KnownVantage(transport.VantageRelay) {
		t.Fatal("a shipped vantage is not recognised")
	}
	if transport.KnownVantage(transport.Vantage("somewhere")) {
		t.Error("an unknown vantage was accepted")
	}
	p := reachedTranscript()
	p.Vantage = transport.Vantage("somewhere")
	if err := p.Validate(); err == nil {
		t.Error("a transcript with an unknown vantage validated")
	}
}

// M1: a PQ pilot's readiness report has to say what a combination COST, not
// only whether it worked. A hybrid group that negotiates but triples the
// handshake is a different answer from one that negotiates cheaply, and a
// report omitting cost would be recommending an outage.
func TestTheTranscriptCarriesHandshakeCost(t *testing.T) {
	t.Parallel()
	tr := transport.ProbeTranscript{Address: "host:443", Reached: true, HandshakeMillis: 42, ChainBytes: 4096}
	canon := string(tr.Canonical())
	for _, want := range []string{"handshake_ms", "chain_bytes"} {
		if !strings.Contains(canon, want) {
			t.Fatalf("the canonical transcript omits %q.\n\n"+
				"Cost that is not in the transcript cannot be signed into a readiness report, and "+
				"a PQ rollout recommended without it is a recommendation made blind.", want)
		}
	}
}

// Zero is "not measured", never "instant and free". A failed handshake must not
// contribute a zero that a reader averages in as a fast success.
func TestUnreachedProbesReportZeroCostNotFastSuccess(t *testing.T) {
	t.Parallel()
	tr := transport.ProbeTranscript{Address: "host:443", Reached: false}
	if tr.HandshakeMillis != 0 || tr.ChainBytes != 0 {
		t.Fatal("an unreached probe carried a cost measurement")
	}
	// The pairing with Reached is the guard: a consumer must read Reached
	// before trusting either number.
	if tr.Reached {
		t.Fatal("precondition")
	}
}
