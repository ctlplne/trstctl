// SPDX-License-Identifier: BUSL-1.1

// Package verify handshakes an endpoint and reports what it is actually
// serving (epic D2).
//
// This is the answer to a question the platform could not previously ask. Expiry
// alerting reads the inventory — what trstctl BELIEVES is deployed — so a
// renewal that succeeds at the CA and never reaches the listener is invisible:
// the inventory is correct and complete and describes a certificate nobody is
// serving. Only a handshake can tell those apart.
//
// Two vantages, and the difference between them is not redundancy:
//
//   - LOCAL is the host agent connecting to a listener on its own machine
//     immediately after deploying to it. It proves the file landed AND the
//     service reloaded, which is the step nothing else in the pipeline observes:
//     a connector's reload is one exec call inside its own Deploy method, and its
//     failure is invisible to everything downstream.
//   - RELAY is a network agent connecting across the segment as a client would.
//     It is the only witness available for an appliance — nothing runs on an F5 —
//     and the only one that proves the endpoint is reachable at all.
//
// A local pass with no relay witness means "the box thinks it is fine". That is
// worth knowing and it is not the same as "clients can reach it", so the record
// always carries which vantage produced it.
package verify

import (
	"context"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// DefaultTimeout bounds one handshake. A verification sweep touches many
// endpoints and an unreachable one must cost a few seconds, not a stall.
const DefaultTimeout = 8 * time.Second

// Request is one endpoint to verify.
type Request struct {
	// Address is host:port. Required.
	Address string
	// ServerName overrides SNI. Empty sends the address host, which is what a
	// client would do.
	ServerName string
	// Vantage records where this probe runs from.
	Vantage transport.Vantage
	// Expect is what the endpoint is supposed to be serving.
	Expect certinfo.Expectation
	// Timeout bounds the handshake; DefaultTimeout when zero.
	Timeout time.Duration
	// PreHandshake performs the configured application's TLS upgrade before
	// ClientHello. Nil is direct TLS; a refusal never falls back to plaintext.
	PreHandshake tlsprobe.PreHandshake
}

// Result pairs the verdict with the transcript that justifies it.
type Result struct {
	Verdict    certinfo.Verdict
	Transcript transport.ProbeTranscript
}

// OK reports whether the endpoint served what it should.
//
// Unreachable is NOT ok. That looks obvious written down, and it is exactly the
// mistake worth guarding: a sweep that treated "could not connect" as "nothing
// to report" would mark an endpoint healthy for being down.
func (r Result) OK() bool { return r.Transcript.Reached && r.Verdict.OK() }

// ErrNoAddress is returned when a verification request names nothing to dial.
var ErrNoAddress = errors.New("verify: no endpoint address to handshake")

// Endpoint performs one handshake and classifies what was served.
//
// It never returns an error for a failed handshake: an unreachable endpoint is
// a RESULT, not an error, and the transcript records it as one. An error comes
// back only when the request itself is unusable — which is a programming or
// configuration fault rather than an observation.
func Endpoint(ctx context.Context, req Request) (Result, error) {
	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		return Result{}, ErrNoAddress
	}
	vantage := req.Vantage
	if !transport.KnownVantage(vantage) {
		return Result{}, errors.New("verify: probe has no recognised vantage")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	observedAt := time.Now().UTC()
	tr := transport.ProbeTranscript{
		Address:             addr,
		Vantage:             vantage,
		ServerName:          strings.TrimSpace(req.ServerName),
		ExpectedFingerprint: normalizeFP(req.Expect.SHA256Fingerprint),
		ExpectedSANDigest:   transport.SANSetDigest(req.Expect.DNSNames),
		ExpectedChainDigest: transport.ChainDigest(req.Expect.ChainFingerprints),
		ObservedAtUnix:      observedAt.Unix(),
	}

	// Timed so a PQ compatibility pilot can report COST, not just whether the
	// handshake worked (M1). Measured around the dial itself, so it includes the
	// key exchange whose size is the whole question for a hybrid group.
	handshakeStart := time.Now()
	probe, err := tlsprobe.Probe(ctx, addr, tlsprobe.WithTimeout(timeout), tlsprobe.WithServerName(strings.TrimSpace(req.ServerName)), tlsprobe.WithPreHandshake(req.PreHandshake))
	tr.HandshakeMillis = time.Since(handshakeStart).Milliseconds()
	if err != nil {
		// Unreachable. The transcript says so and claims nothing else: no
		// mismatch class, no comparison flags, no served fingerprint. Its
		// Validate() enforces that, so a caller cannot accidentally dress a
		// failed dial up as a clean verification.
		tr.Error = transport.SanitizeProbeError(err)
		return Result{
			Verdict: certinfo.Verdict{
				Mismatch: certinfo.MismatchNone,
				Detail:   "endpoint could not be reached: " + tr.Error,
			},
			Transcript: tr,
		}, nil
	}
	if len(probe.PeerCertificates) == 0 {
		tr.Error = "handshake completed but the endpoint presented no certificate"
		return Result{
			Verdict:    certinfo.Verdict{Detail: tr.Error},
			Transcript: tr,
		}, nil
	}

	tr.Reached = true
	for _, der := range probe.PeerCertificates {
		tr.ChainBytes += len(der)
	}
	leaf, err := certinfo.Inspect(probe.PeerCertificates[0])
	if err != nil {
		// Served something unparseable. Reached is true — we did connect — and
		// the mismatch is a fingerprint one, because whatever is there is not
		// the certificate we deployed.
		tr.Error = transport.SanitizeProbeError(err)
		tr.Mismatch = certinfo.MismatchFingerprint
		return Result{
			Verdict: certinfo.Verdict{
				Mismatch: certinfo.MismatchFingerprint,
				Detail:   "endpoint served a certificate that could not be parsed: " + tr.Error,
			},
			Transcript: tr,
		}, nil
	}

	chain := make([]string, 0, len(probe.PeerCertificates)-1)
	for _, der := range probe.PeerCertificates[1:] {
		info, ierr := certinfo.Inspect(der)
		if ierr != nil {
			// One unparseable issuer does not invalidate the observation, but
			// it must not silently shorten the chain either — a shortened chain
			// would compare as a chain mismatch for the wrong reason. Record a
			// placeholder so the length stays honest.
			chain = append(chain, "unparseable")
			continue
		}
		chain = append(chain, normalizeFP(info.SHA256Fingerprint))
	}

	tr.ObservedFingerprint = normalizeFP(leaf.SHA256Fingerprint)
	tr.ObservedSANDigest = transport.SANSetDigest(leaf.DNSNames)
	tr.ObservedChainDigest = transport.ChainDigest(chain)
	tr.NotBeforeUnix = unixOrZero(leaf.NotBefore)
	tr.NotAfterUnix = unixOrZero(leaf.NotAfter)

	verdict := certinfo.Compare(req.Expect, certinfo.Observation{
		Leaf:              leaf,
		ChainFingerprints: chain,
		At:                observedAt,
	})
	if verdict.OK() && strings.TrimSpace(req.ServerName) != "" &&
		certinfo.VerifyHostname(probe.PeerCertificates[0], req.ServerName) != nil {
		verdict.Mismatch = certinfo.MismatchSANs
		verdict.CheckedSANs = true
		verdict.Detail = "served certificate is not valid for the configured server name"
	}
	tr.Mismatch = verdict.Mismatch
	tr.CheckedSANs = verdict.CheckedSANs
	tr.CheckedChain = verdict.CheckedChain

	return Result{Verdict: verdict, Transcript: tr}, nil
}

func normalizeFP(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, ":", "")))
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
