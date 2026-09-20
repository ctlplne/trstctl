// SPDX-License-Identifier: BUSL-1.1

package verify_test

import (
	"context"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// The renewal that succeeded at the CA and never landed (epic D2).
//
// These run against REAL TLS listeners. That is the point of the epic: the
// failure it exists to catch is invisible to every check that reads trstctl's
// own inventory, because the inventory is correct — it describes a certificate
// nobody is serving. Only a handshake distinguishes them, so the tests
// handshake.

// serveTLS starts a real loopback TLS listener presenting a fresh certificate
// for the given names, and returns its address plus the leaf it serves.
//
// Fresh per  call: two servers for the same names present DIFFERENT certificates,
// which is exactly the shape of a renewal that never landed — same names, and
// the listener is still on the old one.
func serveTLS(t *testing.T, names ...string) (addr string, leafPEM []byte) {
	t.Helper()
	srv, err := tlsprobe.NewServingTestServer(names...)
	if err != nil {
		t.Fatalf("start serving test server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv.Addr, srv.LeafPEM
}

// expectationFor builds what a deployer would have recorded for a certificate.
func expectationFor(t *testing.T, leafPEM []byte) certinfo.Expectation {
	t.Helper()
	exp, err := certinfo.ExpectationFromChain(leafPEM)
	if err != nil {
		t.Fatalf("build expectation: %v", err)
	}
	return exp
}

// The headline: a listener serving a certificate other than the deployed one is
// caught, and named as a fingerprint mismatch rather than as a vague failure.
func TestAListenerServingTheWrongCertificateIsCaught(t *testing.T) {
	t.Parallel()

	// The certificate that WAS deployed: minted, then its server discarded, so
	// only the expectation survives — exactly what a renewal leaves behind.
	_, deployedPEM := serveTLS(t, "api.example.test")
	deployed := expectationFor(t, deployedPEM)

	// The listener is still serving the OTHER certificate for the same name.
	addr, _ := serveTLS(t, "api.example.test")

	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr,
		Vantage: transport.VantageRelay,
		Expect:  deployed,
	})
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if res.OK() {
		t.Fatal("a listener serving a different certificate verified successfully — this is the " +
			"exact failure the epic exists to catch, and it is invisible to inventory-based " +
			"expiry alerting because the inventory correctly describes the new certificate")
	}
	if res.Verdict.Mismatch != certinfo.MismatchFingerprint {
		t.Errorf("Mismatch = %q, want fingerprint", res.Verdict.Mismatch)
	}
	if !res.Transcript.Reached {
		t.Error("the endpoint was reachable but the transcript says otherwise")
	}
	if res.Transcript.ObservedFingerprint == res.Transcript.ExpectedFingerprint {
		t.Error("the transcript recorded the expected fingerprint as the observed one")
	}
	if err := res.Transcript.Validate(); err != nil {
		t.Errorf("transcript is not reportable: %v", err)
	}
}

// The happy path, and the part that matters about it: the transcript's evidence
// digest is stable and commits to what was seen.
func TestAListenerServingTheDeployedCertificateVerifies(t *testing.T) {
	t.Parallel()
	addr, leafPEM := serveTLS(t, "api.example.test", "www.example.test")

	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr,
		Vantage: transport.VantageLocal,
		Expect:  expectationFor(t, leafPEM),
	})
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a correctly-serving endpoint failed: %s (%s)", res.Verdict.Mismatch, res.Verdict.Detail)
	}
	if !res.Verdict.CheckedSANs {
		t.Error("the SAN set was supplied but the verdict does not report having checked it")
	}
	if res.Transcript.Digest() == "" {
		t.Error("no evidence digest was produced, so the receipt would commit to nothing")
	}
	if res.Transcript.ObservedSANDigest != res.Transcript.ExpectedSANDigest {
		t.Error("SAN digests differ for an endpoint serving exactly the expected names")
	}
}

// Unreachable is a RESULT, not an error — and emphatically not a pass.
//
// A sweep that treated "could not connect" as "nothing to report" would mark an
// endpoint healthy for being down, which is worse than the blindness this epic
// removes: the inventory never claimed to have looked.
func TestAnUnreachableEndpointIsNotVerified(t *testing.T) {
	t.Parallel()

	// A port nobody is listening on: bind, read the address, close.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr,
		Vantage: transport.VantageRelay,
		Expect:  certinfo.Expectation{SHA256Fingerprint: "aa11"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("an unreachable endpoint returned an error rather than a result: %v", err)
	}
	if res.OK() {
		t.Fatal("an endpoint nobody could connect to reported as verified")
	}
	if res.Transcript.Reached {
		t.Error("the transcript claims the handshake completed")
	}
	if res.Transcript.Error == "" {
		t.Error("no reason was recorded for an unreachable endpoint")
	}
	// And it claims nothing it could not have seen.
	if res.Transcript.ObservedFingerprint != "" || res.Transcript.CheckedSANs || res.Transcript.CheckedChain {
		t.Error("an unreached probe recorded an observation")
	}
	if err := res.Transcript.Validate(); err != nil {
		t.Errorf("an unreachable transcript is not reportable: %v", err)
	}
}

// The SAN case: the right certificate is being served for the wrong names. The
// remedy differs from a fingerprint mismatch — reissue, not redeploy — so the
// class must differ too.
func TestAServedCertificateCoveringTheWrongNamesIsASANMismatch(t *testing.T) {
	t.Parallel()
	addr, leafPEM := serveTLS(t, "api.example.test")
	expect := expectationFor(t, leafPEM)
	// The caller expected this certificate to cover another name too.
	expect.DNSNames = []string{"api.example.test", "payments.example.test"}

	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr,
		Vantage: transport.VantageRelay,
		Expect:  expect,
	})
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if res.Verdict.Mismatch != certinfo.MismatchSANs {
		t.Fatalf("Mismatch = %q, want sans", res.Verdict.Mismatch)
	}
	if res.OK() {
		t.Error("a name-set divergence verified successfully")
	}
}

// A deploy verifies the exact bytes it wrote, but that is not enough: those
// bytes may be a perfectly well-formed certificate for the wrong hostname.
// The operator's configured SNI is therefore an independent name check.
func TestTheDeployedCertificateWithTheWrongConfiguredServerNameFails(t *testing.T) {
	t.Parallel()
	addr, leafPEM := serveTLS(t, "wrong.example.test")
	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr, ServerName: "wanted.example.test", Vantage: transport.VantageLocal,
		Expect: expectationFor(t, leafPEM),
	})
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if res.OK() || res.Verdict.Mismatch != certinfo.MismatchSANs {
		t.Fatalf("wrong configured server name verdict = %+v", res.Verdict)
	}
	if res.Transcript.ServerName != "wanted.example.test" || res.Transcript.Mismatch != certinfo.MismatchSANs {
		t.Fatalf("wrong-SAN transcript = %+v", res.Transcript)
	}
}

// A request with no vantage is refused rather than defaulted.
//
// Defaulting would let a local self-check be recorded as network evidence, and
// "the box thinks it is fine" is not the same claim as "clients can reach it".
func TestAProbeMustSayWhereItRanFrom(t *testing.T) {
	t.Parallel()
	_, err := verify.Endpoint(context.Background(), verify.Request{
		Address: "127.0.0.1:1",
		Expect:  certinfo.Expectation{SHA256Fingerprint: "aa11"},
	})
	if err == nil {
		t.Fatal("a probe with no vantage was accepted; the record could not say whether a local " +
			"self-check or a network probe produced it")
	}
}

// The digest is computed inside the crypto boundary, and the transcript is what
// the receipt commits to. This pins the two together.
func TestTranscriptDigestMatchesTheBoundaryHash(t *testing.T) {
	t.Parallel()
	addr, leafPEM := serveTLS(t, "api.example.test")

	res, err := verify.Endpoint(context.Background(), verify.Request{
		Address: addr, Vantage: transport.VantageLocal,
		Expect: expectationFor(t, leafPEM),
	})
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if got, want := res.Transcript.Digest(), crypto.SHA256Hex(res.Transcript.Canonical()); got != want {
		t.Errorf("Digest() = %s, want the boundary hash of the canonical bytes %s", got, want)
	}
}
