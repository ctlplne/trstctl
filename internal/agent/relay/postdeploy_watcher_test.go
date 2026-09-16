// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// A TCP proxy selects one real TLS listener per new connection. This models
// a watched-file service's delayed activation without replacing verification
// with a fake success result. The live journey separately uses stock Elasticsearch.
func watchedTLSListener(t *testing.T, oldAddress, newAddress string, activateAfter time.Duration) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var active sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		var firstConnection time.Time
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if firstConnection.IsZero() {
				firstConnection = time.Now()
			}
			address := oldAddress
			if time.Since(firstConnection) >= activateAfter {
				address = newAddress
			}
			active.Add(1)
			go func() {
				defer active.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				peer, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(peer, conn); _ = peer.Close(); close(copied) }()
				_, _ = io.Copy(conn, peer)
				_ = conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-stopped; active.Wait() })
	return listener.Addr().String()
}

func TestElasticsearchWatchedCertificateVerification(t *testing.T) {
	old, err := tlsprobe.NewServingTestServer("search.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.Close)
	fresh, err := tlsprobe.NewServingTestServer("search.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Close)
	expectation, err := certinfo.ExpectationFromChain(fresh.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	material := Material{"credential.cert_pem": fresh.LeafPEM}
	for _, tc := range []struct {
		name          string
		delay         time.Duration
		serverName    string
		cancelAfter   time.Duration
		missingIssuer bool
		want          string
	}{
		{name: "activates_on_five_second_file_watch", delay: 5 * time.Second, serverName: "search.example.test", want: transport.OutcomeVerified},
		{name: "ignored_file_change_still_fails", delay: time.Hour, serverName: "search.example.test", want: transport.OutcomeVerifyFailed},
		{name: "wrong_hostname_still_fails", delay: 0, serverName: "other.example.test", want: transport.OutcomeVerifyFailed},
		{name: "missing_expected_issuer_still_fails", delay: 0, serverName: "search.example.test", missingIssuer: true, want: transport.OutcomeVerifyFailed},
		{name: "caller_cancellation_stops_wait", delay: time.Hour, serverName: "search.example.test", cancelAfter: 250 * time.Millisecond, want: transport.OutcomeVerifyFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			material := material
			expectation := expectation
			if tc.missingIssuer {
				chain := append(append([]byte(nil), fresh.LeafPEM...), old.LeafPEM...)
				material = Material{"credential.cert_pem": chain}
				var err error
				expectation, err = certinfo.ExpectationFromChain(chain)
				if err != nil {
					t.Fatal(err)
				}
			}
			intent := DeployIntent{Connector: "elasticsearch", TargetID: "search-target", VerifyAddress: watchedTLSListener(t, old.Addr, fresh.Addr, tc.delay), VerifyServerName: tc.serverName}
			ctx := t.Context()
			if tc.cancelAfter > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.cancelAfter)
				defer cancel()
			}
			start := time.Now()
			outcome, detail, evidence := postDeployVerification(ctx, intent, material)
			elapsed := time.Since(start)
			if outcome != tc.want {
				t.Fatalf("outcome=%s want=%s after=%s detail=%s", outcome, tc.want, elapsed, detail)
			}
			// The production function already has this overall bound. The repair must
			// fit inside it rather than extending a deadline to satisfy this test.
			if elapsed > 10*time.Second {
				t.Fatalf("verification exceeded original 10s budget: %s", elapsed)
			}
			if tc.cancelAfter > 0 {
				if elapsed > time.Second {
					t.Fatalf("cancellation took %s", elapsed)
				}
				return
			}
			var report EndpointVerifyReport
			if err := json.Unmarshal([]byte(detail), &report); err != nil || len(report.Results) != 1 {
				t.Fatalf("missing report: %s err=%v", detail, err)
			}
			tr := report.Results[0].Transcript
			if evidence == "" || evidence != tr.Digest() || tr.ExpectedFingerprint != expectation.SHA256Fingerprint || tr.Vantage != transport.VantageLocal {
				t.Fatalf("missing exact local signed evidence: %+v", tr)
			}
			if tc.missingIssuer && (!tr.CheckedChain || tr.Mismatch != certinfo.MismatchChain) {
				t.Fatalf("missing issuer accepted or unchecked: %+v", tr)
			}
			if err := tr.Validate(); err != nil {
				t.Fatal(err)
			}
			if tc.want == transport.OutcomeVerified && (!tr.Reached || tr.Mismatch != certinfo.MismatchNone || tr.ObservedFingerprint != expectation.SHA256Fingerprint || tr.CheckedChain != (len(expectation.ChainFingerprints) > 0) || !tr.CheckedSANs || tr.ServerName != tc.serverName) {
				t.Fatalf("verification weakened: %+v", tr)
			}
		})
	}
}
