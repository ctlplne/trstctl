// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// The fixture speaks PostgreSQL's SSLRequest and then forwards a real TLS
// handshake. It is protocol regression evidence; the QA journey separately
// qualifies a real PostgreSQL server and reload.
func postgresVerificationListener(t *testing.T, upstream string, offerTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var request [8]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil || !bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
					return
				}
				if !offerTLS {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				peer, err := net.DialTimeout("tcp", upstream, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(peer, conn); _ = peer.Close(); close(copied) }()
				_, _ = io.Copy(conn, peer)
				_ = conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-stopped; connections.Wait() })
	return ln.Addr().String()
}

func TestPostgreSQLNetworkVerificationKeepsProtocolAndReportsDivergence(t *testing.T) {
	server, err := tlsprobe.NewServingTestServer("database.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	address := postgresVerificationListener(t, server.Addr, true)
	expect, err := certinfo.ExpectationFromChain(server.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	intent := EndpointVerifyIntent{Endpoints: []EndpointExpectation{
		{EndpointID: "postgres", Address: address, ServerName: "database.example.test", Connector: "postgresql", Fingerprint: expect.SHA256Fingerprint},
		{EndpointID: "wrong-leaf", Address: address, ServerName: "database.example.test", Connector: "postgresql", Fingerprint: "00"},
		{EndpointID: "refuses-tls", Address: postgresVerificationListener(t, server.Addr, false), Connector: "postgresql", Fingerprint: expect.SHA256Fingerprint},
		{EndpointID: "legacy-direct", Address: server.Addr, ServerName: "database.example.test", Fingerprint: expect.SHA256Fingerprint},
	}}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	ch := &trustTestChannel{jobs: []Job{{JobID: 36, Attempt: 1, Kind: KindEndpointVerify, Payload: payload}}}
	if _, err := RunOnce(t.Context(), ch, http.DefaultClient, 1, 30); err != nil {
		t.Fatal(err)
	}
	if ch.redeemCalls != 0 || len(ch.reports) != 1 || ch.reports[0].outcome != OutcomeExecuted || ch.reports[0].evidence == "" {
		t.Fatalf("verification redeemed credentials or lost its evidence: %+v", ch)
	}
	var report EndpointVerifyReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || len(report.Results) != 4 {
		t.Fatalf("incomplete sweep: %+v err=%v", report, err)
	}
	for _, index := range []int{0, 3} {
		got := report.Results[index].Transcript
		if !got.Reached || got.Mismatch != certinfo.MismatchNone || got.ServerName != "database.example.test" || got.Vantage != transport.VantageRelay {
			t.Fatalf("valid listener not verified: %+v", got)
		}
	}
	if report.Results[1].Transcript.Mismatch != certinfo.MismatchFingerprint || report.Results[2].Transcript.Reached {
		t.Fatalf("divergence or TLS refusal blessed: %+v", report)
	}
	if ch.reports[0].evidence != sweepDigest(report) {
		t.Fatal("evidence digest does not commit to the complete sweep")
	}
}

func TestPostgreSQLHostPreviewAndPostDeployNegotiateSSLRequest(t *testing.T) {
	server, err := tlsprobe.NewServingTestServer("database.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	address := postgresVerificationListener(t, server.Addr, true)
	if got := probeHostListener(t.Context(), address, "database.example.test", nil); got.Status != StepFailed {
		t.Fatal("fixture accepted bare TLS")
	}
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "server.crt"), filepath.Join(root, "server.key")
	for _, p := range []string{certPath, keyPath} {
		if err := os.WriteFile(p, []byte("unchanged fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command, err := exec.LookPath("true")
	if err != nil {
		t.Skip("host exec profile requires a local true command")
	}
	config, err := json.Marshal(HostTargetConfig{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	intent := DeployIntent{Connector: "postgresql", Target: "database", TargetID: "database-target", TargetConfig: config, VerifyAddress: address, VerifyServerName: "database.example.test"}
	plan, err := DryRunOnHost(t.Context(), http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{{LogicalName: "pg_ctl", Command: command, PassArgs: true}}}, intent, nil)
	if err != nil || !plan.Ready {
		t.Fatalf("PostgreSQL preview: ready=%v steps=%+v err=%v", plan.Ready, plan.Steps, err)
	}
	for _, p := range []string{certPath, keyPath} {
		b, err := os.ReadFile(p) // #nosec G304 -- p is one of two fixed filenames under t.TempDir, with no external input (CWE-22).
		if err != nil || string(b) != "unchanged fixture" {
			t.Fatalf("preview changed %s", p)
		}
	}
	material := Material{"credential.cert_pem": server.LeafPEM}
	outcome, detail, evidence := postDeployVerification(context.Background(), intent, material)
	if outcome != transport.OutcomeVerified || evidence == "" {
		t.Fatalf("post-deploy outcome=%s detail=%s evidence=%s", outcome, detail, evidence)
	}
	var report EndpointVerifyReport
	if err := json.Unmarshal([]byte(detail), &report); err != nil || len(report.Results) != 1 || !report.Results[0].Transcript.Reached || report.Results[0].Transcript.ServerName != intent.VerifyServerName {
		t.Fatalf("missing exact signed transcript: %s err=%v", detail, err)
	}
	// A reachable database with the wrong identity must still fail, and a
	// server declining SSLRequest must never be treated as healthy plaintext.
	intent.VerifyServerName = "wrong.example.test"
	if outcome, _, _ := postDeployVerification(t.Context(), intent, material); outcome != transport.OutcomeVerifyFailed {
		t.Fatalf("wrong hostname accepted: %s", outcome)
	}
	intent.VerifyServerName = "database.example.test"
	intent.VerifyAddress = postgresVerificationListener(t, server.Addr, false)
	if got := probeHostListener(t.Context(), intent.VerifyAddress, intent.VerifyServerName, connectorTLSNegotiation(intent.Connector)); got.Status != StepFailed {
		t.Fatal("TLS refusal accepted in preview")
	}
	if outcome, _, _ := postDeployVerification(t.Context(), intent, material); outcome != transport.OutcomeVerifyFailed {
		t.Fatalf("TLS refusal accepted after deploy: %s", outcome)
	}
}
