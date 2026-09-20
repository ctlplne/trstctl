// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"os/exec"
	"trstctl.com/trstctl/internal/agent/workloadapi"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe"
)

// A STOCK go-spiffe client against the HOST's socket (epic B3).
//
// This is the acceptance criterion, and it is deliberately the same proof the
// control plane's own socket already has to pass. A Workload API that only the
// project's own client can talk to is not a Workload API — the entire value is
// that a workload built against go-spiffe, or a spiffe-helper sidecar shipped by
// someone else, dials it unmodified.
//
// Running the identical client against both sockets is what makes "we moved the
// Workload API" a checkable claim rather than an assertion: whatever the stock
// client accepted from the control plane, it must accept from the host.

// hostWorkloadUpstream is a control plane that signs what the host sends up.
//
// Real signing, not a stub returning bytes: the stock client VALIDATES the chain
// it receives, so a fake certificate would fail the client rather than the
// server and the test would prove nothing about either.
type hostWorkloadUpstream struct {
	wl       *spiffe.Server
	nodeID   string
	spiffeID string
}

func (h *hostWorkloadUpstream) FetchWorkloadSVID(
	ctx context.Context, publicKeyDER []byte, selectors, audience []string,
) (*workloadapi.SVIDSet, error) {
	if len(audience) > 0 {
		jwts, err := h.wl.FetchJWTSVIDsForNode(ctx, h.nodeID, audience, selectors)
		if err != nil {
			return nil, err
		}
		out := &workloadapi.SVIDSet{}
		for _, svid := range jwts {
			out.JWT = append(out.JWT, workloadapi.JWTSVID{
				SPIFFEID: svid.SPIFFEID, Token: svid.Token, ExpiresAt: svid.ExpiresAt,
			})
		}
		return out, nil
	}
	svids, err := h.wl.FetchX509SVIDsForNode(ctx, h.nodeID, publicKeyDER, selectors)
	if err != nil {
		return nil, err
	}
	out := &workloadapi.SVIDSet{}
	for _, svid := range svids {
		out.X509 = append(out.X509, workloadapi.X509SVID{
			SPIFFEID: svid.SPIFFEID, CertChainDER: svid.CertChain, ExpiresAt: svid.ExpiresAt,
		})
		if len(out.Bundle) == 0 {
			out.Bundle = svid.Bundle
		}
	}
	return out, nil
}

func TestAStockGoSpiffeClientFetchesFromTheHostSocket(t *testing.T) {
	const (
		nodeID   = "spiffe://served.test/agent/host-a"
		workload = "spiffe://served.test/payments"
	)

	// A real issuing CA and a real SPIFFE server, scoped to this node.
	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
			SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		},
	})
	if h.srv.protocols == nil || h.srv.protocols.spiffe == nil {
		t.Skip("this build serves no SPIFFE trust domain")
	}
	// A SPIFFE server whose entry is scoped to this node, issuing from the same
	// CA the control plane's own socket uses. Built here rather than reusing the
	// protocol's server because its default entry is deliberately unscoped —
	// which is itself the property asserted below.
	wl, err := spiffe.New(spiffe.Config{
		Issuer:      &spiffe.CAIssuer{CACertDER: h.srv.caCertDER, CASigner: h.srv.caSigner},
		TenantID:    servedTestTenant,
		TrustDomain: "served.test",
		Entries: []spiffe.RegistrationEntry{{
			SPIFFEID: workload, Selectors: []string{"unix"}, ParentID: nodeID,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("", "trstctl-b3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "w.sock")

	srv := workloadapi.New(&hostWorkloadUpstream{wl: wl, nodeID: nodeID, spiffeID: workload}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, socket) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	// The SAME stock client the control plane's socket has to satisfy.
	result := runServedGoSpiffeClient(t, "unix://"+socket)
	if result.ID == "" {
		t.Fatal("the stock go-spiffe client got no SPIFFE ID from the host socket")
	}
	if !result.HasPrivateKey {
		t.Fatal("the stock client received no private key; a workload cannot use an SVID it " +
			"has no key for, and the key is the thing this epic moved onto the host")
	}
	if result.CertDER == "" {
		t.Fatal("the stock client received no certificate chain")
	}
	leafDER, err := base64.StdEncoding.DecodeString(result.CertDER)
	if err != nil {
		t.Fatalf("the client returned non-base64 certificate DER: %v", err)
	}
	// The leaf must chain to the SAME CA the control plane's socket issues from.
	// A host-served SVID that did not would be a second trust domain wearing the
	// first one's name.
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("the host-issued SVID does not verify against the served CA: %v", err)
	}
	if result.BundleAuthorities == 0 {
		t.Error("the host socket returned no trust bundle, so the client cannot verify peers")
	}
	if result.ID != workload {
		t.Errorf("the stock client got %q, want the entry scoped to this node (%q)", result.ID, workload)
	}
}

// The same stock client, against a host whose node scopes NOTHING, is refused.
//
// The mirror of the test above, and the one that proves the scoping is load
// bearing rather than decorative: an identical client, an identical socket, an
// identical set of observed selectors — and no identity, because the entry
// names a different node.
func TestAStockGoSpiffeClientIsRefusedByAnUnscopedHost(t *testing.T) {
	const workload = "spiffe://served.test/payments"

	h := newServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
			SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		},
	})
	if h.srv.protocols == nil || h.srv.protocols.spiffe == nil {
		t.Skip("this build serves no SPIFFE trust domain")
	}
	wl, err := spiffe.New(spiffe.Config{
		Issuer:      &spiffe.CAIssuer{CACertDER: h.srv.caCertDER, CASigner: h.srv.caSigner},
		TenantID:    servedTestTenant,
		TrustDomain: "served.test",
		Entries: []spiffe.RegistrationEntry{{
			SPIFFEID: workload, Selectors: []string{"unix"},
			ParentID: "spiffe://served.test/agent/some-other-host",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("", "trstctl-b3n-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "w.sock")

	srv := workloadapi.New(&hostWorkloadUpstream{
		wl: wl, nodeID: "spiffe://served.test/agent/host-a", spiffeID: workload,
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, socket) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	if got := runServedGoSpiffeClientExpectingFailure(t, "unix://"+socket); got == "" {
		t.Fatal("a host obtained an SVID for a workload scoped to a DIFFERENT node; one " +
			"compromised agent would become a compromise of every service in the trust domain")
	}
}

// runServedGoSpiffeClientExpectingFailure runs the stock client and returns its
// error output, or "" if it unexpectedly succeeded.
func runServedGoSpiffeClientExpectingFailure(t *testing.T, endpoint string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the stock go-spiffe client")
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, goBin, "run", ".", endpoint) // #nosec G204 -- test executes a fixed local fixture (CWE-78)
	cmd.Dir = filepath.Join("testdata", "gospiffe-client")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	return string(out)
}
