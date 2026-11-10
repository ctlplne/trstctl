// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// B8-D1: an entry in protocols.spiffe.entries is delivered by the host agent
// it names, over the real agent channel: the enrolled agent asks for the
// workload it observed and receives an SVID for that entry alone, signed by the
// served CA for the key it sent up. Selectors the entry does not list are
// refused, another host's entry is never handed to this agent, the readiness
// check the console shows counts the entries, and the control plane's own
// socket never serves an agent's entry.
func TestServedHostAgentObtainsAConfiguredWorkloadSVIDB8D1(t *testing.T) {
	ctx := context.Background()
	const observed = "unix:uid:1000"
	h := newAgentChannelHarnessWithProtocols(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
		SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		Entries: []config.SPIFFEEntry{
			{SPIFFEID: "spiffe://served.test/b8d1-payments", Selectors: []string{observed}, Agent: "job-agent-1"},
			{SPIFFEID: "spiffe://served.test/b8d1-elsewhere", Selectors: []string{observed}, Agent: "another-host"},
		},
	}})
	if h.srv.protocols == nil || h.srv.protocols.spiffe == nil {
		t.Skip("this build serves no SPIFFE trust domain")
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	resp, err := h.client.FetchWorkloadSVID(ctx, &transport.FetchWorkloadSVIDRequest{
		PublicKeyDER: key.Public().DER, Selectors: []string{"unix", observed, "unix:gid:1000"},
	})
	if err != nil {
		t.Fatalf("the enrolled agent's workload SVID: %v", err)
	}
	if len(resp.X509SVIDs) != 1 || resp.X509SVIDs[0].SPIFFEID != "spiffe://served.test/b8d1-payments" {
		t.Fatalf("the agent received %+v, want the one entry scoped to it", resp.X509SVIDs)
	}
	chain := resp.X509SVIDs[0].CertChainDER
	if len(chain) == 0 {
		t.Fatal("the SVID carries no certificate")
	}
	if err := crypto.VerifyLeafSignedByCA(chain[0], caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("the SVID does not chain to the served CA: %v", err)
	}
	if pub, err := crypto.PublicKeyDERFromCert(chain[0]); err != nil || !slices.Equal(pub, key.Public().DER) {
		t.Fatalf("the SVID certifies another key (%v): the agent's key never left the host", err)
	}
	if len(resp.Bundle) == 0 {
		t.Error("the response carries no trust bundle")
	}

	_, err = h.client.FetchWorkloadSVID(ctx, &transport.FetchWorkloadSVIDRequest{
		PublicKeyDER: key.Public().DER, Selectors: []string{"unix", "unix:uid:1001"},
	})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "scoped to this node") {
		t.Fatalf("a workload the entry does not select = %v, want PermissionDenied naming the node scoping", err)
	}

	// The readiness check the console shows counts the default entry and the
	// two configured ones.
	if q := servedSPIFFEQualificationA85(t, h.servedHarness); q.RegistrationEntryCount != 3 {
		t.Fatalf("the readiness check counts %d registration entries, want 3", q.RegistrationEntryCount)
	}

	local, err := h.srv.protocols.spiffe.wl.FetchX509SVIDs(ctx, key.Public().DER, []string{"unix", observed})
	if err != nil {
		t.Fatalf("the control plane's own socket: %v", err)
	}
	for _, svid := range local {
		if strings.Contains(svid.SPIFFEID, "b8d1-") {
			t.Fatalf("the control plane's own socket served the agent's entry %s", svid.SPIFFEID)
		}
	}
}
