// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/edgetest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
)

// edgeJournalDelegation records a software-key edge delegation for host,
// signed by a fresh parent CA, and returns its id, certificate and key.
func edgeJournalDelegation(t *testing.T, h *roleHarness, host string) (id string, certPEM, keyPEM []byte) {
	t.Helper()
	parentKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentKey.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentKey, crypto.HierarchyCAProfile{CommonName: "edge journal parent", MaxPathLen: 1, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrDER, err := crypto.GenerateEdgeCAKeyAndCSR(host + " edge CA")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentKey, csrDER, crypto.EdgeCARequest{
		CommonName: host + " edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := crypto.CertificateFactsFromDER(issued.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	id = uuid.NewString()
	if err := h.srv.orch.RecordEdgeDelegationIssued(context.Background(), h.tenant, projections.EdgeDelegationIssued{
		ID: id, SegmentID: uuid.NewString(), CAID: uuid.NewString(), Host: host,
		CommonName: host + " edge CA", Serial: facts.SerialHex,
		CertificatePEM:      string(issued.CertificatePEM) + string(parent.CertificatePEM),
		PermittedDNSDomains: []string{"edge.example.test"},
		KeyProvider:         "software", KeyStorage: "file", KeyExportable: true, CustodyAssurance: "host_attested_software_exception",
		NotBefore: facts.NotBefore, NotAfter: facts.NotAfter,
	}); err != nil {
		t.Fatalf("record delegation: %v", err)
	}
	return id, issued.CertificatePEM, keyPEM
}

// A219: a host agent sends its edge journal over the agent channel. Each
// certificate counts against the delegation of that host that issued it: the
// good leaf is reconciled into the inventory, a leaf outside the delegation's
// constraints is recorded as a violation, and a certificate no delegation of
// this host issued is rejected. A second upload counts them as already
// recorded. Before a delegation names the host, the agent reaches nothing.
func TestServedEdgeJournalArrivesOverTheAgentChannel(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "edge-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	// A delegation minted for ANOTHER host gives this agent nothing.
	_, otherCert, otherKey := edgeJournalDelegation(t, h, "some-other-host")
	otherLeaf, err := crypto.IssueEdgeLeaf(otherCert, otherKey, crypto.EdgeLeafRequest{CommonName: "o.edge.example.test", DNSNames: []string{"o.edge.example.test"}, TTL: time.Hour}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.client.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{CertificatesPEM: []string{string(otherLeaf.CertificatePEM)}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a journal before any delegation names this host = %v; want PermissionDenied", err)
	}

	id, certPEM, keyPEM := edgeJournalDelegation(t, h, h.agent)
	good, err := crypto.IssueEdgeLeaf(certPEM, keyPEM, crypto.EdgeLeafRequest{CommonName: "svc.edge.example.test", DNSNames: []string{"svc.edge.example.test"}, TTL: time.Hour}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := edgetest.RogueLeaf(certPEM, keyPEM, "evil.other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	journal := []string{string(good.CertificatePEM), rogue, string(otherLeaf.CertificatePEM)}
	resp, err := h.client.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{CertificatesPEM: journal})
	if err != nil {
		t.Fatalf("report edge journal: %v", err)
	}
	if resp.Reconciled != 1 || resp.Violations != 1 || resp.Rejected != 1 || len(resp.Delegations) != 1 || resp.Delegations[0] != id {
		t.Fatalf("journal = %+v; want the good leaf reconciled, the rogue one a violation, the other host's rejected", resp)
	}
	goodFacts, err := crypto.CertificateFactsFromDER(good.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, crypto.SHA256Hex(good.CertificateDER)); err != nil {
		t.Fatalf("the reconciled leaf %s is not in the inventory: %v", goodFacts.SerialHex, err)
	}
	if !h.hasEvent(t, projections.EventEdgeIssuanceReconciled) {
		t.Fatal("no reconcile event recorded")
	}

	again, err := h.client.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{CertificatesPEM: journal})
	if err != nil || again.Already != 2 || again.Reconciled != 0 || again.Rejected != 1 {
		t.Fatalf("second upload = %+v, %v; want both recorded leaves already known", again, err)
	}
	if _, err := h.client.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty journal = %v; want InvalidArgument", err)
	}
}

// A network-role agent is not a host and cannot report an edge journal.
func TestServedEdgeJournalComesOnlyFromHostAgents(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "edge-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	_, err := h.client.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{CertificatesPEM: []string{"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a network agent's journal = %v; want PermissionDenied", err)
	}
}
