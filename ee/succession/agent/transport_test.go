// SPDX-License-Identifier: LicenseRef-trstctl-EE

package agent_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/agent"
	"trstctl.com/trstctl/ee/succession/agent/cosignpb"
	"trstctl.com/trstctl/internal/crypto"
)

// serveCoSign runs a CoSignServer for cs over a real Unix-domain-socket gRPC transport
// and returns a connected client conn, tearing both down at test end.
func serveCoSign(t *testing.T, cs *agent.CoSigner) *grpc.ClientConn {
	t.Helper()
	dir, err := os.MkdirTemp("", "pcas-cosign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	agent.NewCoSignServer(cs).Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return net.Dial("unix", sock) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestINT16_WorkloadHeldCoSignOverTransport drives the FIG. 5 workload-held-predecessor
// flow across a REAL gRPC process boundary: the workload agent holds the predecessor
// key and serves the co-sign RPC; the control plane forms the commitment and mints a
// succession by requesting the predecessor co-signature over the transport. The
// resulting record is a valid dual-signed succession record, and the agent's
// oracle-prevention refusals hold over the wire (PCAS-claim-19).
func TestINT16_WorkloadHeldCoSignOverTransport(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	predKey, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	const dep, id, tenant = "spiffe://d", "spiffe://d/app", "tenant-a"
	cs, err := agent.New(agent.Config{DeploymentScope: dep, IdentityID: id, TenantID: tenant, Signer: predKey})
	if err != nil {
		t.Fatal(err)
	}
	conn := serveCoSign(t, cs)
	remote := agent.NewRemoteCoSigner(conn)

	// CONTROL-PLANE side: form the predecessor-side fields (the successor is generated
	// here) and mint by co-signing over the transport.
	successor, err := be.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{
		DeploymentScope: dep, IdentityID: id, TenantID: tenant,
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: predKey.Algorithm(), PredecessorPub: cs.PublicDER(),
		PolicyRef: "sha256:policyref", HashAlg: succession.HashAlgSHA256,
		NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	rec, err := agent.MintWorkloadHeld(fields, remote, successor)
	if err != nil {
		t.Fatalf("MintWorkloadHeld over transport: %v", err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("workload-held record failed dual-attestation verify: %v", err)
	}
	// The predecessor attestation was produced by the agent's key, over the commitment
	// the control plane formed.
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyMessage(cs.PublicDER(), commitment, rec.PredecessorAtt); err != nil {
		t.Fatalf("predecessor attestation not by the agent key: %v", err)
	}

	// Oracle-prevention over the wire: a foreign identity is refused (ErrForeignBinding).
	foreign := fields
	foreign.IdentityID = "spiffe://d/someone-else"
	if _, err := remote.CoSign(agent.Request{Purpose: agent.Purpose, Fields: foreign}); !errors.Is(err, agent.ErrForeignBinding) {
		t.Fatalf("foreign-identity co-sign: got %v, want ErrForeignBinding", err)
	}
	// A request outside the co-sign purpose is refused (ErrForeignPurpose).
	if _, err := remote.CoSign(agent.Request{Purpose: "trstctl/some-other-usage", Fields: fields}); !errors.Is(err, agent.ErrForeignPurpose) {
		t.Fatalf("off-purpose co-sign: got %v, want ErrForeignPurpose", err)
	}
	// A foreign predecessor key is refused (ErrNotPredecessor).
	notPred := fields
	notPred.PredecessorPub = successor.Public().DER
	if _, err := remote.CoSign(agent.Request{Purpose: agent.Purpose, Fields: notPred}); !errors.Is(err, agent.ErrNotPredecessor) {
		t.Fatalf("foreign-predecessor co-sign: got %v, want ErrNotPredecessor", err)
	}

	// Opaque / malformed field bytes are refused at the wire boundary: the agent never
	// signs bytes it cannot decode into typed, inspectable fields.
	raw := cosignpb.NewCoSignerServiceClient(conn)
	if _, err := raw.CoSign(context.Background(), &cosignpb.CoSignRequest{Purpose: agent.Purpose, Fields: []byte("opaque-not-structured")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("opaque bytes: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestINT16_FieldsRoundTrip proves the co-sign wire encoding is lossless: the agent
// reconstructs exactly the commitment the caller intends, so a co-signature over the
// decoded fields verifies against the original commitment.
func TestINT16_FieldsRoundTrip(t *testing.T) {
	f := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/app", TenantID: "t",
		PredecessorEpoch: 3, Epoch: 4,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{1, 2, 3},
		SuccessorAlg: crypto.ECDSAP384, SuccessorPub: []byte{4, 5, 6},
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 10, NotAfter: 20,
		CommitmentVersion: 2, RecordType: succession.RecRevocation,
		AuthzDigest: []byte{7, 8}, AttestationEvidenceDigest: []byte{9}, AttestationType: "tpm2",
		DelegationPath: "delegation:v1:abc",
	}
	got, err := agent.UnmarshalFields(agent.MarshalFields(f))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := succession.Commit(f)
	have, _ := succession.Commit(got)
	if string(want) != string(have) {
		t.Fatal("round-tripped fields produce a different commitment")
	}
}
