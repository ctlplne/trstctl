// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type testRootAnchor struct {
	publicDER []byte
	authRef   string
}

type testRootAnchorStore struct {
	anchors      map[string]testRootAnchor
	provisionErr error
	readErr      error
	badReadback  bool
}

func (s *testRootAnchorStore) ProvisionAgentRootAnchor(_ context.Context, tenant, keyID string, publicDER []byte, authRef string) error {
	if s.provisionErr != nil {
		return s.provisionErr
	}
	if s.anchors == nil {
		s.anchors = make(map[string]testRootAnchor)
	}
	key := tenant + "/" + keyID
	if prior, ok := s.anchors[key]; ok && (!bytes.Equal(prior.publicDER, publicDER) || prior.authRef != authRef) {
		return ErrAgentRootConflict
	}
	s.anchors[key] = testRootAnchor{publicDER: bytes.Clone(publicDER), authRef: authRef}
	return nil
}

func (s *testRootAnchorStore) ReadAgentRootAnchor(_ context.Context, tenant, keyID string) ([]byte, string, error) {
	if s.readErr != nil {
		return nil, "", s.readErr
	}
	value, ok := s.anchors[tenant+"/"+keyID]
	if !ok {
		return nil, "", os.ErrNotExist
	}
	if s.badReadback {
		return value.publicDER, "different-authorization", nil
	}
	return bytes.Clone(value.publicDER), value.authRef, nil
}

type testReachabilityStore struct {
	keys         map[string][]byte
	provisionErr error
	readErr      error
	badReadback  bool
}

func (s *testReachabilityStore) PutVerdictSigner(_ context.Context, keyID string, publicDER []byte) error {
	if s.provisionErr != nil {
		return s.provisionErr
	}
	if s.keys == nil {
		s.keys = make(map[string][]byte)
	}
	if prior, ok := s.keys[keyID]; ok && !bytes.Equal(prior, publicDER) {
		return ErrAgentReachabilityConflict
	}
	s.keys[keyID] = bytes.Clone(publicDER)
	return nil
}

func (s *testReachabilityStore) ReadVerdictSigner(_ context.Context, keyID string) ([]byte, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	value, ok := s.keys[keyID]
	if !ok {
		return nil, os.ErrNotExist
	}
	if s.badReadback {
		return []byte("different-key"), nil
	}
	return bytes.Clone(value), nil
}

func testTrustPublicKey(t *testing.T) []byte {
	t.Helper()
	publicDER, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate public trust key: %v", err)
	}
	return publicDER
}

func requireSignerCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("gRPC code = %v, want %v: %v", got, want, err)
	}
}

func TestAgentRootAnchorSignerTrustFloor(t *testing.T) {
	ctx := context.Background()
	publicDER := testTrustPublicKey(t)
	otherDER := testTrustPublicKey(t)
	req := &signerpb.ProvisionAgentRootAnchorRequest{
		TenantId: "tenant-a", KeyId: "root-a", PublicDer: publicDER, AuthRef: "event:root-a",
	}
	server := &Server{}
	_, err := server.ProvisionAgentRootAnchor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	_, err = server.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: "tenant-a", KeyId: "root-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)

	store := &testRootAnchorStore{}
	WithAgentRootAnchorStore(store)(server)
	for _, invalid := range []*signerpb.ProvisionAgentRootAnchorRequest{
		nil,
		{TenantId: "", KeyId: "root-a", PublicDer: publicDER, AuthRef: "event:root-a"},
		{TenantId: "tenant-a", KeyId: "root-a", PublicDer: publicDER, AuthRef: " event:root-a"},
		{TenantId: "tenant-a", KeyId: "root-a", PublicDer: []byte("invalid"), AuthRef: "event:root-a"},
	} {
		_, err = server.ProvisionAgentRootAnchor(ctx, invalid)
		requireSignerCode(t, err, codes.InvalidArgument)
	}
	_, err = server.GetAgentRootAnchor(ctx, nil)
	requireSignerCode(t, err, codes.InvalidArgument)
	_, err = server.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: "tenant-a", KeyId: "missing"})
	requireSignerCode(t, err, codes.NotFound)

	for attempt := 0; attempt < 2; attempt++ {
		receipt, err := server.ProvisionAgentRootAnchor(ctx, req)
		if err != nil || !bytes.Equal(receipt.GetPublicDer(), publicDER) || receipt.GetAuthRef() != req.AuthRef {
			t.Fatalf("provision attempt %d lost exact public binding: receipt=%v err=%v", attempt, receipt, err)
		}
	}
	readback, err := server.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: "tenant-a", KeyId: "root-a"})
	if err != nil || !bytes.Equal(readback.GetPublicDer(), publicDER) || readback.GetAuthRef() != req.AuthRef {
		t.Fatalf("root anchor readback differs: receipt=%v err=%v", readback, err)
	}
	_, err = server.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: "tenant-b", KeyId: "root-a"})
	requireSignerCode(t, err, codes.NotFound)

	changed := &signerpb.ProvisionAgentRootAnchorRequest{
		TenantId: req.TenantId, KeyId: req.KeyId, PublicDer: otherDER, AuthRef: req.AuthRef,
	}
	_, err = server.ProvisionAgentRootAnchor(ctx, changed)
	requireSignerCode(t, err, codes.AlreadyExists)
	store.badReadback = true
	_, err = server.ProvisionAgentRootAnchor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.badReadback = false
	store.provisionErr = errors.New("retained floor unavailable")
	_, err = server.ProvisionAgentRootAnchor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.provisionErr = nil
	store.readErr = errors.New("read failure")
	_, err = server.GetAgentRootAnchor(ctx, &signerpb.GetAgentRootAnchorRequest{TenantId: "tenant-a", KeyId: "root-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)
}

func TestAgentReachabilitySignerTrustFloor(t *testing.T) {
	ctx := context.Background()
	publicDER := testTrustPublicKey(t)
	otherDER := testTrustPublicKey(t)
	req := &signerpb.ProvisionAgentReachabilityKeyRequest{KeyId: "verdict-a", PublicDer: publicDER}
	server := &Server{}
	_, err := server.ProvisionAgentReachabilityKey(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	_, err = server.GetAgentReachabilityKey(ctx, &signerpb.GetAgentReachabilityKeyRequest{KeyId: "verdict-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)

	store := &testReachabilityStore{}
	WithAgentReachabilityKeyStore(store)(server)
	for _, invalid := range []*signerpb.ProvisionAgentReachabilityKeyRequest{
		nil,
		{KeyId: " verdict-a", PublicDer: publicDER},
		{KeyId: "verdict-a", PublicDer: []byte("invalid")},
	} {
		_, err = server.ProvisionAgentReachabilityKey(ctx, invalid)
		requireSignerCode(t, err, codes.InvalidArgument)
	}
	_, err = server.GetAgentReachabilityKey(ctx, nil)
	requireSignerCode(t, err, codes.InvalidArgument)
	_, err = server.GetAgentReachabilityKey(ctx, &signerpb.GetAgentReachabilityKeyRequest{KeyId: "missing"})
	requireSignerCode(t, err, codes.NotFound)

	for attempt := 0; attempt < 2; attempt++ {
		receipt, err := server.ProvisionAgentReachabilityKey(ctx, req)
		if err != nil || !bytes.Equal(receipt.GetPublicDer(), publicDER) {
			t.Fatalf("provision attempt %d lost exact public key: receipt=%v err=%v", attempt, receipt, err)
		}
	}
	readback, err := server.GetAgentReachabilityKey(ctx, &signerpb.GetAgentReachabilityKeyRequest{KeyId: "verdict-a"})
	if err != nil || !bytes.Equal(readback.GetPublicDer(), publicDER) {
		t.Fatalf("reachability key readback differs: receipt=%v err=%v", readback, err)
	}
	changed := &signerpb.ProvisionAgentReachabilityKeyRequest{KeyId: req.KeyId, PublicDer: otherDER}
	_, err = server.ProvisionAgentReachabilityKey(ctx, changed)
	requireSignerCode(t, err, codes.AlreadyExists)
	store.badReadback = true
	_, err = server.ProvisionAgentReachabilityKey(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.badReadback = false
	store.provisionErr = errors.New("retained floor unavailable")
	_, err = server.ProvisionAgentReachabilityKey(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.provisionErr = nil
	store.readErr = errors.New("read failure")
	_, err = server.GetAgentReachabilityKey(ctx, &signerpb.GetAgentReachabilityKeyRequest{KeyId: "verdict-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)
}

type testAttestor struct {
	publicDER []byte
	method    string
}

type testAttestorStore struct {
	attestors    map[string]testAttestor
	provisionErr error
	readErr      error
	badReadback  bool
}

func (s *testAttestorStore) ProvisionAgentAttestor(_ context.Context, tenant, keyID string, publicDER []byte, method string) error {
	if s.provisionErr != nil {
		return s.provisionErr
	}
	if s.attestors == nil {
		s.attestors = make(map[string]testAttestor)
	}
	key := tenant + "/" + keyID
	if prior, ok := s.attestors[key]; ok && (!bytes.Equal(prior.publicDER, publicDER) || prior.method != method) {
		return ErrAgentAttestorConflict
	}
	s.attestors[key] = testAttestor{publicDER: bytes.Clone(publicDER), method: method}
	return nil
}

func (s *testAttestorStore) ReadAgentAttestor(_ context.Context, tenant, keyID string) ([]byte, string, error) {
	if s.readErr != nil {
		return nil, "", s.readErr
	}
	value, ok := s.attestors[tenant+"/"+keyID]
	if !ok {
		return nil, "", os.ErrNotExist
	}
	if s.badReadback {
		return value.publicDER, "hsm", nil
	}
	return bytes.Clone(value.publicDER), value.method, nil
}

// A150: the signer's attestor RPCs validate the binding, keep the first writer,
// read back what they stored, and answer each failure with a distinct code.
func TestAgentAttestorSignerTrustFloor(t *testing.T) {
	ctx := context.Background()
	publicDER := testTrustPublicKey(t)
	otherDER := testTrustPublicKey(t)
	req := &signerpb.ProvisionAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: publicDER, Method: "tpm"}
	server := &Server{}
	_, err := server.ProvisionAgentAttestor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	_, err = server.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)

	store := &testAttestorStore{}
	WithAgentAttestorStore(store)(server)
	for _, invalid := range []*signerpb.ProvisionAgentAttestorRequest{
		nil,
		{TenantId: "", KeyId: "attestor-a", PublicDer: publicDER, Method: "tpm"},
		{TenantId: "tenant-a", KeyId: " attestor-a", PublicDer: publicDER, Method: "tpm"},
		{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: publicDER, Method: ""},
		{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: publicDER, Method: "tpm "},
		{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: []byte("invalid"), Method: "tpm"},
	} {
		_, err = server.ProvisionAgentAttestor(ctx, invalid)
		requireSignerCode(t, err, codes.InvalidArgument)
	}
	_, err = server.GetAgentAttestor(ctx, nil)
	requireSignerCode(t, err, codes.InvalidArgument)
	_, err = server.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: "tenant-a", KeyId: "missing"})
	requireSignerCode(t, err, codes.NotFound)

	for attempt := 0; attempt < 2; attempt++ {
		receipt, err := server.ProvisionAgentAttestor(ctx, req)
		if err != nil || !bytes.Equal(receipt.GetPublicDer(), publicDER) || receipt.GetMethod() != "tpm" {
			t.Fatalf("provision attempt %d lost the exact binding: receipt=%v err=%v", attempt, receipt, err)
		}
	}
	readback, err := server.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a"})
	if err != nil || !bytes.Equal(readback.GetPublicDer(), publicDER) || readback.GetMethod() != "tpm" {
		t.Fatalf("attestor readback differs: receipt=%v err=%v", readback, err)
	}
	_, err = server.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: "tenant-b", KeyId: "attestor-a"})
	requireSignerCode(t, err, codes.NotFound)

	_, err = server.ProvisionAgentAttestor(ctx, &signerpb.ProvisionAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: otherDER, Method: "tpm"})
	requireSignerCode(t, err, codes.AlreadyExists)
	_, err = server.ProvisionAgentAttestor(ctx, &signerpb.ProvisionAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a", PublicDer: publicDER, Method: "hsm"})
	requireSignerCode(t, err, codes.AlreadyExists)
	store.provisionErr = ErrAgentAttestorInvalid
	_, err = server.ProvisionAgentAttestor(ctx, req)
	requireSignerCode(t, err, codes.InvalidArgument)
	store.provisionErr = errors.New("retained floor unavailable")
	_, err = server.ProvisionAgentAttestor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.provisionErr = nil
	store.badReadback = true
	_, err = server.ProvisionAgentAttestor(ctx, req)
	requireSignerCode(t, err, codes.FailedPrecondition)
	store.badReadback = false
	store.readErr = errors.New("read failure")
	_, err = server.GetAgentAttestor(ctx, &signerpb.GetAgentAttestorRequest{TenantId: "tenant-a", KeyId: "attestor-a"})
	requireSignerCode(t, err, codes.FailedPrecondition)
}
