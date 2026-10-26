// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Wrapped key import (A128). An operator's existing private key reaches the
// signer sealed to a one-time import key the signer holds for one operation
// (the control plane's ceremony). The plaintext exists on the operator's
// machine and inside this process for one call; the control plane relays only
// sealed bytes. The import key is never a signing key, and the import that
// uses it destroys it.

const importKeyFileExt = ".import"

// maxSealedImportKey bounds a sealed private key on the wire and on disk.
const maxSealedImportKey = 64 << 10

var errImportKeyExists = errors.New("signing: an import key already exists for this operation")

func importKeyStem(operationID string) string {
	return sanitizeHandle("key-import-" + operationID)
}

func importKeyAAD(stem string) []byte {
	return []byte("trstctl.key-import\x00" + stem)
}

// SaveImportKey seals an import key's seed at rest and links it into place
// exclusively: the first import key saved for an operation is the one every
// signer process sharing the keystore reads.
func (ks *KeyStore) SaveImportKey(operationID string, seed []byte) error {
	stem := importKeyStem(operationID)
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, stem+importKeyFileExt))
	if err != nil {
		return err
	}
	sealed, err := seal.Seal(ks.wrapper, seed, importKeyAAD(stem))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(ks.dir, ".importing-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errImportKeyExists
		}
		return err
	}
	return syncDirectory(ks.dir)
}

// LoadImportKey opens an operation's sealed import key seed. The caller wipes
// the seed.
func (ks *KeyStore) LoadImportKey(operationID string) ([]byte, bool, error) {
	stem := importKeyStem(operationID)
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, stem+importKeyFileExt))
	if err != nil {
		return nil, false, err
	}
	file, err := os.Open(path) // #nosec G304 -- path passed the explicit signer-keystore confinement check above (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxSealedImportKey+1))
	if err != nil {
		return nil, true, err
	}
	if len(raw) > maxSealedImportKey {
		return nil, true, fmt.Errorf("signing: sealed import key for %q is oversized", operationID)
	}
	seed, err := seal.Open(ks.wrapper, raw, importKeyAAD(stem))
	return seed, true, err
}

// RemoveImportKey deletes an operation's used import key.
func (ks *KeyStore) RemoveImportKey(operationID string) error {
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, importKeyStem(operationID)+importKeyFileExt))
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 -- path passed the explicit signer-keystore confinement check above (CWE-22)
		return err
	}
	return syncDirectory(ks.dir)
}

// loadImportKey returns the operation's import key and the release to call
// when done with it.
func (s *Server) loadImportKey(operationID string) (*crypto.KeyImportKey, func(), bool, error) {
	if s.store == nil {
		key := s.importKeys[operationID]
		return key, func() {}, key != nil, nil
	}
	seed, found, err := s.store.LoadImportKey(operationID)
	if err != nil || !found {
		return nil, nil, found, err
	}
	defer secret.Wipe(seed)
	key, err := crypto.NewKeyImportKey(seed)
	if err != nil {
		return nil, nil, true, err
	}
	return key, key.Destroy, true, nil
}

// dropImportKey destroys an operation's used import key.
func (s *Server) dropImportKey(operationID string) error {
	if s.store == nil {
		if key := s.importKeys[operationID]; key != nil {
			key.Destroy()
		}
		delete(s.importKeys, operationID)
		return nil
	}
	return s.store.RemoveImportKey(operationID)
}

// PrepareKeyImport returns the operation's one-time import key, creating it on
// the first call.
func (s *Server) PrepareKeyImport(_ context.Context, req *signerpb.PrepareKeyImportRequest) (*signerpb.PrepareKeyImportResponse, error) {
	operationID := req.GetOperationId()
	if !validOperationID(operationID) {
		return nil, status.Error(codes.InvalidArgument, "key import needs an operation id")
	}
	s.importMu.Lock()
	defer s.importMu.Unlock()
	key, release, found, err := s.loadImportKey(operationID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read import key: %v", err)
	}
	if found {
		defer release()
		return &signerpb.PrepareKeyImportResponse{Suite: crypto.KeyImportSuite, PublicKey: key.Public()}, nil
	}
	key, err = crypto.GenerateKeyImportKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate import key: %v", err)
	}
	if s.store == nil {
		s.importKeys[operationID] = key
		return &signerpb.PrepareKeyImportResponse{Suite: crypto.KeyImportSuite, PublicKey: key.Public()}, nil
	}
	defer key.Destroy()
	seed, err := key.Seed()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read import key: %v", err)
	}
	defer secret.Wipe(seed)
	switch err := s.store.SaveImportKey(operationID, seed); {
	case errors.Is(err, errImportKeyExists):
		// Another signer process sharing the keystore saved one first: offer it.
		winner, release, _, err := s.loadImportKey(operationID)
		if err != nil || winner == nil {
			return nil, status.Errorf(codes.Internal, "read import key: %v", err)
		}
		defer release()
		return &signerpb.PrepareKeyImportResponse{Suite: crypto.KeyImportSuite, PublicKey: winner.Public()}, nil
	case err != nil:
		return nil, status.Errorf(codes.Internal, "persist import key: %v", err)
	}
	return &signerpb.PrepareKeyImportResponse{Suite: crypto.KeyImportSuite, PublicKey: key.Public()}, nil
}

// ImportWrappedKey opens a sealed private key with the operation's import key
// and keeps it under the requested handle.
func (s *Server) ImportWrappedKey(_ context.Context, req *signerpb.ImportWrappedKeyRequest) (*signerpb.ImportWrappedKeyResponse, error) {
	operationID, handle := req.GetOperationId(), req.GetRequestedId()
	if !validOperationID(operationID) || req.GetTenantId() == "" || handle == "" ||
		len(req.GetSealedKey()) == 0 || len(req.GetSealedKey()) > maxSealedImportKey || len(req.GetExpectedPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key import needs an operation, tenant, handle, sealed key and expected public key")
	}
	constraints, err := constraintsFromGenerate(&signerpb.GenerateKeyRequest{
		AllowedPurposes: req.GetAllowedPurposes(), AllowedHashes: req.GetAllowedHashes(),
	})
	if err != nil {
		return nil, err
	}
	if req.GetRequireAuthorization() {
		if s.authorizer == nil {
			return nil, status.Error(codes.FailedPrecondition,
				"dual-control key requested but this signer has no authorizer configured")
		}
		constraints.requireAuth = true
	}
	s.importMu.Lock()
	defer s.importMu.Unlock()
	// A retry after a lost response finds the key already held under its handle.
	if held, err := s.lookup(&signerpb.KeyHandle{Id: handle}); err == nil {
		if !bytes.Equal(held.signer.Public().DER, req.GetExpectedPublicKey()) {
			return nil, status.Error(codes.AlreadyExists, "key handle already exists")
		}
		return importResponse(s, handle, held.signer), nil
	} else if status.Code(err) != codes.NotFound {
		return nil, err
	}
	key, release, found, err := s.loadImportKey(operationID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read import key: %v", err)
	}
	if !found {
		return nil, status.Error(codes.FailedPrecondition, "no import key for this operation; prepare one first")
	}
	defer release()
	plaintext, err := key.Open(crypto.KeyImportInfo(req.GetTenantId(), operationID, req.GetExpectedPublicKey()), req.GetSealedKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed key does not open under this operation's import key and binding")
	}
	defer secret.Wipe(plaintext)
	ls, err := crypto.LockedKeyFromPKCS8(plaintext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed key is not a PKCS#8 signing key")
	}
	refuse := func(code codes.Code, msg string) (*signerpb.ImportWrappedKeyResponse, error) {
		ls.Destroy()
		return nil, status.Error(code, msg)
	}
	if s.keyspec.ProtoFromAlgorithm(ls.Algorithm()) == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return refuse(codes.InvalidArgument, "the sealed key's algorithm is not one this signer holds")
	}
	if err := crypto.RefuseWeakKey(ls.Public()); err != nil {
		return refuse(codes.InvalidArgument, "the sealed key is weak: "+err.Error())
	}
	if !bytes.Equal(ls.Public().DER, req.GetExpectedPublicKey()) {
		return refuse(codes.InvalidArgument, "the sealed key does not match the expected public key")
	}
	if err := ceremonyCheck(ls); err != nil {
		return refuse(codes.Internal, "key ceremony check failed")
	}
	if err := s.mintHeldKey(handle, &heldKey{signer: ls, constraints: constraints}); err != nil {
		ls.Destroy()
		switch {
		case errors.Is(err, errKeyHandleExists):
			return nil, status.Error(codes.AlreadyExists, "key handle already exists")
		case errors.Is(err, ErrDestroyedKeyHandle):
			return nil, status.Error(codes.FailedPrecondition, ErrDestroyedKeyHandle.Error())
		default:
			return nil, status.Errorf(codes.Internal, "persist key: %v", err)
		}
	}
	if err := s.dropImportKey(operationID); err != nil {
		return nil, status.Errorf(codes.Internal, "destroy the used import key: %v", err)
	}
	return importResponse(s, handle, ls), nil
}

func importResponse(s *Server, handle string, key signerKey) *signerpb.ImportWrappedKeyResponse {
	return &signerpb.ImportWrappedKeyResponse{
		Handle: &signerpb.KeyHandle{Id: handle}, Algorithm: s.keyspec.ProtoFromAlgorithm(key.Algorithm()),
		PublicKey: key.Public().DER,
	}
}
