// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Administrative key revocation (A128). A revoked key stays in custody, so its
// public half remains readable and a gated destruction can still retire it, but
// the signer refuses to sign with it from the next request on. The revocation
// mark is the only state it adds: the sealed key material is untouched.

// ErrRevokedKeyHandle is the refusal for any signature with a revoked key.
var ErrRevokedKeyHandle = errors.New("signing: key handle is revoked and signs nothing")

const revokedKeyFileExt = ".revoked"

// maxRevocationRecord bounds a revocation mark read back from the keystore.
const maxRevocationRecord = 4 << 10

// KeyRevocation is the durable, non-secret record of one key revocation. The
// first revocation of a handle is the one every later read returns.
type KeyRevocation struct {
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason"`
	RevokedAt   int64  `json:"revoked_at_unix"`
}

type keyRevocationFile struct {
	Version int `json:"version"`
	KeyRevocation
}

// MarkRevoked records rec for handle unless the handle already carries a
// revocation, and returns the record that holds. The mark is written to a
// private temporary file and linked into place, so it appears whole or not at
// all and a second writer never replaces the first. The mark sits beside the
// sealed key, so every signer process sharing the keystore sees it.
func (ks *KeyStore) MarkRevoked(handle string, rec KeyRevocation) (KeyRevocation, error) {
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return KeyRevocation{}, err
	}
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, sanitizeHandle(handle)+revokedKeyFileExt))
	if err != nil {
		return KeyRevocation{}, err
	}
	if existing, found, err := ks.Revocation(handle); err != nil || found {
		return existing, err
	}
	body, err := json.Marshal(keyRevocationFile{Version: 1, KeyRevocation: rec})
	if err != nil {
		return KeyRevocation{}, err
	}
	tmp, err := os.CreateTemp(ks.dir, ".revoking-*")
	if err != nil {
		return KeyRevocation{}, err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return KeyRevocation{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return KeyRevocation{}, err
	}
	if err := tmp.Close(); err != nil {
		return KeyRevocation{}, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return KeyRevocation{}, err
		}
		existing, found, readErr := ks.Revocation(handle)
		if readErr == nil && !found {
			readErr = errors.New("signing: revocation mark vanished while another writer held it")
		}
		return existing, readErr
	}
	return rec, syncDirectory(ks.dir)
}

// Revocation reads handle's revocation mark. A mark that exists but does not
// decode still revokes the key: IsRevoked decides on the file alone.
func (ks *KeyStore) Revocation(handle string) (KeyRevocation, bool, error) {
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, sanitizeHandle(handle)+revokedKeyFileExt))
	if err != nil {
		return KeyRevocation{}, false, err
	}
	file, err := os.Open(path) // #nosec G304 -- path passed the explicit signer-keystore confinement check above (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return KeyRevocation{}, false, nil
	}
	if err != nil {
		return KeyRevocation{}, false, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxRevocationRecord+1))
	if err != nil {
		return KeyRevocation{}, true, err
	}
	var record keyRevocationFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > maxRevocationRecord || decoder.Decode(&record) != nil || record.Version != 1 {
		return KeyRevocation{}, true, fmt.Errorf("signing: revocation mark for %q is unreadable", handle)
	}
	return record.KeyRevocation, true, nil
}

// IsRevoked reports whether handle carries a revocation mark.
func (ks *KeyStore) IsRevoked(handle string) (bool, error) {
	path, err := confinedKeystorePath(ks.dir, filepath.Join(ks.dir, sanitizeHandle(handle)+revokedKeyFileExt))
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path) // #nosec G703 -- path passed the explicit signer-keystore confinement check above (CWE-22)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// RevokeKey revokes a key handle. The first revocation holds: a redelivered or
// repeated request reads back the original operation, reason and time.
func (s *Server) RevokeKey(_ context.Context, req *signerpb.RevokeKeyRequest) (*signerpb.RevokeKeyResponse, error) {
	if req.GetHandle() == nil || req.GetHandle().GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	if !validOperationID(req.GetOperationId()) || !validRevocationReason(req.GetReason()) {
		return nil, status.Error(codes.InvalidArgument, "revocation needs an operation id and a lower-case reason code")
	}
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	handle := req.GetHandle().GetId()
	record := KeyRevocation{OperationID: req.GetOperationId(), Reason: req.GetReason(), RevokedAt: time.Now().UTC().Unix()}
	if s.store != nil {
		if record, err = s.store.MarkRevoked(handle, record); err != nil {
			return nil, status.Errorf(codes.Internal, "persist key revocation: %v", err)
		}
	} else {
		s.mu.Lock()
		if existing, ok := s.revocations[handle]; ok {
			record = existing
		} else {
			s.revocations[handle] = record
		}
		s.mu.Unlock()
	}
	return &signerpb.RevokeKeyResponse{
		PublicKey: held.signer.Public().DER, OperationId: record.OperationID,
		Reason: record.Reason, RevokedAtUnix: record.RevokedAt,
	}, nil
}

// revoked reports whether handle carries a revocation.
func (s *Server) revoked(handle string) (bool, error) {
	if s.store != nil {
		return s.store.IsRevoked(handle)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revocations[handle]
	return ok, nil
}

// lookupSigning is lookup for an operation that signs with the key: a revoked
// key is refused here, before any constraint or authorization check.
func (s *Server) lookupSigning(h *signerpb.KeyHandle) (*heldKey, error) {
	held, err := s.lookup(h)
	if err != nil {
		return nil, err
	}
	revoked, err := s.revoked(h.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read key revocation: %v", err)
	}
	if revoked {
		return nil, status.Error(codes.FailedPrecondition, ErrRevokedKeyHandle.Error())
	}
	return held, nil
}

// validOperationID accepts a printable operation identifier of at most 128
// bytes: a ceremony ID, or any caller operation that names a request.
func validOperationID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validRevocationReason(reason string) bool {
	if reason == "" || len(reason) > 64 {
		return false
	}
	for _, r := range reason {
		if (r < 'a' || r > 'z') && r != '_' {
			return false
		}
	}
	return true
}
