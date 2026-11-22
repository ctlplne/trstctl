// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// maxSealedImportKey bounds a sealed private key on the wire and on disk.
const maxSealedImportKey = 64 << 10

const legacyImportRefusal = "authenticated CA key import v2 is required; upgrade the signer, control plane and CLI and prepare a new offer"

func (s *Server) keyImportNow() time.Time {
	if s.keyImportClock != nil {
		return s.keyImportClock()
	}
	return time.Now()
}

// PrepareKeyImport keeps the old wire method available to report the upgrade
// requirement explicitly before exposing any legacy offer.
func (s *Server) PrepareKeyImport(context.Context, *signerpb.PrepareKeyImportRequest) (*signerpb.PrepareKeyImportResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, legacyImportRefusal)
}

// ImportWrappedKey refuses legacy ciphertext before reading key custody.
func (s *Server) ImportWrappedKey(context.Context, *signerpb.ImportWrappedKeyRequest) (*signerpb.ImportWrappedKeyResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, legacyImportRefusal)
}

func (s *Server) lockKeyImport(policy crypto.KeyImportPolicy) (func(), error) {
	if err := policy.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if s.store == nil || s.authorizer == nil {
		return nil, status.Error(codes.FailedPrecondition, "CA key import requires a persistent signer and a configured dual-control authorizer")
	}
	unlock, err := s.store.lockHierarchyCustody(policy.Handle)
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.FailedPrecondition, "provision the CA import offer identity on the signer host first")
	}
	if err != nil {
		return nil, hierarchyCustodyStatus("lock CA import storage", err)
	}
	if err := s.store.hierarchyStanding(policy.Handle); err != nil {
		unlock()
		return nil, hierarchyCustodyStatus("check CA import handle", err)
	}
	return unlock, nil
}

// PrepareKeyImportV2 returns the exact signed offer retained for the approved
// policy. The same guard orders preparations and every writer of the handle.
func (s *Server) PrepareKeyImportV2(_ context.Context, req *signerpb.PrepareKeyImportV2Request) (*signerpb.PrepareKeyImportV2Response, error) {
	if req.GetVersion() != crypto.KeyImportOfferVersion {
		return nil, status.Error(codes.InvalidArgument, "CA key import requires protocol version 2")
	}
	policy := keyImportPolicyFromProto(req.GetPolicy())
	unlock, err := s.lockKeyImport(policy)
	if err != nil {
		return nil, err
	}
	defer unlock()

	exists, err := s.store.hierarchyEntryExists(policy.Handle + keyFileExt)
	if err != nil {
		return nil, hierarchyCustodyStatus("check CA import slot", err)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "key handle already exists")
	}
	identity, err := s.store.loadKeyImportIdentity()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "load the signer-host CA import identity: %v", err)
	}
	defer identity.Destroy()

	prepared, err := s.store.loadKeyImportPreparation(policy.Handle)
	if err != nil {
		return nil, hierarchyCustodyStatus("load CA import preparation", err)
	}
	stage := keyImportPreparationName(policy.Handle) + custodyStageExt
	if prepared.recipient != nil {
		defer prepared.recipient.Destroy()
		if _, err := verifyPreparedKeyImport(policy, prepared.offer, crypto.SHA256Hex(identity.Public().DER), s.keyImportNow()); err != nil {
			return nil, err
		}
		if err := s.store.retireCustodyNames(stage); err != nil {
			return nil, hierarchyCustodyStatus("sync CA import preparation", err)
		}
		if s.keyImportNow().Unix() >= prepared.offer.ExpiresAt {
			return nil, status.Error(codes.FailedPrecondition, "CA import offer expired; start a new approved ceremony")
		}
		return prepareKeyImportProto(prepared.offer), nil
	}

	if err := s.store.retireCustodyNames(stage); err != nil {
		return nil, hierarchyCustodyStatus("retire incomplete CA import preparation", err)
	}
	recipient, err := crypto.GenerateKeyImportKey()
	if err != nil {
		return nil, hierarchyCustodyStatus("generate CA import recipient", err)
	}
	defer recipient.Destroy()
	offer, err := crypto.SignKeyImportOffer(policy, recipient.Public(), s.keyImportNow(), identity)
	if err != nil {
		return nil, hierarchyCustodyStatus("sign CA import offer", err)
	}
	if err := s.store.saveKeyImportPreparation(keyImportPreparation{offer: offer, recipient: recipient}); err != nil {
		return nil, hierarchyCustodyStatus("persist CA import preparation", err)
	}
	if s.keyImportNow().Unix() >= offer.ExpiresAt {
		return nil, status.Error(codes.FailedPrecondition, "CA import offer expired; start a new approved ceremony")
	}
	return prepareKeyImportProto(offer), nil
}

func verifyPreparedKeyImport(policy crypto.KeyImportPolicy, offer crypto.AuthenticatedKeyImportOffer, pin string, now time.Time) ([]byte, error) {
	if !offer.Equal(policy) {
		return nil, status.Error(codes.InvalidArgument, "CA key import request differs from its prepared policy")
	}
	info, err := offer.Verify(pin, now)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "verify prepared CA import offer: %v", err)
	}
	return info, nil
}

// ImportWrappedKeyV2 opens ciphertext only with a live, signed preparation for
// the exact approved policy. Installed keys replay only their exact receipt.
func (s *Server) ImportWrappedKeyV2(_ context.Context, req *signerpb.ImportWrappedKeyV2Request) (*signerpb.ImportWrappedKeyV2Response, error) {
	if req.GetVersion() != crypto.KeyImportOfferVersion {
		return nil, status.Error(codes.InvalidArgument, "CA key import requires protocol version 2")
	}
	encryptedKey := req.GetSealedKey()
	if len(encryptedKey) == 0 || len(encryptedKey) > maxSealedImportKey {
		return nil, status.Error(codes.InvalidArgument, "CA key import requires bounded v2 ciphertext")
	}
	policy := keyImportPolicyFromProto(req.GetPolicy())
	unlock, err := s.lockKeyImport(policy)
	if err != nil {
		return nil, err
	}
	defer unlock()

	receipt := policy.Receipt(encryptedKey)
	held, err := s.store.readHierarchyKeyLocked(policy.Handle)
	if err != nil {
		return nil, hierarchyCustodyStatus("load installed CA import key", err)
	}
	if held != nil {
		defer held.signer.Destroy()
		if held.constraints.importReceipt != receipt || !bytes.Equal(held.signer.Public().DER, policy.ExpectedPublicKey) {
			return nil, status.Error(codes.AlreadyExists, "key handle already exists for a different request")
		}
		return s.finishKeyImportLocked(policy.Handle, held.signer)
	}

	pin, err := s.store.KeyImportIdentityFingerprint()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "load the signer-host CA import identity: %v", err)
	}
	prepared, err := s.store.loadKeyImportPreparation(policy.Handle)
	if err != nil {
		return nil, hierarchyCustodyStatus("load CA import preparation", err)
	}
	if prepared.recipient == nil {
		return nil, status.Error(codes.FailedPrecondition, "prepare a signed CA import offer first")
	}
	defer prepared.recipient.Destroy()
	info, err := verifyPreparedKeyImport(policy, prepared.offer, pin, s.keyImportNow())
	if err != nil {
		return nil, err
	}
	if s.keyImportNow().Unix() >= prepared.offer.ExpiresAt {
		return nil, status.Error(codes.FailedPrecondition, "CA import offer expired; start a new approved ceremony")
	}
	if s.beforeImportOpen != nil {
		s.beforeImportOpen()
	}
	key, err := openImportedCAKey(prepared.recipient, info, encryptedKey, policy.ExpectedPublicKey)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	if s.keyspec.ProtoFromAlgorithm(key.Algorithm()) == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "the sealed key's algorithm is not one this signer holds")
	}
	check := ceremonyCheck
	if s.checkImportedKey != nil {
		check = s.checkImportedKey
	}
	if err := check(key); err != nil {
		return nil, status.Error(codes.Internal, "key ceremony check failed")
	}
	constraints := keyConstraints{
		purposes:    map[signerpb.KeyPurpose]bool{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN: true},
		requireAuth: true, importReceipt: receipt,
		ownerTenantID: policy.TenantID, keyClass: KeyClassTenantCA,
	}
	if err := s.store.saveHierarchyKeyLocked(policy.Handle, key, constraints); err != nil {
		return nil, hierarchyCustodyStatus("persist CA import key", err)
	}
	return s.finishKeyImportLocked(policy.Handle, key)
}

func openImportedCAKey(recipient *crypto.KeyImportKey, info, ciphertext, expectedSPKI []byte) (*crypto.LockedSigner, error) {
	plaintext, err := recipient.Open(info, ciphertext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed key does not open under the prepared CA import offer")
	}
	defer secret.Wipe(plaintext)
	key, err := crypto.LockedKeyFromPKCS8(plaintext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed key is not a PKCS#8 signing key")
	}
	if err := crypto.RefuseWeakKey(key.Public()); err != nil {
		key.Destroy()
		return nil, status.Error(codes.InvalidArgument, "the sealed key is weak: "+err.Error())
	}
	if !bytes.Equal(key.Public().DER, expectedSPKI) {
		key.Destroy()
		return nil, status.Error(codes.InvalidArgument, "the sealed key does not match the expected public key")
	}
	return key, nil
}

func (s *Server) finishKeyImportLocked(handle string, key signerKey) (*signerpb.ImportWrappedKeyV2Response, error) {
	if err := s.store.retireCustodyNames(handle + keyFileExt + custodyStageExt); err != nil {
		return nil, hierarchyCustodyStatus("sync installed CA import key", err)
	}
	if err := s.store.retireKeyImportPreparation(handle); err != nil {
		return nil, hierarchyCustodyStatus("retire CA import preparation", err)
	}
	if err := s.store.hierarchyStanding(handle); err != nil {
		return nil, hierarchyCustodyStatus("check installed CA import key", err)
	}
	return &signerpb.ImportWrappedKeyV2Response{
		Handle: &signerpb.KeyHandle{Id: handle}, Algorithm: s.keyspec.ProtoFromAlgorithm(key.Algorithm()),
		PublicKey: key.Public().DER,
	}, nil
}
