// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const gatedDestroyJournalVersion = 1

type gatedDestroyJournalRecord struct {
	Version     int                  `json:"version"`
	OperationID string               `json:"operation_id"`
	RequestHash string               `json:"request_hash"`
	State       string               `json:"state"`
	Decision    GatedDestroyDecision `json:"decision"`
}

// Every field is public evidence. The fixed struct makes the request hash
// independent of Go field layout and binds newly added fields deliberately.
type gatedDestroyJournalIntent struct {
	TenantID             string `json:"tenant_id"`
	Handle               string `json:"handle"`
	SubjectRef           string `json:"subject_ref"`
	AssertedFinalEpoch   uint64 `json:"asserted_final_epoch"`
	LedgerPosition       uint64 `json:"ledger_position"`
	RequiredSet          []byte `json:"required_set"`
	RequiredSetDigest    []byte `json:"required_set_digest"`
	SatisfiedSet         []byte `json:"satisfied_set,omitempty"`
	SatisfactionEvidence []byte `json:"satisfaction_evidence"`
	Authorization        []byte `json:"authorization,omitempty"`
	Approvals            []byte `json:"approvals,omitempty"`
	AuditChainHead       []byte `json:"audit_chain_head"`
	Context              []byte `json:"context"`
}

func gatedDestroyRequestHash(req GatedDestroyRequest) (string, error) {
	raw, err := json.Marshal(gatedDestroyJournalIntent{
		TenantID: req.TenantID, Handle: req.Handle, SubjectRef: req.SubjectRef,
		AssertedFinalEpoch: req.AssertedFinalEpoch, LedgerPosition: req.LedgerPosition,
		RequiredSet: req.RequiredSet, RequiredSetDigest: req.RequiredSetDigest,
		SatisfiedSet: req.SatisfiedSet, SatisfactionEvidence: req.SatisfactionEvidence,
		Authorization: req.Authorization, Approvals: req.Approvals,
		AuditChainHead: req.AuditChainHead, Context: req.Context,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(raw), nil
}

func gatedDestroyOperationID(req GatedDestroyRequest) (string, error) {
	digest, err := gatedDestroyRequestHash(req)
	if err != nil {
		return "", err
	}
	return "gated-destroy-" + digest, nil
}

func (s *Server) loadGatedDestroyOperation(operationID string, req GatedDestroyRequest) (GatedDestroyDecision, string, bool, error) {
	requestHash, err := gatedDestroyRequestHash(req)
	if err != nil {
		return GatedDestroyDecision{}, "", false, err
	}
	var existing gatedDestroyJournalRecord
	found := false
	if s.store != nil {
		existing, err = s.store.readGatedDestroyOperation(operationID)
		found = err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return GatedDestroyDecision{}, "", false, err
		}
	} else if s.gatedDestroyOps != nil {
		existing, found = s.gatedDestroyOps[operationID]
	}
	if !found {
		return GatedDestroyDecision{}, "", false, nil
	}
	if existing.RequestHash != requestHash || existing.OperationID != operationID {
		return GatedDestroyDecision{}, "", false, errors.New("signing: gated destruction journal binding conflict")
	}
	if existing.State != "executing" && existing.State != "completed" {
		return GatedDestroyDecision{}, "", false, fmt.Errorf("signing: unknown gated destruction journal state %q", existing.State)
	}
	if !existing.Decision.Approved {
		return GatedDestroyDecision{}, "", false, errors.New("signing: gated destruction journal omitted its approved decision")
	}
	return cloneGatedDestroyDecision(existing.Decision), existing.State, true, nil
}

func (s *Server) beginGatedDestroyOperation(operationID string, req GatedDestroyRequest, decision GatedDestroyDecision) error {
	requestHash, err := gatedDestroyRequestHash(req)
	if err != nil {
		return err
	}
	if !decision.Approved {
		return errors.New("signing: gated destruction journal requires an approved decision")
	}
	// Only a live handle can authorize a new intent. An exact existing executing
	// marker is the sole authority to resume after a crash removed that handle.
	if _, err := s.lookup(&signerpb.KeyHandle{Id: req.Handle}); err != nil {
		return err
	}
	record := gatedDestroyJournalRecord{
		Version: gatedDestroyJournalVersion, OperationID: operationID,
		RequestHash: requestHash, State: "executing", Decision: cloneGatedDestroyDecision(decision),
	}
	if s.store != nil {
		if err := s.store.createGatedDestroyOperation(record); err != nil {
			return err
		}
	} else {
		if s.gatedDestroyOps == nil {
			s.gatedDestroyOps = make(map[string]gatedDestroyJournalRecord)
		}
		s.gatedDestroyOps[operationID] = record
	}
	return nil
}

func (s *Server) completeGatedDestroyOperation(operationID string, req GatedDestroyRequest, decision GatedDestroyDecision) error {
	requestHash, err := gatedDestroyRequestHash(req)
	if err != nil {
		return err
	}
	record := gatedDestroyJournalRecord{
		Version: gatedDestroyJournalVersion, OperationID: operationID,
		RequestHash: requestHash, State: "completed", Decision: cloneGatedDestroyDecision(decision),
	}
	if s.store != nil {
		return s.store.completeGatedDestroyOperation(record)
	}
	if s.gatedDestroyOps == nil {
		s.gatedDestroyOps = make(map[string]gatedDestroyJournalRecord)
	}
	s.gatedDestroyOps[operationID] = record
	return nil
}

func cloneGatedDestroyDecision(in GatedDestroyDecision) GatedDestroyDecision {
	return GatedDestroyDecision{
		Approved: in.Approved, RefusalRecord: append([]byte(nil), in.RefusalRecord...),
		Authorization: append([]byte(nil), in.Authorization...), Evidence: append([]byte(nil), in.Evidence...),
	}
}

func (ks *KeyStore) gatedDestroyJournalDir() string {
	return filepath.Join(ks.dir, "gated-destructions")
}

func (ks *KeyStore) gatedDestroyJournalPath(operationID string) string {
	return filepath.Join(ks.gatedDestroyJournalDir(), crypto.SHA256Hex([]byte(operationID))+".result")
}

func gatedDestroyJournalAAD(operationID string) []byte {
	return []byte("trstctl:signer-gated-destruction:v1\x00" + operationID)
}

func (ks *KeyStore) createGatedDestroyOperation(record gatedDestroyJournalRecord) error {
	if err := os.MkdirAll(ks.gatedDestroyJournalDir(), 0o700); err != nil {
		return err
	}
	if err := syncDirectory(ks.dir); err != nil {
		return err
	}
	sealed, err := ks.sealGatedDestroyRecord(record)
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	file, err := os.OpenFile(ks.gatedDestroyJournalPath(record.OperationID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(ks.gatedDestroyJournalDir())
}

func (ks *KeyStore) completeGatedDestroyOperation(record gatedDestroyJournalRecord) error {
	sealed, err := ks.sealGatedDestroyRecord(record)
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	temp, err := os.CreateTemp(ks.gatedDestroyJournalDir(), ".gated-destroy-result-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(sealed); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, ks.gatedDestroyJournalPath(record.OperationID)); err != nil {
		return err
	}
	return syncDirectory(ks.gatedDestroyJournalDir())
}

func (ks *KeyStore) readGatedDestroyOperation(operationID string) (gatedDestroyJournalRecord, error) {
	sealed, err := os.ReadFile(ks.gatedDestroyJournalPath(operationID)) // #nosec G304 -- exact signer-owned journal path.
	if err != nil {
		return gatedDestroyJournalRecord{}, err
	}
	plain, err := seal.Open(ks.wrapper, sealed, gatedDestroyJournalAAD(operationID))
	if err != nil {
		return gatedDestroyJournalRecord{}, fmt.Errorf("signing: open gated destruction journal: %w", err)
	}
	defer secret.Wipe(plain)
	var record gatedDestroyJournalRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return gatedDestroyJournalRecord{}, err
	}
	if record.Version != gatedDestroyJournalVersion || record.OperationID != operationID || record.RequestHash == "" {
		return gatedDestroyJournalRecord{}, errors.New("signing: gated destruction journal binding mismatch")
	}
	return record, nil
}

func (ks *KeyStore) sealGatedDestroyRecord(record gatedDestroyJournalRecord) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	return seal.Seal(ks.wrapper, raw, gatedDestroyJournalAAD(record.OperationID))
}
