// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	TypeCustodyZeroized     = "custody_destroy.zeroized"
	TypeCustodyHSMDestroyed = "custody_destroy.hsm_destroyed"
	DispositionZeroized     = "zeroized"

	destroyEvidenceDomain = "trstctl/vdec/custody-destroy/evidence/v1"
)

var (
	ErrInvalidDestroyEvidence = errors.New("custody destroy: invalid evidence")
	ErrTerminalEpochReached   = errors.New("custody destroy: terminal epoch reached")
)

type EvidenceAppendSink interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

// DestroyConfig wires the custody-boundary destroyers that practice
// VDEC-claim-13: the module-signed destroy attestation identifies the destroyed
// key object and a terminal epoch state inside the boundary makes the signer
// refuse any subsequent key operation at or below the final epoch.
type DestroyConfig struct {
	SignerID string
	Sink     EvidenceAppendSink
	Now      func() time.Time
}

type DestructionEvidence struct {
	Kind               string
	TenantID           string
	StableKeyID        string
	FinalEpoch         uint64
	AttestationClass   AttestationClass
	AttestationClassID string
	Record             []byte
	Digest             []byte
}

type SoftwareBuffer struct {
	Epoch    uint64
	Buffer   *secret.Buffer
	Retained bool
}

type SealedCopyDisposition struct {
	ID         string `json:"id"`
	Erased     bool   `json:"erased"`
	KEKRotated bool   `json:"kek_rotated"`
}

type SoftwareDestroyRequest struct {
	TenantID      string
	StableKeyID   string
	FinalEpoch    uint64
	Buffers       []SoftwareBuffer
	SealedCopies  []SealedCopyDisposition
	DestroyReason string
}

type SoftwareZeroizationRecord struct {
	Version            int                     `json:"version"`
	TenantID           string                  `json:"tenant_id"`
	StableKeyID        string                  `json:"stable_key_id"`
	FinalEpoch         uint64                  `json:"final_epoch"`
	BufferCount        int                     `json:"buffer_count"`
	RetainedCount      int                     `json:"retained_count"`
	Disposition        string                  `json:"disposition"`
	SealedCopies       []SealedCopyDisposition `json:"sealed_copies,omitempty"`
	DestroyedAtUnix    int64                   `json:"destroyed_at_unix"`
	SignerID           string                  `json:"signer_id"`
	AttestationClassID string                  `json:"attestation_class_id"`
	DestroyReason      string                  `json:"destroy_reason,omitempty"`
}

type SoftwareCustodyDestroyer struct {
	mu        sync.Mutex
	signerID  string
	sink      EvidenceAppendSink
	now       func() time.Time
	destroyed map[string]DestructionEvidence
	afterWipe func(SoftwareBuffer)
}

func NewSoftwareCustodyDestroyer(cfg DestroyConfig) *SoftwareCustodyDestroyer {
	return &SoftwareCustodyDestroyer{
		signerID:  destroySignerID(cfg.SignerID),
		sink:      destroySink(cfg.Sink),
		now:       destroyClock(cfg.Now),
		destroyed: make(map[string]DestructionEvidence),
	}
}

func (d *SoftwareCustodyDestroyer) Destroy(ctx context.Context, req SoftwareDestroyRequest) (DestructionEvidence, error) {
	if err := ctx.Err(); err != nil {
		return DestructionEvidence{}, err
	}
	if err := validateDestroyTarget(req.TenantID, req.StableKeyID, req.FinalEpoch); err != nil {
		return DestructionEvidence{}, err
	}
	key := destroyKey(req.TenantID, req.StableKeyID, req.FinalEpoch)

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.destroyed[key]; ok {
		return cloneEvidence(existing), nil
	}

	var retainedCount int
	destroyable := make([]SoftwareBuffer, 0, len(req.Buffers))
	for _, ref := range req.Buffers {
		if ref.Retained || (ref.Epoch != 0 && ref.Epoch > req.FinalEpoch) {
			retainedCount++
			continue
		}
		if ref.Buffer == nil {
			return DestructionEvidence{}, fmt.Errorf("%w: nil software buffer", ErrInvalidDestroyEvidence)
		}
		destroyable = append(destroyable, ref)
	}
	if len(destroyable) == 0 && len(req.SealedCopies) == 0 {
		return DestructionEvidence{}, fmt.Errorf("%w: no software custody material supplied", ErrInvalidDestroyEvidence)
	}
	if err := validateSealedCopyDisposition(req.SealedCopies); err != nil {
		return DestructionEvidence{}, err
	}

	bufferCount := 0
	for _, ref := range destroyable {
		if b := ref.Buffer.Bytes(); len(b) > 0 {
			secret.Wipe(b)
		}
		if d.afterWipe != nil {
			d.afterWipe(ref)
		}
		ref.Buffer.Destroy()
		bufferCount++
	}

	record := SoftwareZeroizationRecord{
		Version:            SchemaV1,
		TenantID:           strings.TrimSpace(req.TenantID),
		StableKeyID:        strings.TrimSpace(req.StableKeyID),
		FinalEpoch:         req.FinalEpoch,
		BufferCount:        bufferCount,
		RetainedCount:      retainedCount,
		Disposition:        DispositionZeroized,
		SealedCopies:       cloneSealedCopies(req.SealedCopies),
		DestroyedAtUnix:    d.now().UTC().Unix(),
		SignerID:           d.signerID,
		AttestationClassID: ClassSoftwareZeroize.ID(),
		DestroyReason:      strings.TrimSpace(req.DestroyReason),
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return DestructionEvidence{}, fmt.Errorf("custody destroy: encode zeroization record: %w", err)
	}
	if _, err := d.sink.Append(ctx, eventspec.Event{
		Type:          TypeCustodyZeroized,
		TenantID:      record.TenantID,
		SchemaVersion: SchemaV1,
		Data:          raw,
	}); err != nil {
		return DestructionEvidence{}, fmt.Errorf("custody destroy: append zeroization record: %w", err)
	}
	evidence := newDestructionEvidence(TypeCustodyZeroized, record.TenantID, record.StableKeyID, record.FinalEpoch, ClassSoftwareZeroize, raw)
	d.destroyed[key] = evidence
	return cloneEvidence(evidence), nil
}

type HSMDestroyRequest struct {
	TenantID    string
	StableKeyID string
	ModuleKeyID string
	FinalEpoch  uint64
}

type HSMDestroyAttestation struct {
	Version            int              `json:"version"`
	ModuleID           string           `json:"module_id"`
	KeyID              string           `json:"key_id"`
	FinalEpoch         uint64           `json:"final_epoch"`
	AttestationClass   AttestationClass `json:"attestation_class"`
	AttestationClassID string           `json:"attestation_class_id"`
	Statement          []byte           `json:"statement,omitempty"`
	Signature          []byte           `json:"signature,omitempty"`
	IssuedAtUnix       int64            `json:"issued_at_unix"`
}

type HSMDestroyRecord struct {
	Version        int                   `json:"version"`
	TenantID       string                `json:"tenant_id"`
	StableKeyID    string                `json:"stable_key_id"`
	ModuleKeyID    string                `json:"module_key_id"`
	FinalEpoch     uint64                `json:"final_epoch"`
	Attestation    HSMDestroyAttestation `json:"attestation"`
	TerminalState  TerminalEpochState    `json:"terminal_state"`
	RecordedAtUnix int64                 `json:"recorded_at_unix"`
	EnforcementID  string                `json:"enforcement_id"`
}

type HSMDestroyModule interface {
	DestroyKey(context.Context, HSMDestroyRequest) (HSMDestroyAttestation, error)
}

type TerminalEpochState struct {
	TenantID           string `json:"tenant_id"`
	StableKeyID        string `json:"stable_key_id"`
	ModuleID           string `json:"module_id"`
	ModuleKeyID        string `json:"module_key_id"`
	FinalEpoch         uint64 `json:"final_epoch"`
	AttestationClassID string `json:"attestation_class_id"`
	DestroyedAtUnix    int64  `json:"destroyed_at_unix"`
}

type CustodyOperationRequest struct {
	TenantID    string
	StableKeyID string
	Epoch       uint64
	Operation   string
}

type HSMCustodyBoundary struct {
	mu         sync.Mutex
	module     HSMDestroyModule
	enforcerID string
	sink       EvidenceAppendSink
	now        func() time.Time
	terminal   map[string]TerminalEpochState
	destroyed  map[string]DestructionEvidence
}

func NewHSMCustodyBoundary(module HSMDestroyModule, cfg DestroyConfig) (*HSMCustodyBoundary, error) {
	if module == nil {
		return nil, fmt.Errorf("%w: HSM module is required", ErrInvalidDestroyEvidence)
	}
	return &HSMCustodyBoundary{
		module:     module,
		enforcerID: destroySignerID(cfg.SignerID),
		sink:       destroySink(cfg.Sink),
		now:        destroyClock(cfg.Now),
		terminal:   make(map[string]TerminalEpochState),
		destroyed:  make(map[string]DestructionEvidence),
	}, nil
}

func (b *HSMCustodyBoundary) Destroy(ctx context.Context, req HSMDestroyRequest) (DestructionEvidence, error) {
	if err := ctx.Err(); err != nil {
		return DestructionEvidence{}, err
	}
	if err := validateDestroyTarget(req.TenantID, req.StableKeyID, req.FinalEpoch); err != nil {
		return DestructionEvidence{}, err
	}
	if strings.TrimSpace(req.ModuleKeyID) == "" {
		return DestructionEvidence{}, fmt.Errorf("%w: module key id is required", ErrInvalidDestroyEvidence)
	}
	key := destroyKey(req.TenantID, req.StableKeyID, req.FinalEpoch)
	boundaryKey := terminalKey(req.TenantID, req.StableKeyID)

	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.destroyed[key]; ok {
		return cloneEvidence(existing), nil
	}
	if state, ok := b.terminal[boundaryKey]; ok && req.FinalEpoch <= state.FinalEpoch {
		return DestructionEvidence{}, fmt.Errorf("%w: final epoch %d <= recorded terminal epoch %d", ErrTerminalEpochReached, req.FinalEpoch, state.FinalEpoch)
	}

	attestation, err := b.module.DestroyKey(ctx, req)
	if err != nil {
		return DestructionEvidence{}, fmt.Errorf("custody destroy: HSM destroy: %w", err)
	}
	attestation = normalizeAttestation(attestation)
	if err := validateAttestation(req, attestation); err != nil {
		return DestructionEvidence{}, err
	}
	now := b.now().UTC().Unix()
	state := TerminalEpochState{
		TenantID:           strings.TrimSpace(req.TenantID),
		StableKeyID:        strings.TrimSpace(req.StableKeyID),
		ModuleID:           strings.TrimSpace(attestation.ModuleID),
		ModuleKeyID:        strings.TrimSpace(req.ModuleKeyID),
		FinalEpoch:         req.FinalEpoch,
		AttestationClassID: attestation.AttestationClassID,
		DestroyedAtUnix:    now,
	}
	record := HSMDestroyRecord{
		Version:        SchemaV1,
		TenantID:       state.TenantID,
		StableKeyID:    state.StableKeyID,
		ModuleKeyID:    state.ModuleKeyID,
		FinalEpoch:     state.FinalEpoch,
		Attestation:    attestation,
		TerminalState:  state,
		RecordedAtUnix: now,
		EnforcementID:  b.enforcerID,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return DestructionEvidence{}, fmt.Errorf("custody destroy: encode HSM destroy record: %w", err)
	}
	if _, err := b.sink.Append(ctx, eventspec.Event{
		Type:          TypeCustodyHSMDestroyed,
		TenantID:      record.TenantID,
		SchemaVersion: SchemaV1,
		Data:          raw,
	}); err != nil {
		return DestructionEvidence{}, fmt.Errorf("custody destroy: append HSM destroy record: %w", err)
	}
	b.terminal[boundaryKey] = state
	evidence := newDestructionEvidence(TypeCustodyHSMDestroyed, record.TenantID, record.StableKeyID, record.FinalEpoch, attestation.AttestationClass, raw)
	b.destroyed[key] = evidence
	return cloneEvidence(evidence), nil
}

func (b *HSMCustodyBoundary) AuthorizeOperation(req CustodyOperationRequest) error {
	if err := validateDestroyTarget(req.TenantID, req.StableKeyID, req.Epoch); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if state, ok := b.terminal[terminalKey(req.TenantID, req.StableKeyID)]; ok && req.Epoch <= state.FinalEpoch {
		op := strings.TrimSpace(req.Operation)
		if op == "" {
			op = "key operation"
		}
		return fmt.Errorf("%w: %s for %s epoch %d <= terminal epoch %d", ErrTerminalEpochReached, op, req.StableKeyID, req.Epoch, state.FinalEpoch)
	}
	return nil
}

func (b *HSMCustodyBoundary) TerminalEpoch(tenantID, stableKeyID string) (TerminalEpochState, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.terminal[terminalKey(tenantID, stableKeyID)]
	return state, ok
}

func normalizeAttestation(att HSMDestroyAttestation) HSMDestroyAttestation {
	if att.Version == 0 {
		att.Version = SchemaV1
	}
	if att.AttestationClassID == "" {
		att.AttestationClassID = att.AttestationClass.ID()
	}
	return att
}

func validateAttestation(req HSMDestroyRequest, att HSMDestroyAttestation) error {
	if strings.TrimSpace(att.ModuleID) == "" {
		return fmt.Errorf("%w: module id is required", ErrInvalidDestroyEvidence)
	}
	if strings.TrimSpace(att.KeyID) != strings.TrimSpace(req.ModuleKeyID) {
		return fmt.Errorf("%w: attestation key id mismatch", ErrInvalidDestroyEvidence)
	}
	if att.FinalEpoch != req.FinalEpoch {
		return fmt.Errorf("%w: attestation final epoch mismatch", ErrInvalidDestroyEvidence)
	}
	if att.AttestationClass <= ClassNone || strings.TrimSpace(att.AttestationClassID) == "" {
		return fmt.Errorf("%w: attestation class is required", ErrInvalidDestroyEvidence)
	}
	if att.AttestationClassID != att.AttestationClass.ID() {
		return fmt.Errorf("%w: attestation class id mismatch", ErrInvalidDestroyEvidence)
	}
	if len(att.Statement) == 0 && len(att.Signature) == 0 {
		return fmt.Errorf("%w: attestation statement or signature is required", ErrInvalidDestroyEvidence)
	}
	return nil
}

func newDestructionEvidence(kind, tenantID, stableKeyID string, finalEpoch uint64, class AttestationClass, record []byte) DestructionEvidence {
	return DestructionEvidence{
		Kind:               kind,
		TenantID:           tenantID,
		StableKeyID:        stableKeyID,
		FinalEpoch:         finalEpoch,
		AttestationClass:   class,
		AttestationClassID: class.ID(),
		Record:             append([]byte(nil), record...),
		Digest:             evidenceDigest(kind, record),
	}
}

func evidenceDigest(kind string, record []byte) []byte {
	body := struct {
		Domain string `json:"domain"`
		Kind   string `json:"kind"`
		Record []byte `json:"record"`
	}{
		Domain: destroyEvidenceDomain,
		Kind:   kind,
		Record: record,
	}
	raw, _ := json.Marshal(body)
	return crypto.SHA256Sum(raw)
}

func cloneEvidence(in DestructionEvidence) DestructionEvidence {
	out := in
	out.Record = append([]byte(nil), in.Record...)
	out.Digest = append([]byte(nil), in.Digest...)
	return out
}

func validateDestroyTarget(tenantID, stableKeyID string, epoch uint64) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(stableKeyID) == "" || epoch == 0 {
		return fmt.Errorf("%w: tenant, stable key id, and epoch are required", ErrInvalidDestroyEvidence)
	}
	return nil
}

func destroySignerID(signerID string) string {
	if trimmed := strings.TrimSpace(signerID); trimmed != "" {
		return trimmed
	}
	return "trstctl-signer"
}

func destroySink(sink EvidenceAppendSink) EvidenceAppendSink {
	if sink != nil {
		return sink
	}
	return NewMemorySink()
}

func destroyClock(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}

func destroyKey(tenantID, stableKeyID string, epoch uint64) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(stableKeyID) + "\x00" + fmt.Sprint(epoch)
}

func terminalKey(tenantID, stableKeyID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(stableKeyID)
}

func cloneSealedCopies(in []SealedCopyDisposition) []SealedCopyDisposition {
	out := make([]SealedCopyDisposition, len(in))
	copy(out, in)
	return out
}

func validateSealedCopyDisposition(copies []SealedCopyDisposition) error {
	for _, copy := range copies {
		if strings.TrimSpace(copy.ID) == "" {
			return fmt.Errorf("%w: sealed copy id is required", ErrInvalidDestroyEvidence)
		}
		if !copy.Erased {
			return fmt.Errorf("%w: sealed copy %s was not erased", ErrInvalidDestroyEvidence, copy.ID)
		}
	}
	return nil
}

func hexDigest(digest []byte) string {
	if len(digest) == 0 {
		return ""
	}
	return hex.EncodeToString(digest)
}
