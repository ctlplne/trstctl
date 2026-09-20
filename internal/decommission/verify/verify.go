// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/succession"
)

const (
	proofNodeDomain  = "trstctl/vdec/destruction-record/inclusion-node/v1"
	proofHashDomain  = "trstctl/vdec/destruction-record/inclusion-hash/v1"
	accountingDomain = "trstctl/vdec/destruction-record/completion-accounting/v1"

	DeterminationDestroyedAfterReprotection = "destroyed_after_recorded_reprotection"
)

var (
	ErrInvalidInput           = errors.New("vdec verify: invalid input")
	ErrRecordSignature        = errors.New("vdec verify: record signature invalid")
	ErrInclusionProof         = errors.New("vdec verify: inclusion proof invalid")
	ErrEpochFloor             = errors.New("vdec verify: final epoch below retained last accepted epoch")
	ErrStableKeyMismatch      = errors.New("vdec verify: stable key mismatch")
	ErrSuccessionChain        = errors.New("vdec verify: succession chain correspondence invalid")
	ErrCompletionAccounting   = errors.New("vdec verify: completion accounting invalid")
	ErrUnaccountedDependent   = errors.New("vdec verify: registered dependent is unaccounted")
	ErrCompletionDigest       = errors.New("vdec verify: completion-events digest mismatch")
	ErrCanonicalProofEncoding = errors.New("vdec verify: non-canonical inclusion proof node")
)

type Request struct {
	Record          record.SignedRecord `json:"record"`
	VerificationKey crypto.PublicKey    `json:"verification_key"`
	LogHead         LogHead             `json:"log_head"`
	Retained        RetainedEpoch       `json:"retained"`
	Succession      *SuccessionEvidence `json:"succession,omitempty"`
	Completion      *CompletionEvidence `json:"completion,omitempty"`
}

type RetainedEpoch struct {
	StableKeyID string `json:"stable_key_id"`
	Epoch       uint64 `json:"epoch"`
}

type LogHead struct {
	LogID           string `json:"log_id"`
	TreeSize        uint64 `json:"tree_size"`
	CheckpointEpoch uint64 `json:"checkpoint_epoch,omitempty"`
	RootDigest      []byte `json:"root_digest"`
}

type SuccessionEvidence struct {
	TrustRootPublicKeyDER []byte                        `json:"trust_root_public_key_der"`
	Genesis               succession.GenesisRecord      `json:"genesis"`
	Chain                 []succession.SuccessionRecord `json:"chain"`
	LastAcceptedEpoch     uint64                        `json:"last_accepted_epoch,omitempty"`
}

type CompletionEvidence struct {
	Registered []depstate.Dependent `json:"registered,omitempty"`
	Completed  []depstate.Dependent `json:"completed,omitempty"`
	Released   []depstate.Dependent `json:"released,omitempty"`
	Erased     []depstate.Dependent `json:"erased,omitempty"`
}

type Verdict struct {
	Determination     string  `json:"determination"`
	StableKeyID       string  `json:"stable_key_id"`
	FinalEpoch        uint64  `json:"final_epoch"`
	LogHead           LogHead `json:"log_head"`
	AttestationClass  string  `json:"attestation_class"`
	CompletionChecked bool    `json:"completion_checked"`
	SuccessionChecked bool    `json:"succession_checked"`
}

type ProofSide string

const (
	ProofLeft  ProofSide = "left"
	ProofRight ProofSide = "right"
)

type ProofNode struct {
	Version int       `json:"version"`
	Domain  string    `json:"domain"`
	Side    ProofSide `json:"side"`
	Digest  []byte    `json:"digest"`
}

// Verify practices VDEC-claim-16, the verifying-computer method: obtain the
// destruction record, verify the minting signature against a held verification
// key, verify the inclusion proof against a held transparency-log head, confirm
// the final epoch against the retained last-accepted epoch, and emit the
// destroyed-after-re-protection determination without network access to the
// control plane.
func Verify(req Request) (Verdict, error) {
	if err := record.VerifyRecord(req.Record, req.VerificationKey); err != nil {
		return Verdict{}, fmt.Errorf("%w: %v", ErrRecordSignature, err)
	}
	c := req.Record.Commitment
	if strings.TrimSpace(c.StableKeyID) == "" || c.FinalEpoch == 0 || len(c.CompletionEventsDigest) == 0 ||
		len(c.DestructionEvidence.Digest) == 0 || strings.TrimSpace(c.DestructionEvidence.AttestationClassID) == "" {
		return Verdict{}, fmt.Errorf("%w: destruction record missing verifier-bound fields", ErrInvalidInput)
	}
	if err := VerifyEpoch(c.StableKeyID, c.FinalEpoch, req.Retained); err != nil {
		return Verdict{}, err
	}
	if err := VerifyInclusionProof(req.Record, req.LogHead); err != nil {
		return Verdict{}, err
	}
	if req.Succession != nil {
		if err := VerifySuccessionCorrespondence(req.Record, *req.Succession); err != nil {
			return Verdict{}, err
		}
	}
	if req.Completion != nil {
		if err := VerifyCompletionAccounting(req.Record, *req.Completion); err != nil {
			return Verdict{}, err
		}
	}
	return Verdict{
		Determination:     DeterminationDestroyedAfterReprotection,
		StableKeyID:       c.StableKeyID,
		FinalEpoch:        c.FinalEpoch,
		LogHead:           cloneLogHead(req.LogHead),
		AttestationClass:  c.DestructionEvidence.AttestationClassID,
		CompletionChecked: req.Completion != nil,
		SuccessionChecked: req.Succession != nil,
	}, nil
}

func VerifyEpoch(stableKeyID string, finalEpoch uint64, retained RetainedEpoch) error {
	if strings.TrimSpace(retained.StableKeyID) == "" {
		return fmt.Errorf("%w: retained stable key id is required", ErrInvalidInput)
	}
	if stableKeyID != retained.StableKeyID {
		return fmt.Errorf("%w: record %q retained %q", ErrStableKeyMismatch, stableKeyID, retained.StableKeyID)
	}
	if finalEpoch < retained.Epoch {
		return fmt.Errorf("%w: final %d retained %d", ErrEpochFloor, finalEpoch, retained.Epoch)
	}
	return nil
}

// VerifyInclusionProof practices VDEC-claim-2: the destruction record is
// committed to an append-only transparency log and published with an inclusion
// proof, which a relying party checks against a held log head.
func VerifyInclusionProof(rec record.SignedRecord, head LogHead) error {
	tp := rec.Commitment.Transparency
	if strings.TrimSpace(head.LogID) == "" || len(head.RootDigest) == 0 || head.TreeSize == 0 {
		return fmt.Errorf("%w: held log head is incomplete", ErrInclusionProof)
	}
	if tp.LogID != "" && tp.LogID != head.LogID {
		return fmt.Errorf("%w: log id %q != held %q", ErrInclusionProof, tp.LogID, head.LogID)
	}
	if tp.TreeSize != 0 && tp.TreeSize != head.TreeSize {
		return fmt.Errorf("%w: tree size %d != held %d", ErrInclusionProof, tp.TreeSize, head.TreeSize)
	}
	if tp.CheckpointEpoch != 0 && tp.CheckpointEpoch != head.CheckpointEpoch {
		return fmt.Errorf("%w: checkpoint epoch %d != held %d", ErrInclusionProof, tp.CheckpointEpoch, head.CheckpointEpoch)
	}
	root, err := InclusionRoot(rec.CommitmentDigest, tp.Proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, head.RootDigest) {
		return fmt.Errorf("%w: root digest mismatch", ErrInclusionProof)
	}
	return nil
}

func EncodeProofNode(side ProofSide, digest []byte) ([]byte, error) {
	n := ProofNode{Version: 1, Domain: proofNodeDomain, Side: side, Digest: cloneBytes(digest)}
	if err := validateProofNode(n); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("vdec verify: encode proof node: %w", err)
	}
	return raw, nil
}

func InclusionRoot(leaf []byte, proof [][]byte) ([]byte, error) {
	if len(leaf) == 0 {
		return nil, fmt.Errorf("%w: missing leaf digest", ErrInclusionProof)
	}
	current := cloneBytes(leaf)
	for i, raw := range proof {
		n, err := decodeProofNode(raw)
		if err != nil {
			return nil, fmt.Errorf("proof node %d: %w", i, err)
		}
		current, err = foldProofNode(current, n)
		if err != nil {
			return nil, fmt.Errorf("proof node %d: %w", i, err)
		}
	}
	return current, nil
}

func HeadForRecord(rec record.SignedRecord) (LogHead, error) {
	tp := rec.Commitment.Transparency
	root, err := InclusionRoot(rec.CommitmentDigest, tp.Proof)
	if err != nil {
		return LogHead{}, err
	}
	return LogHead{
		LogID:           tp.LogID,
		TreeSize:        tp.TreeSize,
		CheckpointEpoch: tp.CheckpointEpoch,
		RootDigest:      root,
	}, nil
}

// VerifySuccessionCorrespondence practices VDEC-claim-17: the verifier takes a
// furnished chain of succession records for the stable key identifier, verifies
// the chain signatures, and confirms the final epoch corresponds to an epoch at
// which a successor superseded the key.
func VerifySuccessionCorrespondence(rec record.SignedRecord, ev SuccessionEvidence) error {
	c := rec.Commitment
	if len(ev.TrustRootPublicKeyDER) == 0 || len(ev.Chain) == 0 {
		return fmt.Errorf("%w: furnished chain and trust root are required", ErrSuccessionChain)
	}
	if err := succession.VerifyGenesis(ev.TrustRootPublicKeyDER, ev.Genesis); err != nil {
		return fmt.Errorf("%w: genesis: %v", ErrSuccessionChain, err)
	}
	if err := succession.VerifyChain(ev.Genesis, ev.Chain, ev.LastAcceptedEpoch); err != nil {
		return fmt.Errorf("%w: chain: %v", ErrSuccessionChain, err)
	}
	if ev.Genesis.IdentityID != c.StableKeyID || ev.Genesis.TenantID != c.TenantID {
		return fmt.Errorf("%w: genesis identity does not match destruction record", ErrSuccessionChain)
	}
	for _, link := range ev.Chain {
		if link.Fields.IdentityID != c.StableKeyID || link.Fields.TenantID != c.TenantID {
			continue
		}
		if link.Fields.PredecessorEpoch != c.FinalEpoch {
			continue
		}
		for _, s := range c.Successors {
			if s.Epoch == link.Fields.Epoch && s.Algorithm == link.Fields.SuccessorAlg && bytes.Equal(s.PublicDER, link.Fields.SuccessorPub) {
				return nil
			}
		}
		return fmt.Errorf("%w: successor at epoch %d is not bound in destruction record", ErrSuccessionChain, link.Fields.Epoch)
	}
	return fmt.Errorf("%w: no furnished chain link supersedes final epoch %d", ErrSuccessionChain, c.FinalEpoch)
}

func CompletionEventsDigest(tenantID, stableKeyID string, finalEpoch uint64, ev CompletionEvidence) ([]byte, error) {
	body, err := completionAccountingBody(tenantID, stableKeyID, finalEpoch, ev)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec verify: encode completion accounting: %w", err)
	}
	return crypto.SHA256Sum(raw), nil
}

// VerifyCompletionAccounting practices VDEC-claim-18: the verifier recomputes the
// completion-events digest from a furnished completion set and confirms every
// registered dependent is accounted for.
func VerifyCompletionAccounting(rec record.SignedRecord, ev CompletionEvidence) error {
	if unaccounted := unaccountedDependents(ev); len(unaccounted) > 0 {
		return fmt.Errorf("%w: %s/%s", ErrUnaccountedDependent, unaccounted[0].Class, unaccounted[0].ID)
	}
	got, err := CompletionEventsDigest(rec.Commitment.TenantID, rec.Commitment.StableKeyID, rec.Commitment.FinalEpoch, ev)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, rec.Commitment.CompletionEventsDigest) {
		return fmt.Errorf("%w", ErrCompletionDigest)
	}
	return nil
}

func decodeProofNode(raw []byte) (ProofNode, error) {
	if len(raw) == 0 {
		return ProofNode{}, fmt.Errorf("%w: empty node", ErrInclusionProof)
	}
	var n ProofNode
	if err := json.Unmarshal(raw, &n); err != nil {
		return ProofNode{}, fmt.Errorf("%w: decode node: %v", ErrInclusionProof, err)
	}
	if err := validateProofNode(n); err != nil {
		return ProofNode{}, err
	}
	canonical, err := json.Marshal(n)
	if err != nil {
		return ProofNode{}, fmt.Errorf("vdec verify: canonicalize proof node: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return ProofNode{}, ErrCanonicalProofEncoding
	}
	return n, nil
}

func validateProofNode(n ProofNode) error {
	if n.Version != 1 || n.Domain != proofNodeDomain || len(n.Digest) == 0 {
		return fmt.Errorf("%w: malformed node", ErrInclusionProof)
	}
	if n.Side != ProofLeft && n.Side != ProofRight {
		return fmt.Errorf("%w: unsupported side %q", ErrInclusionProof, n.Side)
	}
	return nil
}

func foldProofNode(current []byte, n ProofNode) ([]byte, error) {
	left, right := current, n.Digest
	if n.Side == ProofLeft {
		left, right = n.Digest, current
	}
	body := struct {
		Domain string `json:"domain"`
		Left   []byte `json:"left"`
		Right  []byte `json:"right"`
	}{Domain: proofHashDomain, Left: left, Right: right}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec verify: hash proof node: %w", err)
	}
	return crypto.SHA256Sum(raw), nil
}

type completionAccountingV1 struct {
	Version    int                  `json:"version"`
	Domain     string               `json:"domain"`
	TenantID   string               `json:"tenant_id"`
	StableKey  string               `json:"stable_key_id"`
	FinalEpoch uint64               `json:"final_epoch"`
	Registered []depstate.Dependent `json:"registered"`
	Completed  []depstate.Dependent `json:"completed"`
	Released   []depstate.Dependent `json:"released"`
	Erased     []depstate.Dependent `json:"erased"`
}

func completionAccountingBody(tenantID, stableKeyID string, finalEpoch uint64, ev CompletionEvidence) (completionAccountingV1, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(stableKeyID) == "" || finalEpoch == 0 {
		return completionAccountingV1{}, fmt.Errorf("%w: tenant, stable key, and final epoch are required", ErrCompletionAccounting)
	}
	body := completionAccountingV1{
		Version:    1,
		Domain:     accountingDomain,
		TenantID:   strings.TrimSpace(tenantID),
		StableKey:  strings.TrimSpace(stableKeyID),
		FinalEpoch: finalEpoch,
		Registered: sortedDependents(ev.Registered),
		Completed:  sortedDependents(ev.Completed),
		Released:   sortedDependents(ev.Released),
		Erased:     sortedDependents(ev.Erased),
	}
	for _, group := range [][]depstate.Dependent{body.Registered, body.Completed, body.Released, body.Erased} {
		for _, dep := range group {
			if strings.TrimSpace(string(dep.Class)) == "" || strings.TrimSpace(dep.ID) == "" {
				return completionAccountingV1{}, fmt.Errorf("%w: dependent class and id are required", ErrCompletionAccounting)
			}
		}
	}
	return body, nil
}

func unaccountedDependents(ev CompletionEvidence) []depstate.Dependent {
	accounted := make(map[string]struct{})
	for _, dep := range append(append(sortedDependents(ev.Completed), ev.Released...), ev.Erased...) {
		accounted[dependentKey(dep)] = struct{}{}
	}
	out := make([]depstate.Dependent, 0)
	for _, dep := range sortedDependents(ev.Registered) {
		if _, ok := accounted[dependentKey(dep)]; !ok {
			out = append(out, dep)
		}
	}
	return out
}

func sortedDependents(in []depstate.Dependent) []depstate.Dependent {
	out := append([]depstate.Dependent(nil), in...)
	for i := range out {
		out[i].ID = strings.TrimSpace(out[i].ID)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func dependentKey(dep depstate.Dependent) string {
	return string(dep.Class) + "\x00" + dep.ID
}

func cloneLogHead(in LogHead) LogHead {
	in.RootDigest = cloneBytes(in.RootDigest)
	return in
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}
