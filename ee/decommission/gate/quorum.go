// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	bgquorum "trstctl.com/trstctl/internal/breakglass/quorum"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	quorumEvidenceDomain = "trstctl/vdec/gated-destruction/quorum-evidence/v1"
	quorumPolicyFile     = "vdec-gated-destruction-quorum.json"
)

var ErrQuorumNotMet = errors.New("vdec gate: quorum not met")

type DestroyContextV1 struct {
	Version  int    `json:"version"`
	KeyClass string `json:"key_class,omitempty"`
}

type QuorumApprovalsV1 struct {
	Version   int      `json:"version"`
	KeyClass  string   `json:"key_class"`
	Approvals []string `json:"approvals"`
}

// QuorumEvidence carries the VDEC-claim-11 quorum: approvals from a threshold of
// distinct operators, bound into the destruction-record commitment.
type QuorumEvidence struct {
	Version         int      `json:"version"`
	Domain          string   `json:"domain"`
	KeyClass        string   `json:"key_class"`
	Threshold       int      `json:"threshold"`
	AuthorizedCount int      `json:"authorized_count"`
	ApprovalCount   int      `json:"approval_count"`
	Approvers       []string `json:"approvers,omitempty"`
	ApproverDigest  []byte   `json:"approver_digest"`
	Satisfied       bool     `json:"satisfied"`
}

type QuorumPolicy map[string]bgquorum.Quorum

type QuorumPolicyV1 struct {
	Version      int                   `json:"version"`
	Requirements []QuorumRequirementV1 `json:"requirements"`
}

type QuorumRequirementV1 struct {
	KeyClass  string   `json:"key_class"`
	Threshold int      `json:"threshold"`
	Operators []string `json:"operators"`
}

func EncodeDestroyContext(keyClass string) ([]byte, error) {
	body := DestroyContextV1{Version: SchemaV1, KeyClass: strings.TrimSpace(keyClass)}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode destroy context: %w", err)
	}
	return raw, nil
}

func DecodeDestroyContext(raw []byte) (DestroyContextV1, error) {
	if len(raw) == 0 {
		return DestroyContextV1{}, nil
	}
	var body DestroyContextV1
	if err := json.Unmarshal(raw, &body); err != nil {
		return DestroyContextV1{}, fmt.Errorf("%w: decode destroy context: %v", ErrInvalidEvidence, err)
	}
	if body.Version != 0 && body.Version != SchemaV1 {
		return DestroyContextV1{}, fmt.Errorf("%w: unsupported destroy context version %d", ErrInvalidEvidence, body.Version)
	}
	body.Version = SchemaV1
	body.KeyClass = strings.TrimSpace(body.KeyClass)
	return body, nil
}

func EncodeQuorumApprovals(keyClass string, approvals []string) ([]byte, error) {
	body := QuorumApprovalsV1{
		Version:   SchemaV1,
		KeyClass:  strings.TrimSpace(keyClass),
		Approvals: cloneStrings(approvals),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode quorum approvals: %w", err)
	}
	return raw, nil
}

func DecodeQuorumEvidence(raw []byte) (QuorumEvidence, error) {
	if len(raw) == 0 {
		return QuorumEvidence{}, fmt.Errorf("%w: missing quorum evidence", ErrInvalidEvidence)
	}
	var ev QuorumEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return QuorumEvidence{}, fmt.Errorf("%w: decode quorum evidence: %v", ErrInvalidEvidence, err)
	}
	ev = NormalizeQuorumEvidence(ev)
	if err := ValidateQuorumEvidence(ev); err != nil {
		return QuorumEvidence{}, err
	}
	return ev, nil
}

func EncodeQuorumEvidence(ev QuorumEvidence) ([]byte, error) {
	ev = NormalizeQuorumEvidence(ev)
	if err := ValidateQuorumEvidence(ev); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode quorum evidence: %w", err)
	}
	return raw, nil
}

func NormalizeQuorumEvidence(ev QuorumEvidence) QuorumEvidence {
	ev.Version = SchemaV1
	ev.Domain = quorumEvidenceDomain
	ev.KeyClass = strings.TrimSpace(ev.KeyClass)
	ev.Approvers = distinctSortedStrings(ev.Approvers)
	ev.ApprovalCount = len(ev.Approvers)
	ev.Satisfied = ev.Threshold > 0 && ev.ApprovalCount >= ev.Threshold
	ev.ApproverDigest = quorumApproverDigest(ev.KeyClass, ev.Approvers)
	return ev
}

func ValidateQuorumEvidence(ev QuorumEvidence) error {
	ev = NormalizeQuorumEvidence(ev)
	if ev.KeyClass == "" || ev.Threshold <= 0 || ev.AuthorizedCount < ev.Threshold {
		return fmt.Errorf("%w: key class, threshold, and authorized count are required", ErrInvalidEvidence)
	}
	if !ev.Satisfied {
		return fmt.Errorf("%w: only %d distinct approvals for threshold %d", ErrQuorumNotMet, ev.ApprovalCount, ev.Threshold)
	}
	if len(ev.ApproverDigest) == 0 {
		return fmt.Errorf("%w: approver digest is required", ErrInvalidEvidence)
	}
	return nil
}

func QuorumEvidenceDigest(ev QuorumEvidence) ([]byte, error) {
	raw, err := EncodeQuorumEvidence(ev)
	if err != nil {
		return nil, err
	}
	body := struct {
		Domain   string `json:"domain"`
		Evidence []byte `json:"evidence"`
	}{Domain: quorumEvidenceDomain, Evidence: raw}
	wrapped, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode quorum evidence digest: %w", err)
	}
	return crypto.SHA256Sum(wrapped), nil
}

func LoadQuorumPolicy(dir string) (QuorumPolicy, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, quorumPolicyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vdec gate: read quorum policy: %w", err)
	}
	return DecodeQuorumPolicy(raw)
}

func DecodeQuorumPolicy(raw []byte) (QuorumPolicy, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var body QuorumPolicyV1
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("%w: decode quorum policy: %v", ErrInvalidEvidence, err)
	}
	if body.Version != 0 && body.Version != SchemaV1 {
		return nil, fmt.Errorf("%w: unsupported quorum policy version %d", ErrInvalidEvidence, body.Version)
	}
	policy := make(QuorumPolicy, len(body.Requirements))
	for _, req := range body.Requirements {
		keyClass := strings.TrimSpace(req.KeyClass)
		quorum := bgquorum.Quorum{
			Threshold: req.Threshold,
			Operators: cloneStrings(req.Operators),
		}
		if keyClass == "" || quorum.Threshold <= 0 || len(quorum.Operators) < quorum.Threshold {
			return nil, fmt.Errorf("%w: quorum policy requires key class, threshold, and operators", ErrInvalidEvidence)
		}
		if err := quorum.Verify(quorum.Operators); err != nil {
			return nil, fmt.Errorf("%w: quorum policy for %s: %v", ErrInvalidEvidence, keyClass, err)
		}
		policy[keyClass] = quorum
	}
	if len(policy) == 0 {
		return nil, nil
	}
	return policy, nil
}

func (p QuorumPolicy) Requirement(keyClass string) (bgquorum.Quorum, bool) {
	if p == nil {
		return bgquorum.Quorum{}, false
	}
	q, ok := p[strings.TrimSpace(keyClass)]
	return q, ok
}

func (p QuorumPolicy) VerifyApprovals(keyClass string, raw []byte) (QuorumEvidence, error) {
	keyClass = strings.TrimSpace(keyClass)
	q, required := p.Requirement(keyClass)
	if !required {
		return QuorumEvidence{}, nil
	}
	if len(raw) == 0 {
		return QuorumEvidence{}, fmt.Errorf("%w: approvals are required for key class %s", ErrQuorumNotMet, keyClass)
	}
	var approvals QuorumApprovalsV1
	if err := json.Unmarshal(raw, &approvals); err != nil {
		return QuorumEvidence{}, fmt.Errorf("%w: decode quorum approvals: %v", ErrInvalidEvidence, err)
	}
	if approvals.Version != 0 && approvals.Version != SchemaV1 {
		return QuorumEvidence{}, fmt.Errorf("%w: unsupported quorum approval version %d", ErrInvalidEvidence, approvals.Version)
	}
	approvals.KeyClass = strings.TrimSpace(approvals.KeyClass)
	if approvals.KeyClass != keyClass {
		return QuorumEvidence{}, fmt.Errorf("%w: approval key class %q does not match destroy key class %q", ErrInvalidEvidence, approvals.KeyClass, keyClass)
	}
	if err := q.Verify(approvals.Approvals); err != nil {
		return QuorumEvidence{}, fmt.Errorf("%w: %v", ErrQuorumNotMet, err)
	}
	ev := NormalizeQuorumEvidence(QuorumEvidence{
		KeyClass:        keyClass,
		Threshold:       q.Threshold,
		AuthorizedCount: len(q.Operators),
		Approvers:       approvals.Approvals,
	})
	if err := ValidateQuorumEvidence(ev); err != nil {
		return QuorumEvidence{}, err
	}
	return ev, nil
}

func (p QuorumPolicy) VerifyEvidence(keyClass string, ev QuorumEvidence) error {
	keyClass = strings.TrimSpace(keyClass)
	q, required := p.Requirement(keyClass)
	if !required {
		return nil
	}
	ev = NormalizeQuorumEvidence(ev)
	if ev.KeyClass != keyClass {
		return fmt.Errorf("%w: quorum evidence key class %q does not match %q", ErrInvalidEvidence, ev.KeyClass, keyClass)
	}
	if ev.Threshold != q.Threshold || ev.AuthorizedCount != len(q.Operators) {
		return fmt.Errorf("%w: quorum threshold or authorization set changed", ErrInvalidEvidence)
	}
	if err := q.Verify(ev.Approvers); err != nil {
		return fmt.Errorf("%w: %v", ErrQuorumNotMet, err)
	}
	return ValidateQuorumEvidence(ev)
}

func (g *Gate) verifyQuorum(req signing.GatedDestroyRequest) ([]byte, error) {
	ctx, err := DecodeDestroyContext(req.Context)
	if err != nil {
		return nil, err
	}
	if _, required := g.quorum.Requirement(ctx.KeyClass); !required {
		return nil, nil
	}
	ev, err := g.quorum.VerifyApprovals(ctx.KeyClass, req.Approvals)
	if err != nil {
		return nil, err
	}
	raw, err := EncodeQuorumEvidence(ev)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func cloneQuorumPolicy(in QuorumPolicy) QuorumPolicy {
	if in == nil {
		return nil
	}
	out := make(QuorumPolicy, len(in))
	for key, q := range in {
		q.Operators = cloneStrings(q.Operators)
		out[strings.TrimSpace(key)] = q
	}
	return out
}

func quorumApproverDigest(keyClass string, approvers []string) []byte {
	body := struct {
		Domain    string   `json:"domain"`
		KeyClass  string   `json:"key_class"`
		Approvers []string `json:"approvers"`
	}{
		Domain:    quorumEvidenceDomain + "/approvers",
		KeyClass:  strings.TrimSpace(keyClass),
		Approvers: distinctSortedStrings(approvers),
	}
	raw, _ := json.Marshal(body)
	return crypto.SHA256Sum(raw)
}

func distinctSortedStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}
