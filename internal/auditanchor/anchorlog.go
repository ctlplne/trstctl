// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/translog"
)

// The anchor log (A148).
//
// A tenant's continuous anchors are also appended, in order, to an RFC 6962
// Merkle tree (internal/translog). An export carries a signed head of that tree
// and an inclusion proof for every anchor record it holds, so a verifier can
// tell that no anchor between two it holds was removed from the chain — the
// log's leaf indexes would skip — and, given the head saved from an earlier
// export, that the log only grew in between: an anchor series rewritten after
// an auditor saw it no longer extends what they saw. The leaf is recomputed by
// the verifier from the anchor record itself; the export supplies only paths.

const anchorLogLeafDomain = "trstctl/audit/anchor-log/leaf/v1"

// AnchorLogEntry is one anchor as the log records it. The token digest binds
// the authority's time and signature; the leaf leaves out stored timestamps,
// whose precision a database may round.
type AnchorLogEntry struct {
	EventID         string
	ThroughSequence uint64
	ChainHead       string
	TokenSHA256     string
}

// leaf is the entry's log leaf for tenantID.
func (e AnchorLogEntry) leaf(tenantID string) []byte {
	return []byte(strings.Join([]string{
		anchorLogLeafDomain, tenantID, strconv.FormatUint(e.ThroughSequence, 10), e.ChainHead, e.TokenSHA256,
	}, "\x00"))
}

// AnchorLogHead is the statement an export signs about a tenant's anchor log.
type AnchorLogHead struct {
	TenantID string    `json:"tenant_id"`
	TreeSize int       `json:"tree_size"`
	RootHash string    `json:"root_hash"`
	IssuedAt time.Time `json:"issued_at"`
}

// AnchorLogProof is what an export carries about the anchor log.
type AnchorLogProof struct {
	// SignedHead is a compact JWS over AnchorLogHead, signed with the audit
	// export key. Save it to check the next export against it.
	SignedHead  string             `json:"signed_head"`
	Inclusions  []AnchorInclusion  `json:"inclusions"`
	Consistency *AnchorConsistency `json:"consistency,omitempty"`
}

// AnchorInclusion proves the anchor record at RecordSequence is the log's
// entry LeafIndex.
type AnchorInclusion struct {
	RecordSequence uint64   `json:"record_sequence"`
	LeafIndex      int      `json:"leaf_index"`
	Path           []string `json:"path"`
}

// AnchorConsistency proves the log extends its first FromSize entries.
type AnchorConsistency struct {
	FromSize int      `json:"from_size"`
	Path     []string `json:"path"`
}

// ArtifactSigner signs a typed artifact (the audit export key).
type ArtifactSigner interface {
	SignArtifact(kind string, payload []byte) (string, error)
}

// ErrAnchorLogFrom reports a consistency request beyond the log.
var ErrAnchorLogFrom = errors.New("auditanchor: the anchor log is smaller than the requested earlier size")

// BuildAnchorLogProof proves every anchor record in records against the
// tenant's whole anchor log (entries, in append order), and, when fromSize is
// positive, that the log extends its first fromSize entries. It returns nil
// when the tenant has no anchors. An anchor record not yet in the entries
// (projection lag) gets no proof; the verifier reports it.
func BuildAnchorLogProof(tenantID string, entries []AnchorLogEntry, records []auditchain.Record, fromSize int, issuedAt time.Time, signer ArtifactSigner) (*AnchorLogProof, error) {
	if len(entries) == 0 {
		if fromSize > 0 {
			return nil, ErrAnchorLogFrom
		}
		return nil, nil
	}
	if signer == nil {
		return nil, errors.New("auditanchor: the anchor log head needs the audit signing key")
	}
	leaves := make([][]byte, len(entries))
	index := make(map[string]int, len(entries))
	for i, entry := range entries {
		leaves[i] = entry.leaf(tenantID)
		index[entry.EventID] = i
	}
	tree := translog.NewTree(leaves)
	payload, err := json.Marshal(AnchorLogHead{TenantID: tenantID, TreeSize: tree.Size(), RootHash: hex.EncodeToString(tree.Root()), IssuedAt: issuedAt.UTC()})
	if err != nil {
		return nil, err
	}
	signed, err := signer.SignArtifact(jose.ArtifactAuditAnchorLog, payload)
	if err != nil {
		return nil, fmt.Errorf("auditanchor: sign the anchor log head: %w", err)
	}
	proof := &AnchorLogProof{SignedHead: signed, Inclusions: []AnchorInclusion{}}
	for _, record := range records {
		if record.Type != EventTypeAnchored {
			continue
		}
		i, ok := index[record.ID]
		if !ok {
			continue
		}
		path, err := tree.InclusionProof(i)
		if err != nil {
			return nil, err
		}
		proof.Inclusions = append(proof.Inclusions, AnchorInclusion{RecordSequence: record.Sequence, LeafIndex: i, Path: hexPath(path)})
	}
	if fromSize > 0 {
		path, err := tree.ConsistencyProof(fromSize)
		if err != nil {
			return nil, ErrAnchorLogFrom
		}
		proof.Consistency = &AnchorConsistency{FromSize: fromSize, Path: hexPath(path)}
	}
	return proof, nil
}

// AnchorLogResult reports the anchor log check in a verification receipt.
type AnchorLogResult struct {
	Checked  bool   `json:"checked"`
	Reason   string `json:"reason,omitempty"`
	TreeSize int    `json:"tree_size,omitempty"`
	RootHash string `json:"root_hash,omitempty"`
	// Proven anchor records are entries of the log the signed head commits to.
	Proven int `json:"proven"`
	// UnloggedTail counts the newest anchor records the log had not taken in
	// when the export was made.
	UnloggedTail int `json:"unlogged_tail"`
	// ConsistentWithPrevious is true when an earlier signed head was supplied
	// and this log extends it.
	ConsistentWithPrevious bool `json:"consistent_with_previous"`
	// SignedHead is the head to keep for the next verification.
	SignedHead string `json:"signed_head,omitempty"`
}

// VerifyAnchorLog checks an export's anchor log proof against its records:
// the signed head (with the pinned audit keys), every anchor record's
// inclusion, that consecutive anchor records are consecutive log entries, and,
// given previousSignedHead from an earlier export, that the log extends it.
func VerifyAnchorLog(records []auditchain.Record, proof *AnchorLogProof, keys *jose.JWKSet, previousSignedHead string) (AnchorLogResult, error) {
	var result AnchorLogResult
	anchorRecords := 0
	for _, record := range records {
		if record.Type == EventTypeAnchored {
			anchorRecords++
		}
	}
	switch {
	case proof == nil && previousSignedHead != "":
		return result, errors.New("auditanchor: an earlier anchor log head was supplied, but this export carries no anchor log")
	case proof == nil:
		if anchorRecords > 0 {
			result.Reason = "the export carries no anchor log"
		}
		return result, nil
	case keys == nil && previousSignedHead != "":
		return result, errors.New("auditanchor: checking the anchor log against an earlier head needs the pinned audit JWK set")
	case keys == nil:
		result.Reason = "the anchor log's signed head is verified with --audit-jwks"
		return result, nil
	}
	head, root, err := verifyAnchorLogHead(proof.SignedHead, keys)
	if err != nil {
		return result, err
	}
	tenantID := ""
	if len(records) > 0 {
		tenantID = records[0].TenantID
	}
	if tenantID != "" && head.TenantID != tenantID {
		return result, errors.New("auditanchor: the anchor log head names a different tenant than the export")
	}
	result.Checked, result.TreeSize, result.RootHash, result.SignedHead = true, head.TreeSize, head.RootHash, proof.SignedHead

	bySequence := make(map[uint64]AnchorInclusion, len(proof.Inclusions))
	for _, inclusion := range proof.Inclusions {
		if _, dup := bySequence[inclusion.RecordSequence]; dup {
			return result, fmt.Errorf("auditanchor: the anchor log proves record %d twice", inclusion.RecordSequence)
		}
		bySequence[inclusion.RecordSequence] = inclusion
	}
	previousIndex, unproven := -1, false
	for _, record := range records {
		if record.Type != EventTypeAnchored {
			continue
		}
		inclusion, ok := bySequence[record.Sequence]
		if !ok {
			unproven = true
			result.UnloggedTail++
			continue
		}
		delete(bySequence, record.Sequence)
		if unproven {
			return result, fmt.Errorf("auditanchor: anchor record %d is in the anchor log, but an earlier anchor record in this export is not", record.Sequence)
		}
		leaf, err := anchorLeafFromRecord(head.TenantID, record)
		if err != nil {
			return result, err
		}
		path, err := decodePath(inclusion.Path)
		if err != nil {
			return result, err
		}
		if !translog.VerifyInclusion(leaf, inclusion.LeafIndex, head.TreeSize, path, root) {
			return result, fmt.Errorf("auditanchor: anchor record %d is not the anchor log entry the export claims", record.Sequence)
		}
		if previousIndex >= 0 && inclusion.LeafIndex != previousIndex+1 {
			return result, fmt.Errorf("auditanchor: the anchor log holds %d anchor(s) between this export's anchor records before %d that the export does not",
				inclusion.LeafIndex-previousIndex-1, record.Sequence)
		}
		previousIndex = inclusion.LeafIndex
		result.Proven++
	}
	if len(bySequence) > 0 {
		return result, errors.New("auditanchor: the anchor log proves records that are not anchor records in this export")
	}
	if previousSignedHead == "" {
		return result, nil
	}
	previous, previousRoot, err := verifyAnchorLogHead(previousSignedHead, keys)
	if err != nil {
		return result, fmt.Errorf("auditanchor: earlier anchor log head: %w", err)
	}
	if previous.TenantID != head.TenantID {
		return result, errors.New("auditanchor: the earlier anchor log head names a different tenant")
	}
	switch {
	case previous.TreeSize > head.TreeSize:
		return result, fmt.Errorf("auditanchor: the anchor log shrank from %d to %d entries since the earlier head", previous.TreeSize, head.TreeSize)
	case previous.TreeSize == head.TreeSize:
		if previous.RootHash != head.RootHash {
			return result, errors.New("auditanchor: the anchor log was rewritten: same size as the earlier head, different root")
		}
	default:
		if proof.Consistency == nil || proof.Consistency.FromSize != previous.TreeSize {
			return result, fmt.Errorf("auditanchor: the export carries no consistency proof from the earlier head's %d entries; export it with anchor_log_from=%d", previous.TreeSize, previous.TreeSize)
		}
		path, err := decodePath(proof.Consistency.Path)
		if err != nil {
			return result, err
		}
		if !translog.VerifyConsistency(previous.TreeSize, head.TreeSize, path, previousRoot, root) {
			return result, errors.New("auditanchor: the anchor log does not extend the earlier head: anchors the auditor saw were rewritten")
		}
	}
	result.ConsistentWithPrevious = true
	return result, nil
}

func verifyAnchorLogHead(signed string, keys *jose.JWKSet) (AnchorLogHead, []byte, error) {
	payload, err := keys.VerifyArtifact(strings.TrimSpace(signed), jose.ArtifactAuditAnchorLog)
	if err != nil {
		return AnchorLogHead{}, nil, fmt.Errorf("auditanchor: verify the anchor log head: %w", err)
	}
	var head AnchorLogHead
	if err := decodeExactJSON(payload, &head); err != nil {
		return AnchorLogHead{}, nil, fmt.Errorf("auditanchor: decode the anchor log head: %w", err)
	}
	root, err := hex.DecodeString(head.RootHash)
	if err != nil || len(root) != 32 || head.TreeSize < 1 || head.TenantID == "" {
		return AnchorLogHead{}, nil, errors.New("auditanchor: the anchor log head is malformed")
	}
	return head, root, nil
}

// anchorLeafFromRecord recomputes an anchor's log leaf from its own record.
func anchorLeafFromRecord(tenantID string, record auditchain.Record) ([]byte, error) {
	var payload AnchoredEvent
	if err := decodeExactJSON(record.Data, &payload); err != nil {
		return nil, fmt.Errorf("auditanchor: anchor record %d is malformed: %w", record.Sequence, err)
	}
	if payload.Anchor.Token == nil || len(payload.Anchor.Token.DER) == 0 {
		return nil, fmt.Errorf("auditanchor: anchor record %d carries no RFC 3161 token", record.Sequence)
	}
	return AnchorLogEntry{
		ThroughSequence: payload.ThroughSequence, ChainHead: payload.Anchor.ChainHead,
		TokenSHA256: crypto.SHA256Hex(payload.Anchor.Token.DER),
	}.leaf(tenantID), nil
}

func hexPath(path [][]byte) []string {
	out := make([]string, len(path))
	for i, node := range path {
		out[i] = hex.EncodeToString(node)
	}
	return out
}

func decodePath(path []string) ([][]byte, error) {
	out := make([][]byte, len(path))
	for i, node := range path {
		raw, err := hex.DecodeString(node)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("auditanchor: an anchor log proof path holds a malformed hash")
		}
		out[i] = raw
	}
	return out, nil
}
