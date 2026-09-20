// SPDX-License-Identifier: BUSL-1.1

package witness

import (
	"bytes"
	"encoding/hex"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
)

const (
	OperationConformToMajority      = "conform-to-majority"
	OperationConformToAuthoritative = "conform-to-authoritative"

	absentMaterialHash = "absent"
)

type MajorityRequest struct {
	TenantID                  string
	SpecVersion               string
	Planes                    []PlaneState
	AuthoritativeByRecordType map[string]string
}

type MajorityResult struct {
	TenantID string
	Entries  []MajorityEntry
}

type MajorityEntry struct {
	RecordKey                canon.RecordKey
	TargetMaterialHash       string
	TargetPresent            bool
	MajorityAuthorityIDs     []string
	MinorityAuthorityIDs     []string
	AuthoritativeAuthorityID string
	PerPlaneProofs           []PlaneProof
	Actions                  []ConformAction
}

type PlaneProof struct {
	AuthorityID  string
	DigestHash   string
	Present      bool
	Inclusion    *InclusionProof
	Absence      *AbsenceProof
	MaterialHash string
}

type ConformAction struct {
	AuthorityID        string
	RecordKey          canon.RecordKey
	Operation          string
	TargetAuthorityID  string
	TargetMaterialHash string
}

type majorityObservation struct {
	authorityID  string
	recordKey    canon.RecordKey
	present      bool
	materialHash string
	inclusion    *InclusionProof
	absence      *AbsenceProof
	digestHash   string
}

// ClassifyMajority decides, per record key, which planes agree and which must
// conform, by three-way majority with an authoritative-plane override
// (XREC-claim-7).
func ClassifyMajority(req MajorityRequest) (MajorityResult, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	spec := strings.TrimSpace(req.SpecVersion)
	if tenantID == "" || spec == "" || len(req.Planes) < 3 {
		return MajorityResult{}, ErrInvalidWitness
	}
	indexes := make([]planeIndex, 0, len(req.Planes))
	seenPlanes := map[string]bool{}
	for _, plane := range req.Planes {
		authorityID := strings.TrimSpace(plane.AuthorityID)
		if authorityID == "" || seenPlanes[authorityID] || plane.Set.TenantID != tenantID || plane.Set.SpecVersion != spec || plane.Tree == nil {
			return MajorityResult{}, ErrInvalidWitness
		}
		seenPlanes[authorityID] = true
		idx, err := indexPlane(plane)
		if err != nil {
			return MajorityResult{}, err
		}
		indexes = append(indexes, idx)
	}
	keys := majorityUnionKeys(indexes)
	result := MajorityResult{TenantID: tenantID}
	for _, key := range keys {
		observations, recordKey, err := majorityObservations(indexes, key)
		if err != nil {
			return MajorityResult{}, err
		}
		entry, ok := majorityEntry(recordKey, observations, req.AuthoritativeByRecordType)
		if ok {
			result.Entries = append(result.Entries, entry)
		}
	}
	return result, nil
}

func majorityObservations(indexes []planeIndex, key []byte) ([]majorityObservation, canon.RecordKey, error) {
	out := make([]majorityObservation, 0, len(indexes))
	var recordKey canon.RecordKey
	for _, idx := range indexes {
		authorityID := idx.state.AuthorityID
		digestHash := hex.EncodeToString(idx.state.Digest.DigestHash)
		if rec, ok := idx.records[string(key)]; ok {
			if recordKey.TenantID == "" {
				recordKey = rec.RecordKey
			}
			mb, err := materialBytes(rec)
			if err != nil {
				return nil, canon.RecordKey{}, err
			}
			inc, ok := idx.state.Tree.InclusionProof(key)
			if !ok {
				return nil, canon.RecordKey{}, ErrInvalidWitness
			}
			out = append(out, majorityObservation{
				authorityID:  authorityID,
				recordKey:    rec.RecordKey,
				present:      true,
				materialHash: hex.EncodeToString(crypto.SHA256Sum(mb)),
				inclusion:    ptrInclusion(inclusionFromDigest(inc)),
				digestHash:   digestHash,
			})
			continue
		}
		abs, ok := idx.state.Tree.AbsenceProof(key)
		if !ok {
			return nil, canon.RecordKey{}, ErrInvalidWitness
		}
		out = append(out, majorityObservation{
			authorityID:  authorityID,
			present:      false,
			materialHash: absentMaterialHash,
			absence:      absenceFromDigest(abs),
			digestHash:   digestHash,
		})
	}
	if recordKey.TenantID == "" {
		return nil, canon.RecordKey{}, ErrInvalidWitness
	}
	return out, recordKey, nil
}

func majorityEntry(recordKey canon.RecordKey, observations []majorityObservation, authoritative map[string]string) (MajorityEntry, bool) {
	groups := map[string][]string{}
	for _, obs := range observations {
		groups[obs.materialHash] = append(groups[obs.materialHash], obs.authorityID)
	}
	for hash := range groups {
		sort.Strings(groups[hash])
	}
	targetHash, targetPresent, targetAuthority, authoritativeOverride := targetMaterial(recordKey, observations, groups, authoritative)
	if targetHash == "" {
		return MajorityEntry{}, false
	}
	minority := []string{}
	for _, obs := range observations {
		if obs.materialHash != targetHash {
			minority = append(minority, obs.authorityID)
		}
	}
	sort.Strings(minority)
	if len(minority) == 0 {
		return MajorityEntry{}, false
	}
	entry := MajorityEntry{
		RecordKey:                recordKey,
		TargetMaterialHash:       targetHash,
		TargetPresent:            targetPresent,
		MinorityAuthorityIDs:     minority,
		AuthoritativeAuthorityID: targetAuthority,
		PerPlaneProofs:           planeProofs(observations),
	}
	if !authoritativeOverride {
		entry.MajorityAuthorityIDs = append([]string(nil), groups[targetHash]...)
	}
	op := OperationConformToMajority
	if authoritativeOverride {
		op = OperationConformToAuthoritative
	}
	for _, authorityID := range minority {
		entry.Actions = append(entry.Actions, ConformAction{
			AuthorityID:        authorityID,
			RecordKey:          recordKey,
			Operation:          op,
			TargetAuthorityID:  targetAuthority,
			TargetMaterialHash: targetHash,
		})
	}
	return entry, true
}

func targetMaterial(recordKey canon.RecordKey, observations []majorityObservation, groups map[string][]string, authoritative map[string]string) (hash string, present bool, authority string, authoritativeOverride bool) {
	if authority = strings.TrimSpace(authoritative[strings.TrimSpace(recordKey.RecordType)]); authority != "" {
		for _, obs := range observations {
			if obs.authorityID == authority {
				return obs.materialHash, obs.present, authority, true
			}
		}
	}
	for h, authorities := range groups {
		if len(authorities) > len(observations)/2 {
			return h, h != absentMaterialHash, "", false
		}
	}
	return "", false, "", false
}

func planeProofs(observations []majorityObservation) []PlaneProof {
	out := make([]PlaneProof, 0, len(observations))
	for _, obs := range observations {
		proof := PlaneProof{
			AuthorityID:  obs.authorityID,
			DigestHash:   obs.digestHash,
			Present:      obs.present,
			MaterialHash: obs.materialHash,
		}
		if obs.inclusion != nil {
			inc := *obs.inclusion
			proof.Inclusion = &inc
		}
		if obs.absence != nil {
			abs := *obs.absence
			proof.Absence = &abs
		}
		out = append(out, proof)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AuthorityID < out[j].AuthorityID })
	return out
}

func majorityUnionKeys(indexes []planeIndex) [][]byte {
	seen := map[string][]byte{}
	for _, idx := range indexes {
		for key := range idx.records {
			seen[key] = []byte(key)
		}
	}
	out := make([][]byte, 0, len(seen))
	for _, key := range seen {
		out = append(out, append([]byte(nil), key...))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func ptrInclusion(in InclusionProof) *InclusionProof {
	return &in
}
