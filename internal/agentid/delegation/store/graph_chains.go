// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IssuanceChain is one issued chain-bound credential with the delegation
// chain it was issued under, root first, for the access graph (Q4-L4).
type IssuanceChain struct {
	Issuance Issuance
	// Chain is root first; empty when Broken.
	Chain []DelegationRecord
	// Broken is true when a parent record is missing, the walk loops, or it
	// never reaches a root anchor within maxChainWalk records.
	Broken bool
	// Revoked is true once a revocation directive has a job for the
	// credential.
	Revoked bool
}

// maxChainWalk bounds how many records one chain walk reads.
const maxChainWalk = 64

// ListIssuanceChains returns up to limit issued credentials in credential id
// order, each with its delegation chain (root first) and whether a
// revocation covers it. more is true when more credentials exist. The chains
// are read level by level, one query per level, rather than record by record.
func (r *Repo) ListIssuanceChains(ctx context.Context, tenantID string, limit int) ([]IssuanceChain, bool, error) {
	if limit <= 0 {
		return nil, false, nil
	}
	var out []IssuanceChain
	more := false
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT credential_id, subject_id, chain_head_digest, chain_digest, agent_stack_digest,
			        task_envelope_digest, not_before, not_after, attestation_ref, seq
			   FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY credential_id
			  LIMIT $1`, limit+1)
		if err != nil {
			return fmt.Errorf("agid store: list issuances: %w", err)
		}
		for rows.Next() {
			var iss Issuance
			if err := rows.Scan(&iss.CredentialID, &iss.SubjectID, &iss.ChainHeadDigest, &iss.ChainDigest, &iss.AgentStackDigest,
				&iss.TaskEnvelopeDigest, &iss.NotBefore, &iss.NotAfter, &iss.AttestationRef, &iss.Seq); err != nil {
				rows.Close()
				return fmt.Errorf("agid store: scan issuance: %w", err)
			}
			out = append(out, IssuanceChain{Issuance: iss})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("agid store: list issuances: %w", err)
		}
		if len(out) > limit {
			out, more = out[:limit], true
		}
		if len(out) == 0 {
			return nil
		}
		records, err := loadChainRecords(ctx, tx, out)
		if err != nil {
			return err
		}
		for i := range out {
			out[i].Chain, out[i].Broken = walkChain(records, out[i].Issuance.ChainHeadDigest)
		}
		ids := make([]string, len(out))
		for i, c := range out {
			ids[i] = c.Issuance.CredentialID
		}
		revoked, err := tx.Query(ctx,
			`SELECT DISTINCT credential_id FROM agent_revocation_jobs
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = ANY($1)`, ids)
		if err != nil {
			return fmt.Errorf("agid store: read revocations: %w", err)
		}
		covered := map[string]bool{}
		for revoked.Next() {
			var id string
			if err := revoked.Scan(&id); err != nil {
				revoked.Close()
				return fmt.Errorf("agid store: scan revocation: %w", err)
			}
			covered[id] = true
		}
		revoked.Close()
		if err := revoked.Err(); err != nil {
			return fmt.Errorf("agid store: read revocations: %w", err)
		}
		for i := range out {
			out[i].Revoked = covered[out[i].Issuance.CredentialID]
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, more, nil
}

// loadChainRecords reads every record the chains reach: the heads first, then
// each level's parents, at most maxChainWalk levels.
func loadChainRecords(ctx context.Context, tx pgx.Tx, chains []IssuanceChain) (map[string]DelegationRecord, error) {
	records := map[string]DelegationRecord{}
	wanted := map[string][]byte{}
	for _, c := range chains {
		wanted[string(c.Issuance.ChainHeadDigest)] = c.Issuance.ChainHeadDigest
	}
	for level := 0; level < maxChainWalk && len(wanted) > 0; level++ {
		digests := make([][]byte, 0, len(wanted))
		for _, d := range wanted {
			digests = append(digests, d)
		}
		rows, err := tx.Query(ctx,
			`SELECT record_digest, parent_digest, root_anchor, delegator_id, delegate_id,
			        depth_remaining, not_before, not_after, encoded, seq
			   FROM agent_delegation_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND record_digest = ANY($1)`, digests)
		if err != nil {
			return nil, fmt.Errorf("agid store: load chain records: %w", err)
		}
		next := map[string][]byte{}
		for rows.Next() {
			var rec DelegationRecord
			var parent []byte
			if err := rows.Scan(&rec.RecordDigest, &parent, &rec.RootAnchor, &rec.DelegatorID, &rec.DelegateID,
				&rec.DepthRemaining, &rec.NotBefore, &rec.NotAfter, &rec.Encoded, &rec.Seq); err != nil {
				rows.Close()
				return nil, fmt.Errorf("agid store: scan chain record: %w", err)
			}
			rec.ParentDigest = parent
			records[string(rec.RecordDigest)] = rec
			if !rec.RootAnchor && len(parent) > 0 {
				if _, have := records[string(parent)]; !have {
					next[string(parent)] = parent
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("agid store: load chain records: %w", err)
		}
		wanted = next
	}
	return records, nil
}

// walkChain follows parent digests from head to a root anchor and returns the
// chain root first, or broken when a record is missing, the walk loops, or it
// is longer than maxChainWalk.
func walkChain(records map[string]DelegationRecord, head []byte) ([]DelegationRecord, bool) {
	var leafToRoot []DelegationRecord
	seen := map[string]bool{}
	for cur := head; len(leafToRoot) < maxChainWalk; {
		rec, ok := records[string(cur)]
		if !ok || seen[string(cur)] {
			return nil, true
		}
		seen[string(cur)] = true
		leafToRoot = append(leafToRoot, rec)
		if rec.RootAnchor {
			chain := make([]DelegationRecord, len(leafToRoot))
			for i := range leafToRoot {
				chain[len(leafToRoot)-1-i] = leafToRoot[i]
			}
			return chain, false
		}
		if len(rec.ParentDigest) == 0 {
			return nil, true
		}
		cur = rec.ParentDigest
	}
	return nil, true
}
