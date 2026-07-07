// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package store is the tenant-scoped (RLS) persistence for the AGID
// delegation/issuance lifecycle: the durable delegation tree, the issued-credential
// registry, the attestation bindings that justified issuances, the signed refusal
// artifacts, and the revocation directive + per-descendant jobs. It layers on the
// MPL core store through the feature-neutral WithExtraMigrations seam and the
// RLS-scoped Store.WithTenant transaction; it forks neither the core store nor its
// migration runner (AN-1, AN-9). AGID DDL ships here as embedded migrations/*.sql
// and is registered only through the tagged ee_attach seam, so the core-only build
// applies zero AGID migrations.
//
// Scope (AGID-02): schema + repositories + read projections only. The signer's
// in-custody verification (AGID-04), minting, the cascade job execution / outbox
// enqueue (AGID-10), and the terminal-state transition / aggregate evidence
// (AGID-11) are NOT here. The revocation tables carry the SCHEMA + the read paths;
// AGID-10/11 write them.
//
// This package holds raw per-tenant DML against tenant tables, so it opts into the
// AN-1 tenant-filter rule with the //trstctl:repository marker: the tenantfilter
// analyzer actively verifies every query below constrains tenant_id in a
// WHERE/ON-CONFLICT/INSERT-column predicate.
//
//trstctl:repository
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsFS returns the AGID delegation DDL as a migration source for the core
// store's feature-neutral WithExtraMigrations seam. It is wired only through the
// tagged ee_attach seam; the core-only build never references it, so the core-only
// build applies zero AGID migrations (INV-A10 / acceptance criterion 5). The AGID
// DDL uses the reserved high version band (>= 910000) so it cannot collide with
// core or succession migration versions.
func MigrationsFS() fs.FS { return migrationsFS }

// ErrChainBroken is returned by FetchChain when the parent-hash edges do not form a
// single gapless chain root-to-leaf for the requested credential (a referenced
// parent record is missing, or the walk does not terminate at a root anchor). The
// store never returns a partial chain silently.
var ErrChainBroken = errors.New("agid store: delegation chain is broken (missing parent or no root anchor)")

// DelegationRecord is a durable delegation-tree row (one per delegation record). It
// mirrors ee/agentid/delegation.Record's persisted shape: the record digest (chain
// node id), the parent-hash edge (empty iff root-anchored), the parties, the
// remaining depth and validity window, and the opaque encoded record. It holds no
// private key material (AN-8); Encoded is the canonical bytes + delegator signature.
type DelegationRecord struct {
	RecordDigest   []byte
	ParentDigest   []byte // empty iff RootAnchor
	RootAnchor     bool
	DelegatorID    string
	DelegateID     string
	DepthRemaining uint32
	NotBefore      int64
	NotAfter       int64
	Encoded        []byte
	Seq            uint64 // determining ledger sequence (watermark ordering)
}

// Issuance is an issued-credential registry row. It binds the verified delegation
// chain (ChainHeadDigest = leaf record digest; ChainDigest = digest over the whole
// chain) and the agent-stack digest, with an optional task-envelope digest, a
// validity window, and the attestation binding that justified it (INV-A3/A4/A6).
type Issuance struct {
	CredentialID       string
	SubjectID          string
	ChainHeadDigest    []byte
	ChainDigest        []byte
	AgentStackDigest   []byte
	TaskEnvelopeDigest []byte // optional
	NotBefore          int64
	NotAfter           int64
	AttestationRef     []byte // optional
	Seq                uint64
}

// AttestationBinding is verified attestation evidence bound to the issuance it
// justified (§4.2). EvidenceDigest is unique per tenant so a replayed attestation
// cannot justify a second issuance (INV-A6 substrate).
type AttestationBinding struct {
	BindingID        string
	CredentialID     string
	EvidenceDigest   []byte
	AttestationClass string
	VerifiedAt       int64
	Seq              uint64
}

// RefusalRecord is a signed refusal artifact (INV-A1). It names the failed check
// and carries the signer's signature over the refusal; no private-key operation
// occurred for the refused request.
type RefusalRecord struct {
	RefusalID     string
	SubjectID     string
	FailedCheck   string
	RequestDigest []byte // optional
	Signature     []byte
	Seq           uint64
}

// RevocationDirective is a revocation directive against a subject and the
// determining watermark (the ledger sequence the descendant set was computed
// as-of). Terminal is advanced by AGID-11 when every job is evidenced (INV-A9).
type RevocationDirective struct {
	DirectiveID string
	SubjectID   string
	Reason      string
	Watermark   uint64
	Terminal    bool
	Seq         uint64
}

// RevocationJob is one descendant job of a cascade: the idempotency key (one
// recorded effect per key), the descendant credential, whether it is a follow-on
// (generated for a record committed after the watermark), and a reference to the
// signed per-job completion evidence (written by AGID-10/11). AGID-02 stores the
// schema + read path; the job execution / outbox enqueue is AGID-10.
type RevocationJob struct {
	DirectiveID    string
	IdempotencyKey string
	CredentialID   string
	FollowOn       bool
	CompletionRef  []byte // optional until AGID-10/11 records evidence
	Seq            uint64
}

// Repo is the tenant-scoped repository. Every method runs inside the core store's
// RLS-scoped transaction (Store.WithTenant), so row-level security confines all
// access to the caller's tenant (AN-1). No method uses SystemPool for tenant data.
type Repo struct {
	core *corestore.Store
}

// New returns a Repo over the core store.
func New(core *corestore.Store) *Repo { return &Repo{core: core} }

// InsertDelegationRecord inserts a delegation-tree row for tenantID. The tenant_id
// column is bound from the RLS session setting, so the row is always the caller's
// tenant (the RLS WITH CHECK enforces it). parent_digest is stored NULL when the
// record is root-anchored so the linkage CHECK holds.
func (r *Repo) InsertDelegationRecord(ctx context.Context, tenantID string, rec DelegationRecord) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_delegation_records
			   (tenant_id, record_digest, parent_digest, root_anchor, delegator_id, delegate_id,
			    depth_remaining, not_before, not_after, encoded, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			rec.RecordDigest, nilIfEmpty(rec.ParentDigest), rec.RootAnchor, rec.DelegatorID, rec.DelegateID,
			int64(rec.DepthRemaining), rec.NotBefore, rec.NotAfter, rec.Encoded, int64(rec.Seq))
		if err != nil {
			return fmt.Errorf("agid store: insert delegation record: %w", err)
		}
		return nil
	})
}

// InsertIssuance inserts an issued-credential registry row for tenantID.
func (r *Repo) InsertIssuance(ctx context.Context, tenantID string, iss Issuance) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_issuances
			   (tenant_id, credential_id, subject_id, chain_head_digest, chain_digest, agent_stack_digest,
			    task_envelope_digest, not_before, not_after, attestation_ref, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			iss.CredentialID, iss.SubjectID, iss.ChainHeadDigest, iss.ChainDigest, iss.AgentStackDigest,
			nilIfEmpty(iss.TaskEnvelopeDigest), iss.NotBefore, iss.NotAfter, nilIfEmpty(iss.AttestationRef), int64(iss.Seq))
		if err != nil {
			return fmt.Errorf("agid store: insert issuance: %w", err)
		}
		return nil
	})
}

// InsertAttestationBinding inserts a verified attestation binding for tenantID. A
// duplicate evidence_digest violates the unique index (INV-A6 replay-refused).
func (r *Repo) InsertAttestationBinding(ctx context.Context, tenantID string, ab AttestationBinding) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_attestation_bindings
			   (tenant_id, binding_id, credential_id, evidence_digest, attestation_class, verified_at, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)`,
			ab.BindingID, ab.CredentialID, ab.EvidenceDigest, ab.AttestationClass, ab.VerifiedAt, int64(ab.Seq))
		if err != nil {
			return fmt.Errorf("agid store: insert attestation binding: %w", err)
		}
		return nil
	})
}

// InsertRefusalRecord inserts a signed refusal artifact for tenantID (INV-A1).
func (r *Repo) InsertRefusalRecord(ctx context.Context, tenantID string, rr RefusalRecord) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_refusal_records
			   (tenant_id, refusal_id, subject_id, failed_check, request_digest, signature, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)`,
			rr.RefusalID, rr.SubjectID, rr.FailedCheck, nilIfEmpty(rr.RequestDigest), rr.Signature, int64(rr.Seq))
		if err != nil {
			return fmt.Errorf("agid store: insert refusal record: %w", err)
		}
		return nil
	})
}

// InsertRevocationDirectiveWithJobs inserts a revocation directive together with its
// per-descendant jobs in a SINGLE RLS-scoped transaction (the transactional-outbox
// shape INV-A8 requires; AGID-10 drives the job execution). The directive carries
// the determining watermark. Every row is bound to the caller's tenant.
func (r *Repo) InsertRevocationDirectiveWithJobs(ctx context.Context, tenantID string, dir RevocationDirective, jobs []RevocationJob) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO agent_revocation_directives
			   (tenant_id, directive_id, subject_id, reason, watermark, terminal, seq)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)`,
			dir.DirectiveID, dir.SubjectID, dir.Reason, int64(dir.Watermark), dir.Terminal, int64(dir.Seq)); err != nil {
			return fmt.Errorf("agid store: insert revocation directive: %w", err)
		}
		for _, j := range jobs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO agent_revocation_jobs
				   (tenant_id, directive_id, idempotency_key, credential_id, follow_on, completion_ref, seq)
				 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)`,
				dir.DirectiveID, j.IdempotencyKey, j.CredentialID, j.FollowOn, nilIfEmpty(j.CompletionRef), int64(j.Seq)); err != nil {
				return fmt.Errorf("agid store: insert revocation job %q: %w", j.IdempotencyKey, err)
			}
		}
		return nil
	})
}

// FetchDelegationRecord returns one delegation record by digest, scoped to tenantID
// by RLS. found is false when no such record exists for the caller's tenant.
func (r *Repo) FetchDelegationRecord(ctx context.Context, tenantID string, recordDigest []byte) (rec DelegationRecord, found bool, err error) {
	err = r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		got, ok, e := scanRecord(ctx, tx, recordDigest)
		if e != nil {
			return e
		}
		rec, found = got, ok
		return nil
	})
	return rec, found, err
}

// FetchChain returns the delegation records for a credential ordered ROOT-TO-LEAF
// and gapless. It resolves the credential's chain-head record digest from
// agent_issuances, then walks parent_digest to the root anchor, reversing the walk
// so index 0 is the root. A missing parent or a walk that never reaches a root
// anchor is ErrChainBroken (the chain is never returned partial). Scoped to
// tenantID by RLS. found is false when the credential is not registered.
func (r *Repo) FetchChain(ctx context.Context, tenantID, credentialID string) (chain []DelegationRecord, found bool, err error) {
	err = r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var head []byte
		e := tx.QueryRow(ctx,
			`SELECT chain_head_digest FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1`, credentialID).Scan(&head)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil // found stays false
		}
		if e != nil {
			return fmt.Errorf("agid store: resolve chain head: %w", e)
		}
		found = true

		// Walk leaf -> root following parent_digest, guarding against cycles by
		// bounding the walk to the number of records visited.
		var leafToRoot []DelegationRecord
		cur := head
		seen := make(map[string]struct{})
		for cur != nil {
			if _, dup := seen[string(cur)]; dup {
				return fmt.Errorf("%w: cycle at digest", ErrChainBroken)
			}
			seen[string(cur)] = struct{}{}
			rec, ok, e := scanRecord(ctx, tx, cur)
			if e != nil {
				return e
			}
			if !ok {
				return fmt.Errorf("%w: missing record in chain", ErrChainBroken)
			}
			leafToRoot = append(leafToRoot, rec)
			if rec.RootAnchor {
				cur = nil
				break
			}
			if len(rec.ParentDigest) == 0 {
				// Not root-anchored yet no parent: the chain is broken.
				return fmt.Errorf("%w: non-root record without parent", ErrChainBroken)
			}
			cur = rec.ParentDigest
		}
		// Reverse to root-to-leaf.
		chain = make([]DelegationRecord, len(leafToRoot))
		for i := range leafToRoot {
			chain[len(leafToRoot)-1-i] = leafToRoot[i]
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return chain, found, nil
}

// FetchDescendantSet returns every issued credential whose delegation chain
// includes subjectID as of watermark: the subject appears as a delegator or
// delegate on some record with seq <= watermark, and the credential's chain head
// was recorded with seq <= watermark. The result is the set of credential ids (a
// credential appears at most once), ordered for determinism. Scoped to tenantID by
// RLS. This is the store-side read of the descendant-set projection (INV-A8); the
// authoritative fold is Projection.DescendantSet.
func (r *Repo) FetchDescendantSet(ctx context.Context, tenantID, subjectID string, watermark uint64) ([]string, error) {
	var out []string
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Load every delegation record and every issuance visible up to the
		// watermark, tenant-scoped by the RLS predicate. The chain membership
		// (whether the subject sits on a credential's chain) is then decided by a
		// Go-side walk over the parent-hash edges — the same walk FetchChain uses —
		// so the semantics match the Projection fold exactly (a credential is a
		// descendant iff the subject appears as delegator or delegate on any record
		// of its chain). Both queries filter tenant_id in a WHERE predicate (AN-1).
		byDigest := make(map[string]DelegationRecord)
		drows, err := tx.Query(ctx,
			`SELECT record_digest, parent_digest, root_anchor, delegator_id, delegate_id,
			        depth_remaining, not_before, not_after, encoded, seq
			   FROM agent_delegation_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND seq <= $1`, int64(watermark))
		if err != nil {
			return fmt.Errorf("agid store: load records for descendants: %w", err)
		}
		for drows.Next() {
			var rec DelegationRecord
			var parent []byte
			var depth, seq int64
			if err := drows.Scan(&rec.RecordDigest, &parent, &rec.RootAnchor, &rec.DelegatorID, &rec.DelegateID,
				&depth, &rec.NotBefore, &rec.NotAfter, &rec.Encoded, &seq); err != nil {
				drows.Close()
				return fmt.Errorf("agid store: scan record for descendants: %w", err)
			}
			rec.ParentDigest = parent
			rec.DepthRemaining = uint32(depth)
			rec.Seq = uint64(seq)
			byDigest[string(rec.RecordDigest)] = rec
		}
		if err := drows.Err(); err != nil {
			drows.Close()
			return err
		}
		drows.Close()

		type issRow struct {
			cred string
			head []byte
		}
		var issuances []issRow
		irows, err := tx.Query(ctx,
			`SELECT credential_id, chain_head_digest FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND seq <= $1
			  ORDER BY credential_id ASC`, int64(watermark))
		if err != nil {
			return fmt.Errorf("agid store: load issuances for descendants: %w", err)
		}
		for irows.Next() {
			var row issRow
			if err := irows.Scan(&row.cred, &row.head); err != nil {
				irows.Close()
				return fmt.Errorf("agid store: scan issuance for descendants: %w", err)
			}
			issuances = append(issuances, row)
		}
		if err := irows.Err(); err != nil {
			irows.Close()
			return err
		}
		irows.Close()

		for _, iss := range issuances {
			if chainContainsSubject(byDigest, iss.head, subjectID) {
				out = append(out, iss.cred)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// chainContainsSubject reports whether subjectID appears as a delegator or delegate
// on any record of the chain rooted at head, walking parent-hash edges through the
// byDigest map. A missing edge stops the walk (a broken chain simply cannot match
// beyond the break); cycles are bounded by the visited set. This is the in-memory
// twin of FetchChain's walk, kept identical so the store read and the Projection
// fold agree on chain membership.
func chainContainsSubject(byDigest map[string]DelegationRecord, head []byte, subjectID string) bool {
	cur := head
	seen := make(map[string]struct{})
	for len(cur) > 0 {
		if _, dup := seen[string(cur)]; dup {
			return false
		}
		seen[string(cur)] = struct{}{}
		rec, ok := byDigest[string(cur)]
		if !ok {
			return false
		}
		if rec.DelegatorID == subjectID || rec.DelegateID == subjectID {
			return true
		}
		if rec.RootAnchor || len(rec.ParentDigest) == 0 {
			return false
		}
		cur = rec.ParentDigest
	}
	return false
}

// scanRecord loads a single delegation record by digest inside an already-scoped
// transaction. It returns ok=false for a missing record. A NULL parent_digest reads
// back as an empty slice.
func scanRecord(ctx context.Context, tx pgx.Tx, recordDigest []byte) (DelegationRecord, bool, error) {
	var rec DelegationRecord
	var parent []byte
	var depth, seq int64
	e := tx.QueryRow(ctx,
		`SELECT record_digest, parent_digest, root_anchor, delegator_id, delegate_id,
		        depth_remaining, not_before, not_after, encoded, seq
		   FROM agent_delegation_records
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND record_digest = $1`, recordDigest).
		Scan(&rec.RecordDigest, &parent, &rec.RootAnchor, &rec.DelegatorID, &rec.DelegateID,
			&depth, &rec.NotBefore, &rec.NotAfter, &rec.Encoded, &seq)
	if errors.Is(e, pgx.ErrNoRows) {
		return DelegationRecord{}, false, nil
	}
	if e != nil {
		return DelegationRecord{}, false, fmt.Errorf("agid store: scan delegation record: %w", e)
	}
	rec.ParentDigest = parent
	rec.DepthRemaining = uint32(depth)
	rec.Seq = uint64(seq)
	return rec, true, nil
}

// nilIfEmpty maps an empty byte slice to nil so it stores as SQL NULL (rather than
// an empty-but-non-NULL bytea), keeping the linkage CHECK and the optional columns
// honest.
func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
