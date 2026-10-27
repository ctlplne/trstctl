// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"context"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/store"
)

// auditLimit bounds the audit references one record cites.
const auditLimit = 100

// PackLimit bounds the records an evidence pack carries.
const PackLimit = 50

// Assembler builds records from the tenant's store, its audit chain and the
// orchestrator's reading of retained issuance evidence. The API serves its
// records one at a time; evidence packs take the recent ones.
type Assembler struct {
	Store *store.Store
	Audit *audit.Service
	// Issuance resolves a certificate's retained issuance evidence; nil reads
	// none.
	Issuance func(ctx context.Context, tenantID string, cert store.Certificate) (IssuanceEvidence, error)
	Now      func() time.Time
}

// Record builds one certificate's record. A certificate outside the tenant is
// a not-found error.
func (a *Assembler) Record(ctx context.Context, tenantID, certificateID string) (Record, error) {
	evidence, err := a.Store.CredentialEvidence(ctx, tenantID, certificateID)
	if err != nil {
		return Record{}, err
	}
	cert := evidence.Certificate
	bindings, err := a.Store.CertificateIdentityBindings(ctx, tenantID, []string{cert.ID})
	if err != nil {
		return Record{}, err
	}
	in := Inputs{TenantID: tenantID, Now: a.now(), Evidence: evidence, IdentityIDs: bindings[cert.ID]}
	if a.Issuance != nil {
		if in.Issuance, err = a.Issuance(ctx, tenantID, cert); err != nil {
			return Record{}, err
		}
	}
	if in.Audit, in.AuditTruncated, err = a.auditReferences(ctx, tenantID, cert); err != nil {
		return Record{}, err
	}
	return Build(in), nil
}

// Recent builds the records of the certificates whose lifecycle changed in
// [from, through] — delivered, verified, renewed or revoked — newest first, at
// most PackLimit, and whether there were more.
func (a *Assembler) Recent(ctx context.Context, tenantID string, from, through time.Time) ([]Record, bool, error) {
	ids, truncated, err := a.Store.ListAssuranceSubjects(ctx, tenantID, from, through, PackLimit)
	if err != nil {
		return nil, false, err
	}
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		record, err := a.Record(ctx, tenantID, id)
		if err != nil {
			return nil, false, err
		}
		out = append(out, record)
	}
	return out, truncated, nil
}

func (a *Assembler) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// auditReferences are the tenant audit-chain entries that name the certificate
// by id or fingerprint, oldest first, at most auditLimit.
func (a *Assembler) auditReferences(ctx context.Context, tenantID string, cert store.Certificate) ([]AuditReference, bool, error) {
	if a.Audit == nil {
		return nil, false, nil
	}
	seen := map[uint64]bool{}
	var refs []AuditReference
	truncated := false
	for _, needle := range []string{cert.ID, cert.Fingerprint} {
		if needle == "" {
			continue
		}
		records, err := a.Audit.Search(ctx, audit.Query{TenantID: tenantID, Contains: needle, Limit: auditLimit + 1})
		if err != nil {
			return nil, false, err
		}
		if len(records) > auditLimit {
			truncated = true
		}
		for _, record := range records {
			if seen[record.Sequence] {
				continue
			}
			seen[record.Sequence] = true
			refs = append(refs, AuditReference{
				Sequence: record.Sequence, EventID: record.ID, Type: record.Type, At: record.Time.UTC(), Hash: record.Hash,
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Sequence < refs[j].Sequence })
	if len(refs) > auditLimit {
		refs, truncated = refs[:auditLimit], true
	}
	return refs, truncated, nil
}
