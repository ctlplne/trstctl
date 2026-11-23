// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
)

// DirectiveRevocationReader reads the tenant-scoped AGID projection in the control
// plane. A directive continues to revoke its subject after cascade terminal. The
// per-subject read covers freshly signed hops that have no projection row yet.
// This package is never linked into the isolated signer (AN-4): the signer holds
// only narrow interfaces and obtains any online authorization through its transport.
type DirectiveRevocationReader struct {
	repo *agidstore.Repo
	// ctx is the context the per-hop reads run under. The gate's RevocationReader
	// interface (IsRevoked) takes no context (it is a signer-facing, deadline-free
	// hot-path read), so the control-plane reader carries one it was constructed with;
	// production supplies a request/background context, tests supply context.Background.
	ctx context.Context
}

// NewDirectiveRevocationReader builds the directive-backed reader over the AGID-02 repo,
// carrying ctx for its reads. repo is required; ctx defaults to context.Background when
// nil so a misconfigured reader still runs (fail-closed reads, never a nil-context panic).
func NewDirectiveRevocationReader(repo *agidstore.Repo, ctx context.Context) *DirectiveRevocationReader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &DirectiveRevocationReader{repo: repo, ctx: ctx}
}

// IsRevoked checks an indexed record's parties. An unindexed record returns false;
// the caller must also check its signed subject IDs with IsSubjectRevoked.
func (d *DirectiveRevocationReader) IsRevoked(tenantID string, recordDigest []byte) (bool, error) {
	if d == nil || d.repo == nil {
		// Fail closed: an unconfigured reader reports "revoked" so the gate refuses rather
		// than silently approving under a broken revocation view.
		return true, errNoRevocationRepo
	}
	return d.repo.RecordDigestUnderRevocationDirective(d.ctx, tenantID, recordDigest)
}

// IsSubjectRevoked checks an identity directly, including when its newly signed
// delegation record has not yet been projected. Read errors refuse issuance.
func (d *DirectiveRevocationReader) IsSubjectRevoked(tenantID, subjectID string) (bool, error) {
	if d == nil || d.repo == nil {
		return true, errNoRevocationRepo
	}
	return d.repo.SubjectHasRevocationDirective(d.ctx, tenantID, subjectID)
}

// IsKeyRevoked derives key bindings from already-issued signed envelopes. It
// catches a revoked subject that reuses its key under a new textual identity.
// Malformed retained evidence fails closed instead of silently losing a key.
func (d *DirectiveRevocationReader) IsKeyRevoked(tenantID string, keyThumbprint []byte) (bool, error) {
	if d == nil || d.repo == nil {
		return true, errNoRevocationRepo
	}
	if len(keyThumbprint) == 0 {
		return true, errors.New("revoke: empty delegator key thumbprint")
	}
	records, err := d.repo.RevokedSubjectRecords(d.ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, row := range records {
		var env delegation.RecordEnvelope
		if err := json.Unmarshal(row.Encoded, &env); err != nil || env.Record.TenantID != tenantID ||
			env.Record.DelegatorID != row.DelegatorID || env.Record.DelegateID != row.DelegateID {
			return false, fmt.Errorf("revoke: malformed retained delegation envelope for revoked subject %q", row.SubjectID)
		}
		if row.SubjectID == row.DelegatorID && bytes.Equal(delegation.DelegateKeyThumbprintOf(env.DelegatorPublicDER), keyThumbprint) {
			return true, nil
		}
		if row.SubjectID == row.DelegateID && bytes.Equal(env.Record.DelegateKeyThumbprint, keyThumbprint) {
			return true, nil
		}
	}
	return false, nil
}

// errNoRevocationRepo is returned by a nil/unconfigured DirectiveRevocationReader so the
// gate's fail-closed reader-error path refuses (CheckRevocation) rather than approving.
var errNoRevocationRepo = revocationConfigError("revoke: directive revocation reader has no store (fail-closed)")

// revocationConfigError is a tiny error type so the fail-closed sentinel needs no fmt
// import here and reads clearly at the call site.
type revocationConfigError string

func (e revocationConfigError) Error() string { return string(e) }
