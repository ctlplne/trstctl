// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

// maxArchiveObjectBytes bounds the read-back of one archived segment: a
// compact JWS over at most maxArchiveSigningPayloadBytes of payload.
const maxArchiveObjectBytes = 4 << 20

// ObjectArchiver writes each segment to the object store under the tenant's
// object prefix as audit/audit-<boundarySeq>.jws. The object is created once,
// with its SHA-256, then read back and verified before Archive returns, so the
// checkpoint advances only over a segment the store actually holds. The uri is
// the object's s3:// locator, the same for a tenant and boundary on every
// attempt, and it is recorded in the audit.archived event rather than derived
// again later.
type ObjectArchiver struct {
	Store objectstore.Store
	// Verify checks a signed segment against the deployment's audit
	// verification keys and returns its bundle.
	Verify func(signed string) (audit.Bundle, error)
}

// Archive writes the signed bundle and returns its locator.
func (a ObjectArchiver) Archive(ctx context.Context, tenantID string, boundarySeq uint64, signedBundle string) (string, error) {
	if a.Store == nil || a.Verify == nil {
		return "", errors.New("audit: the object archive is not configured")
	}
	want, err := a.Verify(signedBundle)
	if err != nil {
		return "", fmt.Errorf("audit: segment to archive does not verify: %w", err)
	}
	if want.TenantID != tenantID {
		return "", errors.New("audit: segment to archive names another tenant")
	}
	view, err := objectstore.ForTenant(ctx, a.Store, tenantID)
	if err != nil {
		return "", err
	}
	data := []byte(signedBundle)
	name, err := view.Create(ctx, fmt.Sprintf("audit/audit-%020d.jws", boundarySeq), bytes.NewReader(data), int64(len(data)), crypto.SHA256Sum(data))
	if err != nil && !errors.Is(err, objectstore.ErrExists) {
		return "", fmt.Errorf("audit: write archive segment: %w", err)
	}
	// Verify what the store holds. After a crash between this write and the
	// audit.archived event the object is the earlier attempt's: a fresh
	// signature over the same records differs byte-wise, but it must cover
	// exactly the same segment, or the checkpoint does not advance.
	var stored bytes.Buffer
	if _, err := a.Store.Get(ctx, name, &stored, maxArchiveObjectBytes); err != nil {
		return "", fmt.Errorf("audit: read back archive segment %s: %w", a.Store.Location(name), err)
	}
	got, err := a.Verify(stored.String())
	if err != nil {
		return "", fmt.Errorf("audit: archive segment %s does not verify: %w", a.Store.Location(name), err)
	}
	if got.TenantID != want.TenantID || got.PrevHash != want.PrevHash || got.ChainHead != want.ChainHead || got.Count != want.Count {
		return "", fmt.Errorf("audit: %s holds a different segment; the checkpoint does not advance", a.Store.Location(name))
	}
	return a.Store.Location(name), nil
}
