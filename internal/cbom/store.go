package cbom

import (
	"context"

	"trstctl.com/trstctl/internal/store"
)

// StoreSink reconciles classified findings into the crypto_assets inventory —
// the persisted CBOM (F52), idempotent by signature. Tenant-scoped per AN-1.
type StoreSink struct {
	store    *store.Store
	tenantID string
}

var _ Sink = (*StoreSink)(nil)

// NewStoreSink records findings for a tenant.
func NewStoreSink(s *store.Store, tenantID string) *StoreSink {
	return &StoreSink{store: s, tenantID: tenantID}
}

// Record upserts the classified finding into the CBOM.
func (ss *StoreSink) Record(ctx context.Context, f Finding) error {
	_, err := ss.store.UpsertCryptoAsset(ctx, store.CryptoAsset{
		TenantID:          ss.tenantID,
		Kind:              string(f.Kind),
		Location:          f.Location,
		Algorithm:         f.Algorithm,
		KeyBits:           f.KeyBits,
		Protocol:          f.Protocol,
		Cipher:            f.Cipher,
		Library:           f.Library,
		Strength:          string(f.Class.Strength),
		QuantumVulnerable: f.Class.QuantumVulnerable,
		OutOfPolicy:       f.Class.OutOfPolicy,
		Reasons:           f.Class.Reasons,
	})
	return err
}
