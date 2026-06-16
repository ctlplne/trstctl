package discovery

import (
	"context"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

// StoreSink reconciles discovered certificates into the inventory (S4.1) via an
// idempotent upsert keyed by (tenant, fingerprint): a certificate found in more
// than one place, or re-discovered on a later pass, refreshes its single row
// rather than duplicating it. The row records which source found it and where.
type StoreSink struct {
	store    *store.Store
	tenantID string
}

var _ Sink = (*StoreSink)(nil)

// NewStoreSink records discoveries for a tenant.
func NewStoreSink(s *store.Store, tenantID string) *StoreSink {
	return &StoreSink{store: s, tenantID: tenantID}
}

// Record upserts the discovered certificate's metadata into the inventory.
func (ss *StoreSink) Record(ctx context.Context, f Found) error {
	info := f.Cert
	notBefore, notAfter := info.NotBefore, info.NotAfter
	_, err := ss.store.UpsertCertificate(ctx, store.Certificate{
		TenantID:           ss.tenantID,
		Subject:            info.Subject,
		SANs:               sans(info),
		Issuer:             info.Issuer,
		Serial:             info.SerialNumber,
		Fingerprint:        info.SHA256Fingerprint,
		KeyAlgorithm:       info.KeyAlgorithm,
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		DeploymentLocation: f.Location,
		Source:             f.Source,
	})
	return err
}

// sans flattens every subject alternative name kind into one list.
func sans(info certinfo.Info) []string {
	out := make([]string, 0, len(info.DNSNames)+len(info.IPAddresses)+len(info.URIs)+len(info.EmailAddresses))
	out = append(out, info.DNSNames...)
	out = append(out, info.IPAddresses...)
	out = append(out, info.URIs...)
	out = append(out, info.EmailAddresses...)
	return out
}
