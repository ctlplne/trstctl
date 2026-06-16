package cloudcert

import (
	"context"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

// StoreSink reconciles cloud-discovered certificates into the inventory (S4.1),
// idempotently by fingerprint. The cloud resource id becomes the certificate's
// deployment location, so the credential graph (S6.4) places it on a resource
// just like a scan- or agent-discovered cert. Tenant-scoped per AN-1.
type StoreSink struct {
	store    *store.Store
	tenantID string
}

var _ Sink = (*StoreSink)(nil)

// NewStoreSink records discoveries for a tenant.
func NewStoreSink(s *store.Store, tenantID string) *StoreSink {
	return &StoreSink{store: s, tenantID: tenantID}
}

// Record upserts the discovered certificate into the inventory.
func (ss *StoreSink) Record(ctx context.Context, f Found) error {
	info := f.Cert
	notBefore, notAfter := info.NotBefore, info.NotAfter
	location := f.ResourceID
	if location == "" {
		location = f.Location
	}
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
		DeploymentLocation: location,
		Source:             "cloud-" + f.Provider,
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
