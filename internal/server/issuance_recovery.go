package server

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func recoverCertificatesByIssuanceKey(ctx context.Context, st *store.Store, log *events.Log, tenantID, key string) ([]store.Certificate, error) {
	certs, err := st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 || log == nil {
		return certs, nil
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		return nil, fmt.Errorf("server: recover issued certificate projection: %w", err)
	}
	return st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
}
