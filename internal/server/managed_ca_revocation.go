// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// managedCARevocationService binds one tenant and immutable authority ID to the
// same signed CRL/OCSP implementation as the built-in CA. A rotation does not
// redirect predecessor revocations to the successor: both keep their own serial
// ledger, signing key, responder and publication URL.
func (s *Server) managedCARevocationService(ctx context.Context, tenantID, caID string, provision bool) (*revocationService, error) {
	if s.caHierarchy == nil || s.signer == nil || s.signer.Client() == nil {
		return nil, api.ErrCAHierarchyUnavailable
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, pgx.ErrNoRows
	}
	if _, err := uuid.Parse(caID); err != nil {
		return nil, pgx.ErrNoRows
	}
	key := tenantID + "/" + caID
	s.managedRevocMu.RLock()
	cached := s.managedRevocs[key]
	s.managedRevocMu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	authority, err := s.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return nil, err
	}
	if authority.SignerHandle == "" {
		return nil, api.ErrCAHierarchyUnavailable
	}
	issuerDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return nil, err
	}
	caSigner, err := s.caHierarchy.signerForAuthority(ctx, authority)
	if err != nil {
		return nil, err
	}
	var ocspSigner crypto.DigestSigner
	if provision {
		ocspSigner, err = s.provisionOCSPResponderSigner(ctx, s.signer.Client(), caID)
	} else {
		// Anonymous status reads must not create signer key handles. The first
		// issuance outbox intent or the trusted scheduler provisions this one.
		ocspSigner, err = s.signer.Client().SignerForHandleWithPurpose(ctx, ocspResponderHandlePrefix+caID, signing.PurposeGeneric)
	}
	if err != nil {
		return nil, fmt.Errorf("server: managed CA OCSP signer: %w", err)
	}
	service := newRevocationService(s.store, s.log, caID, caSigner, issuerDER, ocspSigner)
	if service == nil {
		return nil, api.ErrCAHierarchyUnavailable
	}
	if s.revoc != nil {
		service.ocspMetrics = s.revoc.ocspMetrics
	}
	s.managedRevocMu.Lock()
	if s.managedRevocs == nil {
		s.managedRevocs = make(map[string]*revocationService)
	}
	if cached = s.managedRevocs[key]; cached == nil {
		s.managedRevocs[key] = service
		cached = service
	}
	s.managedRevocMu.Unlock()
	return cached, nil
}

func (s *Server) publishManagedAuthorityCRL(ctx context.Context, tenantID, caID string) error {
	service, err := s.managedCARevocationService(ctx, tenantID, caID, true)
	if err != nil {
		return err
	}
	// The trusted event projection committed both the certificate and issuer
	// ledger before the outbox intent. Never replay unrelated projections on the
	// delivery worker's deadline.
	if _, err := service.generateCRLFromCurrentProjection(ctx, tenantID); err != nil {
		return err
	}
	_, err = service.activeOCSPResponder(ctx, tenantID)
	return err
}

func (s *Server) regenerateDueManagedCRLs(ctx context.Context) (int, error) {
	if s.caHierarchy == nil {
		return 0, nil
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, tenant := range tenants {
		ids, err := s.store.ManagedCAAuthoritiesWithIssuedCerts(ctx, tenant.TenantID)
		if err != nil {
			return count, err
		}
		for _, caID := range ids {
			due, err := s.store.CRLDueForRegeneration(ctx, tenant.TenantID, caID, time.Now(), crlRefreshLead)
			if err != nil {
				return count, err
			}
			if !due {
				continue
			}
			if err := s.publishManagedAuthorityCRL(ctx, tenant.TenantID, caID); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

func (s *Server) managedCARoutes(mux *http.ServeMux) {
	if s.caHierarchy == nil {
		return
	}
	wrap := func(handler func(*revocationService) http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			service, err := s.managedCARevocationService(r.Context(), r.PathValue("tenant"), r.PathValue("ca"), false)
			if err != nil {
				if store.IsNotFound(err) {
					http.NotFound(w, r)
					return
				}
				if errors.Is(err, api.ErrCAHierarchyUnavailable) {
					http.Error(w, "revocation: authority is unavailable", http.StatusServiceUnavailable)
					return
				}
				http.Error(w, "revocation: authority cannot serve status", http.StatusBadGateway)
				return
			}
			handler(service)(w, r)
		}
	}
	mux.HandleFunc("POST /ocsp/{tenant}/authorities/{ca}", wrap((*revocationService).ocspHandler))
	mux.HandleFunc("GET /ocsp/{tenant}/authorities/{ca}/{b64request}", wrap((*revocationService).ocspHandler))
	mux.HandleFunc("GET /crl/{tenant}/authorities/{ca}/manifest.json", wrap((*revocationService).crlManifestHandler))
	mux.HandleFunc("GET /crl/{tenant}/authorities/{ca}/shards/{shard}", wrap((*revocationService).crlShardHandler))
	mux.HandleFunc("GET /crl/{tenant}/authorities/{ca}/delta/{base}", wrap((*revocationService).crlDeltaHandler))
	mux.HandleFunc("GET /crl/{tenant}/authorities/{ca}", wrap((*revocationService).crlHandler))
}
