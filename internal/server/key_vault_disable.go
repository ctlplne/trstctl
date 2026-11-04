// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudcert/kvdisable"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Key Vault disables (N2), on the server side. The vault's network settings and
// its write credential come from the Key Vault discovery source that covers
// the certificate's vault; discovery itself stays read-only.

// keyVaultWriteRoute is the covering discovery source's vault configuration.
type keyVaultWriteRoute struct {
	SourceID string
	Provider cloudCertificateProviderConfig
}

// keyVaultWriteRouteFor finds the cloud certificate discovery source of this
// tenant that covers the vault of resourceID and names a write credential.
func keyVaultWriteRouteFor(ctx context.Context, st *store.Store, tenantID, resourceID string) (keyVaultWriteRoute, error) {
	target, err := kvdisable.ParseCertificateID(resourceID)
	if err != nil {
		return keyVaultWriteRoute{}, err
	}
	sources, err := st.ListDiscoverySourcesOfKind(ctx, tenantID, "cloud_certificate")
	if err != nil {
		return keyVaultWriteRoute{}, err
	}
	for _, src := range sources {
		var cfg cloudCertificateDiscoveryConfig
		if json.Unmarshal(src.Config, &cfg) != nil {
			continue
		}
		for _, p := range cfg.Providers {
			if p.Provider != "azure-keyvault" || strings.TrimSpace(p.WriteTokenRef) == "" {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(p.VaultURL))
			if err == nil && "https://"+strings.ToLower(u.Host) == target.VaultURL {
				return keyVaultWriteRoute{SourceID: src.ID, Provider: p}, nil
			}
		}
	}
	return keyVaultWriteRoute{}, fmt.Errorf("%w: no Key Vault discovery source for %s names a write_token_ref", errKeyVaultNoWriteRoute, target.VaultURL)
}

var errKeyVaultNoWriteRoute = errors.New("key vault write route unavailable")

// keyVaultDisableClient builds the client a disable calls the vault with: the
// same egress-guarded client cloud discovery uses. Tests replace it to trust a
// vault double's certificate.
var keyVaultDisableClient = cloudHTTPClient

// handleKeyVaultDisable runs one queued disable: the covering source's network
// settings and write credential, the exact version, and the vault's readback.
func (d *issuanceDispatcher) handleKeyVaultDisable(ctx context.Context, m orchestrator.Message) error {
	var job orchestrator.KeyVaultDisableJob
	if err := decodeStrictJSON(m.Payload, &job); err != nil {
		return fmt.Errorf("server: decode Key Vault disable: %w", err)
	}
	route, err := keyVaultWriteRouteFor(ctx, d.store, m.TenantID, job.ResourceID)
	if err != nil {
		return err
	}
	if route.SourceID != job.SourceID {
		return errors.New("server: the Key Vault discovery source covering this vault changed since the request")
	}
	target, err := kvdisable.ParseCertificateID(job.ResourceID)
	if err != nil {
		return err
	}
	client, err := keyVaultDisableClient(target.VaultURL, route.Provider.AllowPrivateEndpoint, route.Provider.PrivateEgressCIDRs)
	if err != nil {
		return err
	}
	token, err := resolveDiscoveryCredentialRef(ctx, route.Provider.WriteTokenRef)
	if err != nil {
		return fmt.Errorf("resolve write_token_ref: %w", err)
	}
	result, err := kvdisable.Disable(ctx, kvdisable.Config{Token: cloudcert.StaticToken(token), HTTPClient: client}, target)
	if err != nil {
		return err
	}
	disabled := projections.KeyVaultDisabled{ID: job.ID}
	if !result.Updated.IsZero() {
		updated := result.Updated
		disabled.VaultUpdatedAt = &updated
	}
	return d.orch.RecordKeyVaultDisabled(ctx, m.TenantID, disabled)
}

// RequestKeyVaultDisable queues a disable of the certificate version an
// inventory row was found as in Key Vault.
func (s *Server) RequestKeyVaultDisable(ctx context.Context, tenantID, requester, certificateID, reason, command string) (store.KeyVaultDisable, error) {
	cert, err := s.store.GetCertificate(ctx, tenantID, certificateID)
	if err != nil {
		return store.KeyVaultDisable{}, err
	}
	if cert.Source != "cloud-azure-keyvault" {
		return store.KeyVaultDisable{}, api.ErrKeyVaultDisableNotKeyVault
	}
	route, err := keyVaultWriteRouteFor(ctx, s.store, tenantID, cert.DeploymentLocation)
	switch {
	case errors.Is(err, errKeyVaultNoWriteRoute):
		return store.KeyVaultDisable{}, api.ErrKeyVaultDisableNoRoute
	case err != nil:
		return store.KeyVaultDisable{}, fmt.Errorf("%w (%v)", api.ErrKeyVaultDisableNotKeyVault, err)
	}
	id := orchestrator.KeyVaultDisableID(tenantID, command)
	if err := s.orch.QueueKeyVaultDisable(ctx, tenantID, projections.KeyVaultDisableRequested{ID: id, CertificateID: cert.ID,
		ResourceID: cert.DeploymentLocation, SourceID: route.SourceID, Reason: reason, RequestedBy: requester}); err != nil {
		return store.KeyVaultDisable{}, err
	}
	return s.store.GetKeyVaultDisable(ctx, tenantID, id)
}
