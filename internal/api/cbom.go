// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/store"
)

// CBOMService is the served CBOM worker behind the API. It scans only public
// cryptographic facts (TLS negotiation, certificate public keys, host config) and
// records observations through the event log before the read model is updated.
type CBOMService interface {
	Scan(ctx context.Context, tenantID string, req CBOMScanRequest) (CBOMScanResponse, error)
	Inventory(ctx context.Context, tenantID string) (CBOMInventoryResponse, error)
}

// WithCBOM wires the served CBOM scan + migration-inventory surface. When unset the
// routes fail closed with a clear 503 rather than pretending a scan ran.
func WithCBOM(svc CBOMService) Option {
	return func(c *config) { c.cbom = svc }
}

// CBOMScanRequest names the read-only estate slices to inspect.
type CBOMScanRequest struct {
	TLSEndpoints []string `json:"tls_endpoints"`
	HostConfigs  []string `json:"host_configs"`
}

// CBOMReport is the scan summary returned by the served worker.
type CBOMReport struct {
	Sources           int `json:"sources"`
	Findings          int `json:"findings"`
	Weak              int `json:"weak"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
	OutOfPolicy       int `json:"out_of_policy"`
	Failed            int `json:"failed"`
}

// CBOMAsset is one customer-readable crypto inventory row with migration posture.
type CBOMAsset struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	Location            string   `json:"location"`
	Algorithm           string   `json:"algorithm,omitempty"`
	KeyBits             int      `json:"key_bits,omitempty"`
	Protocol            string   `json:"protocol,omitempty"`
	Cipher              string   `json:"cipher,omitempty"`
	Library             string   `json:"library,omitempty"`
	Strength            string   `json:"strength"`
	QuantumVulnerable   bool     `json:"quantum_vulnerable"`
	OutOfPolicy         bool     `json:"out_of_policy"`
	Reasons             []string `json:"reasons,omitempty"`
	MigrationTarget     string   `json:"migration_target"`
	MigrationStandard   string   `json:"migration_standard"`
	MigrationGeneration string   `json:"migration_generation"`
}

// CBOMInventoryResponse is the read API for the CBOM plus its migration-progress
// rollup.
type CBOMInventoryResponse struct {
	Items             []CBOMAsset            `json:"items"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
}

// CBOMScanResponse is returned after a served scan completes.
type CBOMScanResponse struct {
	Report            CBOMReport             `json:"report"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
}

// CBOMInventoryFromAssets adapts store rows to the public inventory shape.
func CBOMInventoryFromAssets(assets []store.CryptoAsset) CBOMInventoryResponse {
	items := make([]CBOMAsset, 0, len(assets))
	findings := make([]cbom.Finding, 0, len(assets))
	for _, a := range assets {
		f := cbom.Finding{
			Kind: cbom.AssetKind(a.Kind), Location: a.Location, Algorithm: a.Algorithm,
			KeyBits: a.KeyBits, Protocol: a.Protocol, Cipher: a.Cipher, Library: a.Library,
			Class: cbom.Classification{
				Strength: cbom.Strength(a.Strength), QuantumVulnerable: a.QuantumVulnerable,
				OutOfPolicy: a.OutOfPolicy, Reasons: a.Reasons,
			},
		}
		target := cbom.MigrationTargetFor(f)
		items = append(items, CBOMAsset{
			ID: a.ID, Kind: a.Kind, Location: a.Location, Algorithm: a.Algorithm,
			KeyBits: a.KeyBits, Protocol: a.Protocol, Cipher: a.Cipher, Library: a.Library,
			Strength: a.Strength, QuantumVulnerable: a.QuantumVulnerable,
			OutOfPolicy: a.OutOfPolicy, Reasons: a.Reasons,
			MigrationTarget: target.Algorithm, MigrationStandard: target.Standard,
			MigrationGeneration: target.Generation,
		})
		findings = append(findings, f)
	}
	return CBOMInventoryResponse{Items: items, MigrationProgress: cbom.ProgressFor(findings)}
}

//trstctl:mutation
func (a *API) startCBOMScan(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.cbom == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "CBOM scanning is not configured")
		}
		var req CBOMScanRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.TLSEndpoints) == 0 && len(req.HostConfigs) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "CBOM scan requires at least one TLS endpoint or host config")
		}
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("cbom", "scan", start, opErr) }()
		resp, err := a.cbom.Scan(ctx, tenantID, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, resp, nil
	})
}

func (a *API) listCBOMAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.cbom == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM inventory is not configured"))
		return
	}
	resp, err := a.cbom.Inventory(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, resp)
}
