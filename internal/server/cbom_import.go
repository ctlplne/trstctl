// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"sort"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Import records an imported CBOM (X6): its assets through the same evented
// sink scans use, inside a discovery run keyed by the BOM's identity, so a
// second import of the same BOM finds the finished run and writes nothing.
func (s *cbomService) Import(ctx context.Context, tenantID, source string, bom cbom.ImportedBOM, digest string) (api.CBOMImportResponse, error) {
	resp := api.CBOMImportResponse{
		Source: source, SerialNumber: bom.SerialNumber, Version: bom.Version,
		Components: bom.Components, Findings: len(bom.Findings),
	}
	ids := map[string]bool{}
	for _, f := range bom.Findings {
		ids[cbomAssetFor(tenantID, f).ID] = true
	}
	for id := range ids {
		resp.AssetIDs = append(resp.AssetIDs, id)
	}
	sort.Strings(resp.AssetIDs)
	resp.RunID = orchestrator.CBOMImportRunID(tenantID, source, bom.SerialNumber, bom.Version, digest)
	_, done, err := s.orch.BeginCBOMImport(ctx, tenantID, source, resp.RunID, bom.Components)
	if err != nil {
		return api.CBOMImportResponse{}, err
	}
	if done {
		resp.Replayed = true
		return resp, nil
	}
	sink := &eventedCBOMSink{store: s.store, log: s.log, tenantID: tenantID}
	for _, f := range bom.Findings {
		if err := sink.Record(ctx, f); err != nil {
			return api.CBOMImportResponse{}, err
		}
	}
	if err := s.orch.FinishCBOMImport(ctx, tenantID, resp.RunID, bom.Components, len(ids)); err != nil {
		return api.CBOMImportResponse{}, err
	}
	return resp, nil
}

// cbomAssetFor is the inventory row a finding becomes; Record and Import
// derive the same stable ID from it.
func cbomAssetFor(tenantID string, f cbom.Finding) store.CryptoAsset {
	asset := store.CryptoAsset{
		TenantID: tenantID, Kind: string(f.Kind), Location: f.Location, CertificateFingerprint: f.CertificateFingerprint,
		Algorithm: f.Algorithm, KeyBits: f.KeyBits, Protocol: f.Protocol,
		Cipher: f.Cipher, Library: f.Library, Strength: string(f.Class.Strength),
		QuantumVulnerable: f.Class.QuantumVulnerable, OutOfPolicy: f.Class.OutOfPolicy,
		Reasons: f.Class.Reasons,
	}
	asset.ID = store.StableCryptoAssetID(asset.TenantID, asset.Signature())
	return asset
}
