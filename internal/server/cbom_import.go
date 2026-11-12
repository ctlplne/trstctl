// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"sort"
	"strings"

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
	certificates := importedCertificates(source, bom)
	if done {
		resp.Replayed = true
		if resp.CertificateIDs, err = s.inventoryImportedCertificates(ctx, tenantID, certificates, false); err != nil {
			return api.CBOMImportResponse{}, err
		}
		return resp, nil
	}
	sink := &eventedCBOMSink{store: s.store, log: s.log, tenantID: tenantID}
	for _, f := range bom.Findings {
		if err := sink.Record(ctx, f); err != nil {
			return api.CBOMImportResponse{}, err
		}
	}
	if resp.CertificateIDs, err = s.inventoryImportedCertificates(ctx, tenantID, certificates, true); err != nil {
		return api.CBOMImportResponse{}, err
	}
	if err := s.orch.FinishCBOMImport(ctx, tenantID, resp.RunID, bom.Components, len(ids)); err != nil {
		return api.CBOMImportResponse{}, err
	}
	return resp, nil
}

// importedCertificates are the BOM's certificates that name their SHA-256
// fingerprint (X6-L6), one per fingerprint, as certificate inventory
// observations: subject, issuer, serial, key algorithm and validity as the
// BOM states them, with no certificate bytes, under source "cbom:<source>".
// A certificate without a fingerprint stays a CBOM row only.
func importedCertificates(source string, bom cbom.ImportedBOM) []store.Certificate {
	seen := map[string]bool{}
	var out []store.Certificate
	for _, f := range bom.Findings {
		c := f.Certificate
		if c == nil || c.Fingerprint == "" || seen[c.Fingerprint] {
			continue
		}
		seen[c.Fingerprint] = true
		out = append(out, store.Certificate{Subject: c.Subject, Issuer: c.Issuer, Serial: c.Serial, Fingerprint: c.Fingerprint,
			KeyAlgorithm: importedKeyAlgorithm(f), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			Source: "cbom:" + source, ObservationOnly: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

func importedKeyAlgorithm(f cbom.Finding) string {
	alg := strings.TrimSpace(f.Algorithm)
	if alg != "" && f.KeyBits > 0 && !strings.ContainsAny(alg, "0123456789") {
		return fmt.Sprintf("%s-%d", alg, f.KeyBits)
	}
	return alg
}

// inventoryImportedCertificates takes the BOM's fingerprinted certificates
// into the certificate inventory and returns their rows' IDs. A fingerprint
// the inventory already holds keeps its row exactly as it is: an issued or
// ingested certificate's owner, names, location and bytes are better facts
// than a BOM's statement about the same certificate, and recording an
// observation over them would replace them. Without record (a replayed
// import) it only looks the rows up.
func (s *cbomService) inventoryImportedCertificates(ctx context.Context, tenantID string, certificates []store.Certificate, record bool) ([]string, error) {
	ids := []string{}
	for _, c := range certificates {
		existing, err := s.store.GetCertificateByFingerprint(ctx, tenantID, c.Fingerprint)
		if err == nil {
			ids = append(ids, existing.ID)
			continue
		}
		if !store.IsNotFound(err) {
			return nil, err
		}
		if !record {
			continue
		}
		row, err := s.orch.RecordCertificate(ctx, tenantID, c)
		if err != nil {
			return nil, err
		}
		ids = append(ids, row.ID)
	}
	sort.Strings(ids)
	return ids, nil
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
