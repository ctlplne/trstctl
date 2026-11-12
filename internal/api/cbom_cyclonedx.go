// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	gouuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// The crypto inventory as a CycloneDX 1.6 CBOM (Q3): one signed document
// scanners and agencies can ingest, mapped from the same inventory
// GET /api/v1/cbom/assets serves, with the certificates, host keys, crypto
// libraries and observed handshakes beside it (Q3-L2). The audit evidence key signs the exact
// document bytes, so the export verifies offline with the published keys.

type cbomCycloneDXExportResponse struct {
	SpecVersion string          `json:"spec_version"`
	Components  int             `json:"components"`
	BOM         json.RawMessage `json:"bom"`
	BOMSHA256   string          `json:"bom_sha256"`
	SignedBOM   string          `json:"signed_bom"`
	PublicJWKS  json.RawMessage `json:"public_jwks"`
}

// CBOMExportSupplementer adds to the CycloneDX export what the CBOM
// inventory does not hold (Q3-L2): the certificates the certificate
// inventory holds for its certificate keys, and the host keys, crypto
// libraries and observed handshakes agents reported.
type CBOMExportSupplementer interface {
	CycloneDXSupplement(ctx context.Context, tenantID string, assets []cbom.CycloneDXAsset) (cbom.CycloneDXSupplement, error)
}

func (a *API) cbomCycloneDXRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/cbom/export/cyclonedx", opID: "exportCBOMCycloneDX",
			summary: "Export the crypto inventory as a signed CycloneDX 1.6 CBOM",
			handler: a.exportCBOMCycloneDX, resSchema: "CBOMCycloneDXExport", successCode: "200", perm: authz.RiskRead},
	}
}

func (a *API) exportCBOMCycloneDX(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.cbom == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM inventory is not configured"))
		return
	}
	if a.pqcCampaignSigner == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM export signing is not configured"))
		return
	}
	inventory, err := a.cbom.Inventory(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	assets := make([]cbom.CycloneDXAsset, 0, len(inventory.Items))
	for _, item := range inventory.Items {
		assets = append(assets, cbom.CycloneDXAsset{
			ID: item.ID, Kind: item.Kind, Location: item.Location, Algorithm: item.Algorithm, KeyBits: item.KeyBits,
			Protocol: item.Protocol, Cipher: item.Cipher, Library: item.Library, CertificateFingerprint: item.CertificateFingerprint,
			Strength: item.Strength, QuantumVulnerable: item.QuantumVulnerable, OutOfPolicy: item.OutOfPolicy,
			Reasons: item.Reasons, MigrationTarget: item.MigrationTarget,
		})
	}
	var extra cbom.CycloneDXSupplement
	if supplementer, ok := a.cbom.(CBOMExportSupplementer); ok {
		if extra, err = supplementer.CycloneDXSupplement(r.Context(), tenantID, assets); err != nil {
			a.writeError(w, err)
			return
		}
	}
	document := cbom.CycloneDXWith(assets, extra, cbom.CycloneDXMeta{
		SerialUUID: gouuid.NewString(), GeneratedAt: time.Now().UTC(), ToolVersion: buildinfo.Version(),
	})
	bom, err := json.Marshal(document)
	if err != nil {
		a.writeError(w, err)
		return
	}
	signed, err := a.pqcCampaignSigner.SignArtifact(jose.ArtifactCBOMCycloneDX, bom)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "sign the CBOM export: "+err.Error()))
		return
	}
	jwks, err := a.pqcCampaignSigner.PublicJWKS()
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "publish the CBOM export verifier: "+err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, cbomCycloneDXExportResponse{
		SpecVersion: cbom.CycloneDXSpecVersion, Components: len(document.Components), BOM: bom,
		BOMSHA256: "sha256:" + crypto.SHA256Hex(bom), SignedBOM: signed, PublicJWKS: json.RawMessage(jwks),
	})
}
