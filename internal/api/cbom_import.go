// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto"
)

// CycloneDX CBOM import (X6). A vendor-published CBOM, a source-code scan's
// or an image scan's merges into the crypto inventory with its source
// recorded; importing the same BOM again changes nothing.

// CBOMImportResponse says what an import took in.
type CBOMImportResponse struct {
	RunID        string   `json:"run_id"`
	Source       string   `json:"source"`
	SerialNumber string   `json:"serial_number,omitempty"`
	Version      int      `json:"version"`
	Components   int      `json:"components"`
	Findings     int      `json:"findings"`
	AssetIDs     []string `json:"asset_ids"`
	// Replayed is true when this BOM was imported before; nothing was written.
	Replayed bool `json:"replayed"`
}

// CBOMImporter is the served import, implemented beside the scan service.
type CBOMImporter interface {
	Import(ctx context.Context, tenantID, source string, bom cbom.ImportedBOM, digest string) (CBOMImportResponse, error)
}

// maxCBOMImportBytes bounds one imported document. The import reads its own
// body under this limit: the shared mutation recorder's 1 MiB cap would refuse
// an ordinary image scan's CBOM (a small Alpine image's is about 6 MiB).
const maxCBOMImportBytes = 32 << 20

func (a *API) cbomImportRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/cbom/imports", opID: "importCBOM",
			summary: "Import a CycloneDX CBOM (a vendor's, a source scan's or an image scan's) into the crypto inventory; the same BOM again changes nothing",
			handler: a.importCBOM, query: []param{{name: "source", typ: "string", desc: "vendor:<name>, source:<repository> or image:<reference>"}},
			reqSchema: "CBOMImportDocument", resSchema: "CBOMImport", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
	}
}

//trstctl:mutation
func (a *API) importCBOM(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCBOMImportBytes+1))
	_ = r.Body.Close()
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "failed to read the CBOM"))
		return
	}
	if len(raw) > maxCBOMImportBytes {
		a.writeError(w, errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("a CBOM import is at most %d bytes", maxCBOMImportBytes)))
		return
	}
	// The binding replaces the recorder's own, so its 1 MiB cap does not apply:
	// the key binds this caller, this source and this exact document.
	binding := "cbom-import:v1:" + crypto.SHA256Hex([]byte(principal)) + ":" + crypto.SHA256Hex([]byte(r.URL.Query().Get("source"))) + ":" + crypto.SHA256Hex(raw)
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		importer, ok := a.cbom.(CBOMImporter)
		if a.cbom == nil || !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "CBOM import is not configured")
		}
		var doc json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "the CBOM is not a JSON document")
		}
		source := strings.TrimSpace(r.URL.Query().Get("source"))
		if !strings.HasPrefix(source, "vendor:") && !strings.HasPrefix(source, "source:") && !strings.HasPrefix(source, "image:") {
			return 0, nil, errStatus(http.StatusBadRequest, "source must start with vendor:, source: or image:")
		}
		bom, err := cbom.ParseCycloneDXImport(doc, source, cbom.DefaultPolicy())
		if err != nil {
			return 0, nil, errStatusFrom(http.StatusBadRequest, err)
		}
		resp, err := importer.Import(ctx, tenantID, source, bom, crypto.SHA256Hex(doc))
		if err != nil {
			return 0, nil, err
		}
		if resp.Replayed {
			return http.StatusOK, resp, nil
		}
		return http.StatusCreated, resp, nil
	})
}
