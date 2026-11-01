// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/cbom/coverage"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CycloneDX CBOM imports (X6). Each import is a discovery run of a source
// named after what produced the BOM, so coverage knows when vendor, source and
// image CBOMs were last taken in. The run ID is derived from the tenant, the
// source and the BOM's serial number and version: importing the same BOM again
// finds its finished run and writes nothing.

var (
	cbomImportSourceNamespace = uuid.MustParse("6b7c0f2e-3c1a-5d84-9e42-7a1f0b3c2d5e")
	cbomImportRunNamespace    = uuid.MustParse("0c9e2a71-8d4b-5f36-a1e7-4b2c6d8e9f10")
)

// CBOMImportSourceKind maps an import source to its discovery source kind:
// vendor:… a vendor-published CBOM, source:… a source-code scan, image:… an
// image or directory scan.
func CBOMImportSourceKind(source string) (string, error) {
	switch prefix, _, _ := strings.Cut(source, ":"); prefix {
	case "vendor":
		return coverage.ImportVendorKind, nil
	case "source":
		return coverage.ImportSourceKind, nil
	case "image":
		return coverage.ImportImageKind, nil
	}
	return "", fmt.Errorf("orchestrator: import source %q has no vendor, source or image prefix", source)
}

// CBOMImportRunID is the run an import of this BOM records.
func CBOMImportRunID(tenantID, source, serialNumber string, version int, digest string) string {
	identity := serialNumber
	if identity == "" {
		identity = "sha256:" + digest // a BOM without a serial number is identified by its bytes
	}
	return uuid.NewSHA1(cbomImportRunNamespace, []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", tenantID, source, identity, version))).String()
}

// BeginCBOMImport records the import's source and starts its run. It reports
// done when the run already finished, in which case nothing is written.
func (o *Orchestrator) BeginCBOMImport(ctx context.Context, tenantID, source, runID string, components int) (run store.DiscoveryRun, done bool, err error) {
	kind, err := CBOMImportSourceKind(source)
	if err != nil {
		return store.DiscoveryRun{}, false, err
	}
	if existing, err := o.store.GetDiscoveryRun(ctx, tenantID, runID); err == nil {
		switch existing.Status {
		case "succeeded", "partial", "failed":
			return existing, true, nil
		}
		return existing, false, nil // an interrupted import finishes now
	} else if !store.IsNotFound(err) {
		return store.DiscoveryRun{}, false, err
	}
	sourceID := uuid.NewSHA1(cbomImportSourceNamespace, []byte(tenantID+"\x00"+source)).String()
	cfg, err := json.Marshal(map[string]any{"source": source, "components": components})
	if err != nil {
		return store.DiscoveryRun{}, false, err
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: kind, Name: sourcecatalog.CBOMImportSourcePrefix + source, Config: cfg,
	}); err != nil {
		return store.DiscoveryRun{}, false, err
	}
	requestedBy := "api:cbom-import"
	if actor, ok := events.ActorFromContext(ctx); ok && strings.TrimSpace(actor.Subject) != "" {
		requestedBy = actor.Subject
	}
	payload, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: requestedBy})
	if err != nil {
		return store.DiscoveryRun{}, false, err
	}
	if _, err := o.emit(ctx, projections.EventDiscoveryRunQueued, tenantID, payload); err != nil {
		return store.DiscoveryRun{}, false, err
	}
	if err := o.StartDiscoveryRun(ctx, tenantID, runID); err != nil {
		return store.DiscoveryRun{}, false, err
	}
	return store.DiscoveryRun{ID: runID, TenantID: tenantID, SourceID: sourceID, Status: "running", RequestedBy: requestedBy}, false, nil
}

// FinishCBOMImport completes the import's run with what it recorded.
func (o *Orchestrator) FinishCBOMImport(ctx context.Context, tenantID, runID string, components, recorded int) error {
	return o.CompleteDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
		ID: runID, Status: "succeeded", Targets: components, Discovered: recorded,
	})
}
