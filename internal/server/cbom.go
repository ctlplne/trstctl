// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
	"trstctl.com/trstctl/internal/cbom/tlssource"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type cbomService struct {
	store *store.Store
	log   *events.Log
}

func (s *Server) buildCBOMService(d Deps) api.CBOMService {
	return &cbomService{store: d.Store, log: d.Log}
}

func (s *cbomService) Scan(ctx context.Context, tenantID string, req api.CBOMScanRequest) (api.CBOMScanResponse, error) {
	if len(req.TLSEndpoints) == 0 && len(req.HostConfigs) == 0 {
		return api.CBOMScanResponse{}, errors.New("server: CBOM scan requires at least one TLS endpoint or host config")
	}
	sources := make([]cbom.Source, 0, 2)
	if len(req.TLSEndpoints) > 0 {
		sources = append(sources, tlssource.New(req.TLSEndpoints))
	}
	if len(req.HostConfigs) > 0 {
		sources = append(sources, hostsource.New(req.HostConfigs...))
	}
	sink := &eventedCBOMSink{store: s.store, log: s.log, tenantID: tenantID}
	scanner := cbom.NewScanner(sink, cbom.WithWorkers(4), cbom.WithQueue(64))
	defer scanner.Close()
	rep := scanner.Scan(ctx, sources)
	inv, err := s.Inventory(ctx, tenantID)
	if err != nil {
		return api.CBOMScanResponse{}, err
	}
	return api.CBOMScanResponse{
		Report: api.CBOMReport{
			Sources: rep.Sources, Findings: rep.Findings, Weak: rep.Weak,
			QuantumVulnerable: rep.QuantumVulnerable, OutOfPolicy: rep.OutOfPolicy,
			Failed: rep.Failed,
		},
		MigrationProgress: inv.MigrationProgress,
	}, nil
}

func (s *cbomService) Inventory(ctx context.Context, tenantID string) (api.CBOMInventoryResponse, error) {
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return api.CBOMInventoryResponse{}, err
	}
	return api.CBOMInventoryFromAssets(assets), nil
}

type eventedCBOMSink struct {
	store    *store.Store
	log      *events.Log
	tenantID string
}

const (
	cbomWriteAttempts = 3
	cbomWriteBackoff  = 20 * time.Millisecond
)

func retryCBOMWrite(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt < cbomWriteAttempts; attempt++ {
		if err = operation(); err == nil {
			return nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || attempt == cbomWriteAttempts-1 {
			return err
		}
		timer := time.NewTimer(cbomWriteBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (s *eventedCBOMSink) Record(ctx context.Context, f cbom.Finding) error {
	if s.log == nil || s.store == nil {
		return errors.New("server: CBOM sink requires store and event log")
	}
	asset := store.CryptoAsset{
		TenantID: s.tenantID, Kind: string(f.Kind), Location: f.Location,
		Algorithm: f.Algorithm, KeyBits: f.KeyBits, Protocol: f.Protocol,
		Cipher: f.Cipher, Library: f.Library, Strength: string(f.Class.Strength),
		QuantumVulnerable: f.Class.QuantumVulnerable, OutOfPolicy: f.Class.OutOfPolicy,
		Reasons: f.Class.Reasons,
	}
	asset.ID = store.StableCryptoAssetID(asset.TenantID, asset.Signature())
	payload := projections.CBOMAssetObserved{
		ID: asset.ID, Kind: asset.Kind, Location: asset.Location, Algorithm: asset.Algorithm,
		KeyBits: asset.KeyBits, Protocol: asset.Protocol, Cipher: asset.Cipher,
		Library: asset.Library, Strength: asset.Strength, QuantumVulnerable: asset.QuantumVulnerable,
		OutOfPolicy: asset.OutOfPolicy, Reasons: asset.Reasons,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("server: encode CBOM asset event: %w", err)
	}
	// Pin one event ID across retries. If JetStream committed the first publish but
	// its acknowledgement was lost, the retry is duplicate-suppressed and returns
	// the canonical immutable event instead of adding a second observation.
	event := events.Event{ID: events.NewID(), Type: projections.EventCBOMAssetObserved, TenantID: s.tenantID, Data: data}
	var stored events.Event
	if err := retryCBOMWrite(ctx, func() error {
		var appendErr error
		stored, appendErr = s.log.Append(ctx, event)
		return appendErr
	}); err != nil {
		return fmt.Errorf("server: append CBOM asset event: %w", err)
	}
	// Project the exact canonical event for read-your-write API responses. The tail
	// worker can apply it concurrently or later; the projection is idempotent by the
	// tenant-scoped asset signature. Retrying this step never appends another event.
	if err := retryCBOMWrite(ctx, func() error { return projections.New(s.store).Apply(ctx, stored) }); err != nil {
		return fmt.Errorf("server: project CBOM asset event: %w", err)
	}
	return nil
}
