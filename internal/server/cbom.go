// SPDX-License-Identifier: BUSL-1.1

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
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
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

const (
	cbomWorkerLimit = 4
	cbomQueueDepth  = 64
)

func (s *cbomService) Preview(_ context.Context, _ string, req api.CBOMScanRequest) (api.CBOMScanPreview, error) {
	return s.plan(req)
}

func (s *cbomService) plan(req api.CBOMScanRequest) (api.CBOMScanPreview, error) {
	normalized, err := api.NormalizeCBOMScanRequest(req)
	if err != nil {
		return api.CBOMScanPreview{}, err
	}
	sourceCount := 0
	findingWriteLimit := 0
	outsideCalls := []string{}
	hostReads := []string{}
	hostFileReadLimit := 0
	hostFileByteLimit := int64(0)
	if len(normalized.TLSEndpoints) > 0 {
		sourceCount++
		findingWriteLimit += min(len(normalized.TLSEndpoints)*2, cbom.DefaultMaxFindingsPerSource)
		outsideCalls = append(outsideCalls,
			fmt.Sprintf("Open at most %d TLS connections: one handshake to each normalized endpoint, with no application request or payload.", len(normalized.TLSEndpoints)))
	}
	if len(normalized.HostConfigs) > 0 {
		sourceCount++
		findingWriteLimit += cbom.DefaultMaxFindingsPerSource
		hostFileReadLimit = hostsource.DefaultMaxFiles
		hostFileByteLimit = hostsource.DefaultMaxFileBytes
		hostReads = append(hostReads,
			fmt.Sprintf("Resolve %d declared absolute path or glob selector(s), then read at most %d matching files and %d bytes per file.", len(normalized.HostConfigs), hostFileReadLimit, hostFileByteLimit))
	}
	blockers := []string{}
	if s.store == nil || s.log == nil {
		blockers = append(blockers, "The tenant-scoped CBOM store and immutable event log must be attached before a scan can run.")
	}
	return api.CBOMScanPreview{
		Capability: "F52", Ready: len(blockers) == 0, EffectFree: true,
		NormalizedRequest: normalized, SourceCount: sourceCount,
		TLSConnectionLimit:    len(normalized.TLSEndpoints),
		HostReadSelectorCount: len(normalized.HostConfigs),
		HostFileReadLimit:     hostFileReadLimit, HostFileByteLimit: hostFileByteLimit,
		FindingWriteLimit: findingWriteLimit, WorkerLimit: cbomWorkerLimit,
		QueueDepth: cbomQueueDepth, PerEndpointTimeoutSeconds: int(tlsprobe.DefaultTimeout.Seconds()),
		OutsideCalls: outsideCalls, HostReads: hostReads,
		DurableWrites: []string{
			fmt.Sprintf("Append and project at most %d tenant-scoped cbom.asset.observed records; unreachable, unreadable, oversized, or capped inputs remain visible in the failed count.", findingWriteLimit),
		},
		SignerCalls: 0, OutboxCalls: 0, Blockers: blockers,
		RecoverySteps: []string{
			"If a target is unreachable, correct its host or port, confirm this control plane can reach it, then preview and retry only that target.",
			"If a host path is unreadable or too broad, narrow the absolute path or glob and grant read-only access; never grant write access for CBOM discovery.",
			"A partial scan keeps every successfully observed asset. Review the failed count, repair the inputs, and rerun; stable asset identities safely converge instead of multiplying rows.",
		},
		SafetyNotes: []string{
			"Preview performs no network connection, file read, event append, projection write, signer call, or outbox delivery.",
			"TLS discovery completes a handshake only and sends no HTTP or other application-layer request.",
			"Host discovery reads only explicitly declared absolute paths or globs and parses public protocol and cipher declarations; it never returns file contents.",
		},
	}, nil
}

func (s *cbomService) Scan(ctx context.Context, tenantID string, req api.CBOMScanRequest) (api.CBOMScanResponse, error) {
	plan, err := s.plan(req)
	if err != nil {
		return api.CBOMScanResponse{}, err
	}
	if !plan.Ready {
		return api.CBOMScanResponse{}, errors.New("server: CBOM scan dependencies are not ready")
	}
	sources := make([]cbom.Source, 0, 2)
	if len(plan.NormalizedRequest.TLSEndpoints) > 0 {
		sources = append(sources, tlssource.New(plan.NormalizedRequest.TLSEndpoints))
	}
	if len(plan.NormalizedRequest.HostConfigs) > 0 {
		sources = append(sources, hostsource.New(plan.NormalizedRequest.HostConfigs...))
	}
	sink := &eventedCBOMSink{store: s.store, log: s.log, tenantID: tenantID}
	scanner := cbom.NewScanner(sink,
		cbom.WithWorkers(cbomWorkerLimit), cbom.WithQueue(cbomQueueDepth),
		cbom.WithMaxFindingsPerSource(cbom.DefaultMaxFindingsPerSource))
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
	// its acknowledgment was lost, the retry is duplicate-suppressed and returns
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
