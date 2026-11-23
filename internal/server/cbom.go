// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
	"trstctl.com/trstctl/internal/cbom/tlssource"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type cbomService struct {
	nativeTLSExecutable  string
	privateEgressCeiling []string
	store                *store.Store
	log                  *events.Log
	// orch records CBOM imports as discovery runs (X6).
	orch *orchestrator.Orchestrator
	// packageDatabases decide a host-config scan's product defaults (X2-L7);
	// nil means this host's own.
	packageDatabases []string
}

func (s *Server) buildCBOMService(d Deps) api.CBOMService {
	return &cbomService{store: d.Store, log: d.Log, nativeTLSExecutable: d.CBOMTLSProbeOpenSSL, orch: s.orch,
		privateEgressCeiling: d.CBOMPrivateEgressCIDRs, packageDatabases: d.CBOMPackageDatabases}
}

const (
	cbomWorkerLimit = 4
	cbomQueueDepth  = 64
)

func (s *cbomService) Preview(_ context.Context, _ string, req api.CBOMScanRequest) (api.CBOMScanPreview, error) {
	return s.plan(req)
}

func (s *cbomService) tlsDialControl(req api.CBOMScanRequest) (func(string, string, syscall.RawConn) error, error) {
	if !req.AllowPrivateEndpoint {
		return netsec.SafeDialControl, nil
	}
	if len(s.privateEgressCeiling) == 0 {
		return nil, errors.New("CBOM private TLS egress is not enabled by the operator")
	}
	ceiling := make([]netip.Prefix, 0, len(s.privateEgressCeiling))
	for _, raw := range s.privateEgressCeiling {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("CBOM operator private egress ceiling: %w", err)
		}
		ceiling = append(ceiling, prefix)
	}
	allowed := make([]netip.Prefix, 0, len(req.PrivateEgressCIDRs))
	for _, raw := range req.PrivateEgressCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, err
		}
		contained := false
		for _, limit := range ceiling {
			if limit.Addr().Is4() == prefix.Addr().Is4() &&
				limit.Bits() <= prefix.Bits() && limit.Contains(prefix.Addr()) {
				contained = true
				break
			}
		}
		if !contained {
			return nil, errors.New("CBOM private_egress_cidrs exceeds the operator ceiling")
		}
		allowed = append(allowed, prefix)
	}
	return netsec.SafeDialControlWithOptions(netsec.SafeClientOptions{AllowPrivateCIDRs: allowed}), nil
}

func (s *cbomService) plan(req api.CBOMScanRequest) (api.CBOMScanPreview, error) {
	normalized, err := api.NormalizeCBOMScanRequest(req)
	if err != nil {
		return api.CBOMScanPreview{}, err
	}
	if _, err := s.tlsDialControl(normalized); err != nil {
		return api.CBOMScanPreview{}, err
	}
	// One ordinary handshake, one TLS-1.2-capped compatibility handshake,
	// and optionally one native fallback after the ordinary Go probe fails.
	tlsConnectionLimit := len(normalized.TLSEndpoints) * 2
	if s.nativeTLSExecutable != "" {
		tlsConnectionLimit += len(normalized.TLSEndpoints)
	}
	sourceCount := 0
	findingWriteLimit := 0
	outsideCalls := []string{}
	hostReads := []string{}
	hostFileReadLimit := 0
	hostFileByteLimit := int64(0)
	if len(normalized.TLSEndpoints) > 0 {
		sourceCount++
		findingWriteLimit += min(len(normalized.TLSEndpoints)*3, cbom.DefaultMaxFindingsPerSource)
		outsideCalls = append(outsideCalls,
			fmt.Sprintf("Open at most %d TLS connections across %d normalized endpoints within each endpoint's shared deadline, with no application request or payload. A successful TLS 1.3 negotiation is followed by a TLS 1.2-capped compatibility probe. When a native probe is configured, a failed ordinary Go handshake may also be followed by one native handshake.", tlsConnectionLimit, len(normalized.TLSEndpoints)))
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
		TLSConnectionLimit:    tlsConnectionLimit,
		HostReadSelectorCount: len(normalized.HostConfigs),
		HostFileReadLimit:     hostFileReadLimit, HostFileByteLimit: hostFileByteLimit,
		FindingWriteLimit: findingWriteLimit, WorkerLimit: cbomWorkerLimit,
		QueueDepth: cbomQueueDepth, PerEndpointTimeoutSeconds: int(tlsprobe.DefaultTimeout.Seconds()),
		OutsideCalls: outsideCalls, HostReads: hostReads,
		DurableWrites: []string{
			fmt.Sprintf("Append and project at most %d tenant-scoped cbom.asset.observed records; unreachable, unreadable, oversized, or capped inputs remain visible in the failed count.", findingWriteLimit),
			"After every source completes without failure, append cbom.source.reconciled records for its exact observed files and endpoints; retire facts absent from the latest complete observation while retaining immutable audit history.",
		},
		SignerCalls: 0, OutboxCalls: 0, Blockers: blockers,
		RecoverySteps: []string{
			"If a target is unreachable, correct its host or port, confirm this control plane can reach it, then preview and retry only that target.",
			"If a host path is unreadable or too broad, narrow the absolute path or glob and grant read-only access; never grant write access for CBOM discovery.",
			"A partial scan keeps prior facts active to avoid falsely clearing risk. Review the failed count, repair the inputs, and rerun the complete source to reconcile its current facts.",
		},
		SafetyNotes: []string{
			"Preview performs no network connection, file read, event append, projection write, signer call, or outbox delivery.",
			"TLS discovery completes a handshake only and sends no HTTP or other application-layer request.",
			"TLS dials check each resolved address; private ranges need egress:private, an explicit requested CIDR, and an operator-configured CIDR ceiling. Metadata and link-local addresses stay blocked.",
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
	control, err := s.tlsDialControl(plan.NormalizedRequest)
	if err != nil {
		return api.CBOMScanResponse{}, err
	}
	sources := make([]cbom.Source, 0, 2)
	var host *hostsource.Source
	if len(plan.NormalizedRequest.TLSEndpoints) > 0 {
		options := []tlssource.Option{tlssource.WithProber(func(ctx context.Context, addr string) (tlsprobe.Result, error) {
			if s.nativeTLSExecutable == "" {
				return tlsprobe.Probe(ctx, addr, tlsprobe.WithDialControl(control))
			}
			// A native executable has no dial hook. It may only receive an
			// already-authorized literal IP; DNS names stay in the guarded Go probe.
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && net.ParseIP(host) != nil && control("tcp", addr, nil) == nil {
				return tlsprobe.ProbeWithNativeFallback(ctx, s.nativeTLSExecutable, addr)
			}
			return tlsprobe.ProbeWithNativeFallback(ctx, s.nativeTLSExecutable, addr,
				tlsprobe.WithDialControl(control))
		})}
		// Keep the compatibility probe on Go's capped ClientHello so a TLS
		// 1.3 native success cannot masquerade as TLS 1.2 acceptance.
		options = append(options, tlssource.WithCompatibilityProber(func(ctx context.Context, addr string) (tlsprobe.Result, error) {
			return tlsprobe.Probe(ctx, addr, tlsprobe.WithMaxVersion(tlsprobe.TLSVersion12),
				tlsprobe.WithDialControl(control))
		}))
		sources = append(sources, tlssource.New(plan.NormalizedRequest.TLSEndpoints, options...))
	}
	if len(plan.NormalizedRequest.HostConfigs) > 0 {
		host = hostsource.New(plan.NormalizedRequest.HostConfigs...)
		if s.packageDatabases != nil {
			host.WithPackageDatabases(s.packageDatabases...)
		}
		sources = append(sources, host)
	}
	sink := &eventedCBOMSink{store: s.store, log: s.log, tenantID: tenantID}
	scanner := cbom.NewScanner(sink,
		cbom.WithWorkers(cbomWorkerLimit), cbom.WithQueue(cbomQueueDepth),
		cbom.WithMaxFindingsPerSource(cbom.DefaultMaxFindingsPerSource))
	defer scanner.Close()
	rep := scanner.Scan(ctx, sources)
	// Retire stale facts only after every requested input and event write in this
	// scan succeeded. On partial failure we cannot tell absence from omission.
	if rep.Failed == 0 {
		for _, location := range plan.NormalizedRequest.TLSEndpoints {
			if err := sink.Reconcile(ctx, "tls-endpoints", location); err != nil {
				rep.Failed++
			}
		}
		if host != nil {
			for _, location := range host.ResolvedPaths() {
				if err := sink.Reconcile(ctx, "host-config", location); err != nil {
					rep.Failed++
				}
			}
		}
	}
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
		ObservedAssetIDs:  sink.observedAssetIDs(),
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
	// importSource names the CBOM import source on each observation (X6-L3);
	// empty for trstctl's own scans.
	importSource string
	mu           sync.Mutex
	observed     map[string]store.CryptoAsset
	// firstObserved is the stream sequence of the sink's first recorded
	// observation: an import's reconciliation retires its source's facts
	// projected before it.
	firstObserved uint64
}

func (s *eventedCBOMSink) observedAssetIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.observed))
	for id := range s.observed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *eventedCBOMSink) observedSourceIDs(sourceKind, location string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, a := range s.observed {
		switch sourceKind {
		case store.AgentCryptoLibrarySource, store.AgentKeystoreSource, store.AgentPrivateKeySource:
			// A host agent's report covers its host: "<host>:<path>" (X2-L5R).
			want := map[string]string{store.AgentCryptoLibrarySource: string(cbom.AssetCryptoLibrary),
				store.AgentKeystoreSource: string(cbom.AssetKeystoreKey), store.AgentPrivateKeySource: string(cbom.AssetKeyFile)}[sourceKind]
			if a.Kind == want && strings.HasPrefix(a.Location, location+":") {
				ids = append(ids, id)
			}
			continue
		}
		if a.Location != location {
			continue
		}
		if sourceKind == "host-config" && a.Kind != "host-config" {
			continue
		}
		if sourceKind == "tls-endpoints" && a.Kind != "tls-endpoint" && a.Kind != "certificate-key" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *eventedCBOMSink) Reconcile(ctx context.Context, sourceKind, location string) error {
	if s.log == nil || s.store == nil {
		return errors.New("server: CBOM sink requires store and event log")
	}
	data, err := json.Marshal(projections.CBOMSourceReconciled{
		SourceKind: sourceKind, Location: location,
		ObservedAssetIDs: s.observedSourceIDs(sourceKind, location),
	})
	if err != nil {
		return fmt.Errorf("server: encode CBOM source reconciliation: %w", err)
	}
	return s.appendAndProject(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventCBOMSourceReconciled,
		TenantID: s.tenantID, Data: data,
	})
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
	asset := cbomAssetFor(s.tenantID, f)
	payload := projections.CBOMAssetObserved{
		ID: asset.ID, Kind: asset.Kind, Location: asset.Location, Algorithm: asset.Algorithm, CertificateFingerprint: asset.CertificateFingerprint,
		KeyBits: asset.KeyBits, Protocol: asset.Protocol, Cipher: asset.Cipher,
		Library: asset.Library, Strength: asset.Strength, QuantumVulnerable: asset.QuantumVulnerable,
		OutOfPolicy: asset.OutOfPolicy, Reasons: asset.Reasons, ImportSource: s.importSource,
		ConfigSource: asset.ConfigSource, ProductVersion: asset.ProductVersion,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("server: encode CBOM asset event: %w", err)
	}
	stored, err := s.appendAndProjectStored(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventCBOMAssetObserved,
		TenantID: s.tenantID, Data: data,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.observed == nil {
		s.observed = make(map[string]store.CryptoAsset)
	}
	s.observed[asset.ID] = asset
	if s.firstObserved == 0 || stored.Sequence < s.firstObserved {
		s.firstObserved = stored.Sequence
	}
	s.mu.Unlock()
	return nil
}

// maxCBOMBatchBytes bounds one cbom.assets.observed payload, well under the
// event log's message limit.
const maxCBOMBatchBytes = 256 << 10

// RecordBatch records an import's findings as cbom.assets.observed batches
// (X6-O1): up to projections.MaxCBOMAssetsPerEvent observations and
// maxCBOMBatchBytes an event, in order, each applied as cbom.asset.observed
// would be. A large image scan is a few events instead of one per finding.
func (s *eventedCBOMSink) RecordBatch(ctx context.Context, findings []cbom.Finding) error {
	if s.log == nil || s.store == nil {
		return errors.New("server: CBOM sink requires store and event log")
	}
	var batch []projections.CBOMAssetObserved
	var assets []store.CryptoAsset
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		data, err := json.Marshal(projections.CBOMAssetsObserved{Assets: batch})
		if err != nil {
			return fmt.Errorf("server: encode CBOM asset batch event: %w", err)
		}
		stored, err := s.appendAndProjectStored(ctx, events.Event{
			ID: events.NewID(), Type: projections.EventCBOMAssetsObserved, TenantID: s.tenantID, Data: data,
		})
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.observed == nil {
			s.observed = make(map[string]store.CryptoAsset)
		}
		for _, asset := range assets {
			s.observed[asset.ID] = asset
		}
		if s.firstObserved == 0 || stored.Sequence < s.firstObserved {
			s.firstObserved = stored.Sequence
		}
		s.mu.Unlock()
		batch, assets, size = nil, nil, 0
		return nil
	}
	for _, f := range findings {
		asset := cbomAssetFor(s.tenantID, f)
		payload := projections.CBOMAssetObserved{
			ID: asset.ID, Kind: asset.Kind, Location: asset.Location, Algorithm: asset.Algorithm, CertificateFingerprint: asset.CertificateFingerprint,
			KeyBits: asset.KeyBits, Protocol: asset.Protocol, Cipher: asset.Cipher,
			Library: asset.Library, Strength: asset.Strength, QuantumVulnerable: asset.QuantumVulnerable,
			OutOfPolicy: asset.OutOfPolicy, Reasons: asset.Reasons, ImportSource: s.importSource,
			ConfigSource: asset.ConfigSource, ProductVersion: asset.ProductVersion,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("server: encode CBOM asset event: %w", err)
		}
		if len(batch) == projections.MaxCBOMAssetsPerEvent || (len(batch) > 0 && size+len(encoded)+1 > maxCBOMBatchBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
		batch, assets, size = append(batch, payload), append(assets, asset), size+len(encoded)+1
	}
	return flush()
}

// ReconcileImport records that the sink's import of its source took in the
// whole BOM (X6-L3): the source's facts it did not observe again are retired.
// It returns the IDs of the rows it retired.
func (s *eventedCBOMSink) ReconcileImport(ctx context.Context, runID string) ([]string, error) {
	if s.log == nil || s.store == nil || s.importSource == "" {
		return nil, errors.New("server: CBOM import reconciliation requires store, event log and import source")
	}
	s.mu.Lock()
	from := s.firstObserved
	s.mu.Unlock()
	if from == 0 {
		return nil, errors.New("server: CBOM import reconciliation before any observation")
	}
	data, err := json.Marshal(projections.CBOMImportReconciled{Source: s.importSource, RunID: runID, ObservedFromSequence: from})
	if err != nil {
		return nil, fmt.Errorf("server: encode CBOM import reconciliation: %w", err)
	}
	stored, err := s.appendAndProjectStored(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventCBOMImportReconciled,
		TenantID: s.tenantID, Data: data,
	})
	if err != nil {
		return nil, err
	}
	return s.store.CryptoAssetIDsRetiredByImport(ctx, s.tenantID, s.importSource, stored.Sequence)
}

func (s *eventedCBOMSink) appendAndProject(ctx context.Context, event events.Event) error {
	_, err := s.appendAndProjectStored(ctx, event)
	return err
}

func (s *eventedCBOMSink) appendAndProjectStored(ctx context.Context, event events.Event) (events.Event, error) {
	// Pin one event ID across retries. A lost JetStream acknowledgment must not
	// create a second observation or reconciliation event.
	var stored events.Event
	if err := retryCBOMWrite(ctx, func() error {
		var appendErr error
		stored, appendErr = s.log.Append(ctx, event)
		return appendErr
	}); err != nil {
		return events.Event{}, fmt.Errorf("server: append CBOM %s event: %w", event.Type, err)
	}
	// Project the exact canonical event for read-your-write API responses. The tail
	// worker can apply it concurrently or later; the projection is idempotent by the
	// tenant-scoped asset signature. Retrying this step never appends another event.
	if err := retryCBOMWrite(ctx, func() error { return projections.New(s.store).Apply(ctx, stored) }); err != nil {
		return events.Event{}, fmt.Errorf("server: project CBOM %s event: %w", event.Type, err)
	}
	return stored, nil
}
