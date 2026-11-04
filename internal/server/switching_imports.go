// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Switching imports (A265), on the leader. An apply command records an
// import's rows; this worker records each mapped row's certificate and owner
// in bounded batches, so a 50,000-row export never holds one request or one
// transaction open, and a restart resumes at the first row not applied yet.
// It also runs the endpoint watch: each round reads what every imported
// certificate's endpoints serve — from the control plane, under its egress
// rules, private ranges only through the CIDRs the operator granted — and
// records matched, serves_other, unreachable or no_endpoint for every row. A
// watched import is checked again every day.

const (
	defaultSwitchingImportInterval = 2 * time.Second
	switchingImportBatch           = 500
	// switchingImportBatchesPerTick bounds one tick's work per import.
	switchingImportBatchesPerTick = 20
	switchingImportsPerTenant     = 10
	switchingWatchEvery           = 24 * time.Hour
	switchingWatchBatch           = 200
	switchingWatchConcurrency     = 8
	switchingWatchTimeout         = 5 * time.Second
	switchingWatchDetailLimit     = 300
)

// RunSwitchingImports applies and watches switching imports, on the leader.
func (s *Server) RunSwitchingImports(ctx context.Context) {
	ticker := time.NewTicker(defaultSwitchingImportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.ApplySwitchingImportsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("switching import could not apply or watch every pending row", slog.String("error", err.Error()))
			}
		}
	}
}

// ApplySwitchingImportsOnce applies, and watches, a bounded share of every
// tenant's switching imports and reports how many rows it handled.
func (s *Server) ApplySwitchingImportsOnce(ctx context.Context) (int, error) {
	return s.applySwitchingImportsAt(ctx, time.Now().UTC())
}

func (s *Server) applySwitchingImportsAt(ctx context.Context, now time.Time) (int, error) {
	if s.store == nil || s.orch == nil {
		return 0, nil
	}
	due := now.Add(-switchingWatchEvery)
	tenants, err := s.store.TenantsWithSwitchingWork(ctx, due)
	if err != nil {
		return 0, err
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	handled := 0
	for _, tenantID := range tenants {
		imports, err := s.store.RecordingSwitchingImports(ctx, tenantID, switchingImportsPerTenant)
		note(err)
		for _, imp := range imports {
			for range switchingImportBatchesPerTick {
				n, done, err := s.orch.ApplySwitchingImportRows(ctx, tenantID, imp, switchingImportBatch)
				handled += n
				note(err)
				if err != nil || done || n == 0 || ctx.Err() != nil {
					break
				}
			}
		}
		watched, err := s.store.SwitchingImportsWithWatchWork(ctx, tenantID, due, switchingImportsPerTenant)
		note(err)
		for _, imp := range watched {
			if imp.WatchPending == 0 {
				// A watched import whose last round is a day old starts the next
				// round with the egress the operator granted.
				note(s.orch.RequestSwitchingWatch(ctx, tenantID, projections.SwitchingWatchRequested{ImportID: imp.ID,
					Round: imp.WatchRound + 1, AllowPrivateEndpoint: imp.WatchAllowPrivate, PrivateEgressCIDRs: imp.WatchPrivateCIDRs,
					RequestedBy: "scheduler"}))
				continue
			}
			n, err := s.watchSwitchingImport(ctx, tenantID, imp)
			handled += n
			note(err)
		}
	}
	return handled, firstErr
}

// watchSwitchingImport observes one bounded batch of a watch round.
func (s *Server) watchSwitchingImport(ctx context.Context, tenantID string, imp store.SwitchingImport) (int, error) {
	rows, err := s.store.PendingSwitchingWatchRows(ctx, tenantID, imp.ID, imp.WatchRound, switchingWatchBatch)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	control := netsec.SafeDialControl
	if imp.WatchAllowPrivate {
		opts, err := privateEgressSafeClientOptions(imp.WatchPrivateCIDRs)
		if err != nil {
			return 0, err
		}
		control = netsec.SafeDialControlWithOptions(opts)
	}
	results := make([]store.SwitchingWatchResult, len(rows))
	sem := make(chan struct{}, switchingWatchConcurrency)
	var wg sync.WaitGroup
	for i, row := range rows {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, row store.SwitchingImportRow) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = observeSwitchingRow(ctx, row, control)
		}(i, row)
	}
	wg.Wait()
	return len(rows), s.orch.RecordSwitchingWatch(ctx, tenantID, imp.ID, imp.WatchRound, results)
}

// observeSwitchingRow reads what each of a row's endpoints serves. One
// endpoint serving another certificate makes the row serves_other; failing
// that, one unreachable endpoint makes it unreachable.
func observeSwitchingRow(ctx context.Context, row store.SwitchingImportRow,
	control func(network, address string, c syscall.RawConn) error) store.SwitchingWatchResult {
	out := store.SwitchingWatchResult{Row: row.Row}
	if len(row.Endpoints) == 0 {
		out.Status, out.Detail = store.SwitchingWatchNoEndpoint, "the export names no endpoint for this certificate"
		return out
	}
	var other, unreachable []string
	var otherFingerprint, unreachableReason string
	for _, endpoint := range row.Endpoints {
		res, err := tlsprobe.Probe(ctx, endpoint, tlsprobe.WithDialControl(control), tlsprobe.WithTimeout(switchingWatchTimeout))
		switch {
		case err != nil:
			unreachable = append(unreachable, endpoint)
			if unreachableReason == "" {
				unreachableReason = err.Error()
			}
		case crypto.SHA256Hex(res.PeerCertificates[0]) != row.Fingerprint:
			other = append(other, endpoint)
			if otherFingerprint == "" {
				otherFingerprint = crypto.SHA256Hex(res.PeerCertificates[0])
			}
		}
	}
	switch {
	case len(other) > 0:
		out.Status, out.Endpoint, out.ServedFingerprint = store.SwitchingWatchServesOther, other[0], otherFingerprint
		out.Detail = fmt.Sprintf("%d of %d endpoints serve another certificate", len(other), len(row.Endpoints))
	case len(unreachable) > 0:
		out.Status, out.Endpoint = store.SwitchingWatchUnreachable, unreachable[0]
		out.Detail = fmt.Sprintf("%d of %d endpoints unreachable: %s", len(unreachable), len(row.Endpoints), unreachableReason)
	default:
		out.Status, out.Endpoint = store.SwitchingWatchMatched, row.Endpoints[0]
		out.Detail = fmt.Sprintf("%d of %d endpoints serve this certificate", len(row.Endpoints), len(row.Endpoints))
	}
	if len(out.Detail) > switchingWatchDetailLimit {
		out.Detail = out.Detail[:switchingWatchDetailLimit]
	}
	return out
}
