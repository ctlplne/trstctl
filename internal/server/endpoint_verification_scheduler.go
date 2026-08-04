// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Re-verifying endpoints on a schedule (epic D2).
//
// A post-deploy check proves the reload took effect at the moment of deploy.
// It says nothing about the weeks afterwards, and the failure this epic exists
// to catch does not only happen at deploy time: a config reload elsewhere, a
// failover to a node that never got the file, an operator restoring an old
// backup — each leaves a listener serving a certificate nobody deployed, with
// every trstctl record still truthfully green.
//
// So verification has to be a loop, not an event. Without this the epic's own
// acceptance criterion — "detected within one verification interval" — has no
// interval to be within.

// defaultEndpointVerificationInterval is how often a relay re-probes.
//
// An hour rather than minutes: a probe is a real TCP+TLS handshake against
// production listeners, and a fleet of them every minute is a load pattern an
// operator did not ask for. An hour bounds the worst case — a certificate that
// stopped serving correctly is found within an hour — against a cost nobody
// notices.
const defaultEndpointVerificationInterval = time.Hour

// endpointVerificationBatch bounds how many endpoints ride in one job.
//
// A sweep amortises one claim over many endpoints, but an unbounded list would
// let one tenant's job hold a relay for an arbitrarily long time while other
// tenants' work waits behind it (AN-7).
const endpointVerificationBatch = 50

// RunEndpointVerificationScheduler enqueues periodic re-verification sweeps.
//
// It is a no-op when nothing has ever been verified. That is deliberate: this
// scheduler re-probes endpoints the estate already knows about, and inventing
// endpoints to probe from deployment targets would mean guessing listener
// addresses — which is exactly the guess that would produce confident, wrong
// verification records.
func (s *Server) RunEndpointVerificationScheduler(ctx context.Context) {
	if s.store == nil || s.outbox == nil {
		return
	}
	interval := s.endpointVerificationInterval
	if interval <= 0 {
		interval = defaultEndpointVerificationInterval
	}
	_, _ = s.RunEndpointVerificationOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunEndpointVerificationOnce(ctx)
		}
	}
}

// RunEndpointVerificationOnce queues one re-verification sweep per tenant that
// has endpoints to re-probe, and returns how many endpoints were queued.
//
// Exported for served-path tests: the acceptance criterion is that a renewal
// which never lands is detected within one interval, and a test has to be able
// to run exactly one interval on demand.
func (s *Server) RunEndpointVerificationOnce(ctx context.Context) (int, error) {
	if s.store == nil || s.outbox == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithVerifiableEndpoints(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, tenantID := range tenants {
		n, err := s.queueEndpointVerificationSweep(ctx, tenantID)
		if err != nil {
			// One tenant's failure does not stop the others. A sweep that could
			// not be queued is retried on the next tick, which is a better
			// outcome than a scheduler that stops at the first bad tenant.
			continue
		}
		queued += n
	}
	return queued, nil
}

// queueEndpointVerificationSweep enqueues one tenant's sweep.
func (s *Server) queueEndpointVerificationSweep(ctx context.Context, tenantID string) (int, error) {
	rows, err := s.store.ListEndpointVerifications(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	// One expectation per ENDPOINT, taken from whichever vantage last saw it.
	// Not per row: probing the same listener twice because two vantages have
	// observed it would double the load to learn the same fact.
	seen := map[string]bool{}
	intent := relay.EndpointVerifyIntent{}
	for _, r := range rows {
		if seen[r.EndpointID] || r.Address == "" || r.ExpectedFingerprint == "" {
			continue
		}
		seen[r.EndpointID] = true
		intent.Endpoints = append(intent.Endpoints, relay.EndpointExpectation{
			EndpointID: r.EndpointID,
			Address:    r.Address,
			// The expectation is the control plane's own record of what should
			// be there, never the agent's last observation. Re-probing against
			// what was last SEEN would ratify a divergence: an endpoint serving
			// the wrong certificate would be re-verified as correct on the
			// second sweep, and the alarm would silence itself.
			Fingerprint: r.ExpectedFingerprint,
		})
		if len(intent.Endpoints) >= endpointVerificationBatch {
			break
		}
	}
	if len(intent.Endpoints) == 0 {
		return 0, nil
	}

	payload, err := json.Marshal(intent)
	if err != nil {
		return 0, err
	}
	// The idempotency key carries the interval bucket, so a scheduler that runs
	// twice inside one interval — a restart, an overlapping tick — enqueues one
	// sweep rather than two. Without it a flapping process would queue work
	// faster than relays could drain it.
	bucket := time.Now().UTC().Truncate(s.effectiveEndpointVerificationInterval()).Format(time.RFC3339)
	idem := "endpoint-verify-sweep:" + bucket
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, qerr := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    relay.KindEndpointVerify,
			IdempotencyKey: idem,
			Payload:        payload,
		})
		return qerr
	})
	if err != nil {
		return 0, err
	}
	return len(intent.Endpoints), nil
}

func (s *Server) effectiveEndpointVerificationInterval() time.Duration {
	if s.endpointVerificationInterval > 0 {
		return s.endpointVerificationInterval
	}
	return defaultEndpointVerificationInterval
}

var _ = store.EndpointVerification{}
