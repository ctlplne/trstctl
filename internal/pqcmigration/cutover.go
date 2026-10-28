// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// A217: a hybrid composite leaf moves to pure ML-DSA only after the relying
// parties of its identity have acknowledged they accept pure post-quantum
// certificates — the same signed-acknowledgment quorum (PCAS-10) that gates
// retiring a predecessor key. The run records the reissue as a cutover and
// holds its host job; this worker evaluates the identity's active retirement
// policy against the signed acknowledgments in the ledger and, once the quorum
// is met, queues the held job unchanged. Without the quorum the cutover waits.

// EventCertificateCutoverReleased records that a held cutover met its
// identity's acknowledgment quorum and its host job was queued.
const EventCertificateCutoverReleased = "pqc.migration.cutover_released"

// CertificateCutoverReleased is one released cutover and the quorum that
// released it.
type CertificateCutoverReleased struct {
	RunID            string   `json:"run_id"`
	AssetID          string   `json:"asset_id"`
	IdentityID       string   `json:"identity_id"`
	PredecessorEpoch uint64   `json:"predecessor_epoch"`
	RelyingParties   []string `json:"relying_parties"`
	AckSetDigest     string   `json:"ack_set_digest"`
}

func init() {
	if err := events.RegisterPrivacyEventPolicy(EventCertificateCutoverReleased, 1, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{
			{Path: "/run_id", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/asset_id", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/identity_id", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/predecessor_epoch", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/relying_parties", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/ack_set_digest", Mode: events.PrivacyFieldOpaqueExact},
		},
		PayloadShape: events.PrivacyPayloadShapeOf[CertificateCutoverReleased](), RejectSubjectData: true,
	}); err != nil {
		panic(err)
	}
}

var cutoverReleaseNamespace = uuid.MustParse("0d7a4c2e-6b19-5f3a-8e47-a217c0e5b9d1")

// applyCutoverReleased moves a held cutover to queued.
func (p *ProgressProjection) applyCutoverReleased(ev eventspec.Event, released CertificateCutoverReleased) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: released.RunID, assetID: released.AssetID}
	delete(p.heldCutovers, key)
	if item, ok := p.items[key]; ok && item.Status == CertificateFindingAwaitingAcknowledgment {
		item.Status, item.UpdatedAt = TLSFindingQueued, eventTime(ev)
		p.items[key] = item
	}
}

// HeldCutover is one cutover waiting for its acknowledgment quorum.
type HeldCutover struct {
	TenantID string
	Reissue  projections.LicensedCryptoMigrationReissue
}

// HeldCutovers lists the cutovers waiting for their quorum, in a stable order.
func (p *ProgressProjection) HeldCutovers() []HeldCutover {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]HeldCutover, 0, len(p.heldCutovers))
	for key, reissue := range p.heldCutovers {
		out = append(out, HeldCutover{TenantID: key.tenantID, Reissue: reissue})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].Reissue.RunID != out[j].Reissue.RunID {
			return out[i].Reissue.RunID < out[j].Reissue.RunID
		}
		return out[i].Reissue.AssetID < out[j].Reissue.AssetID
	})
	return out
}

// CutoverReleaseWorker queues held cutovers whose identity's relying-party
// acknowledgment quorum is met. It runs on the leader.
type CutoverReleaseWorker struct {
	progress      *ProgressProjection
	store         *store.Store
	log           *events.Log
	outbox        *orchestrator.Outbox
	repo          *pcasstore.Repo
	defaultWindow time.Duration
	interval      time.Duration
	now           func() time.Time
}

// cutoverReleaseInterval is how often held cutovers are evaluated.
const cutoverReleaseInterval = time.Minute

// CutoverReleaseWorker builds the release worker over the runtime's progress.
// defaultWindow is how long an acknowledgment counts when a policy names no
// window (PCAS retirement's own default).
func (r *Runtime) CutoverReleaseWorker(st *store.Store, log *events.Log, defaultWindow time.Duration) *CutoverReleaseWorker {
	if defaultWindow <= 0 {
		defaultWindow = 24 * time.Hour
	}
	return &CutoverReleaseWorker{progress: r.Progress, store: st, log: log, outbox: orchestrator.NewOutbox(st),
		repo: pcasstore.New(st), defaultWindow: defaultWindow, interval: cutoverReleaseInterval,
		now: func() time.Time { return time.Now().UTC() }}
}

// Name names the worker in the runtime roster.
func (w *CutoverReleaseWorker) Name() string { return "pqc.cutover_release" }

// Run evaluates held cutovers every interval until ctx ends.
func (w *CutoverReleaseWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if _, err := w.ReleaseOnce(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ReleaseOnce evaluates every held cutover and returns how many it released.
func (w *CutoverReleaseWorker) ReleaseOnce(ctx context.Context) (int, error) {
	if w == nil || w.progress == nil || w.store == nil || w.log == nil || w.outbox == nil {
		return 0, errors.New("pqcmigration: the cutover release worker is not assembled")
	}
	held := w.progress.HeldCutovers()
	acks := map[string][]retirement.SignedAck{}
	released := 0
	var errs []error
	for _, cutover := range held {
		tenantAcks, ok := acks[cutover.TenantID]
		if !ok {
			var err error
			if tenantAcks, err = w.tenantAcks(ctx, cutover.TenantID); err != nil {
				errs = append(errs, err)
				continue
			}
			acks[cutover.TenantID] = tenantAcks
		}
		done, err := w.release(ctx, cutover, tenantAcks)
		if err != nil {
			errs = append(errs, fmt.Errorf("run %s asset %s: %w", cutover.Reissue.RunID, cutover.Reissue.AssetID, err))
			continue
		}
		if done {
			released++
		}
	}
	return released, errors.Join(errs...)
}

// release queues one held cutover when its identity's quorum is met.
func (w *CutoverReleaseWorker) release(ctx context.Context, cutover HeldCutover, acks []retirement.SignedAck) (bool, error) {
	reissue := cutover.Reissue
	policy, ok, err := w.acknowledgmentPolicy(ctx, cutover.TenantID, reissue.IdentityID)
	if err != nil || !ok {
		return false, err
	}
	roster, err := retirement.DecodeRoster(policy.RosterJSON)
	if err != nil {
		return false, err
	}
	window := w.defaultWindow
	if policy.ValidityWindowSeconds > 0 && policy.ValidityWindowSeconds <= uint64(math.MaxInt64/int64(time.Second)) {
		window = time.Duration(policy.ValidityWindowSeconds) * time.Second // #nosec G115 -- bounded above (CWE-190)
	}
	quorum := retirement.EvaluateQuorum(acks,
		retirement.Target{TenantID: cutover.TenantID, IdentityID: reissue.IdentityID, Epoch: policy.PredecessorEpoch},
		roster, retirement.QuorumPolicy{Threshold: policy.Threshold, ValidityWindow: window}, w.now())
	if !quorum.Met {
		return false, nil
	}
	parties := make([]string, 0, len(quorum.Satisfying))
	for _, ack := range quorum.Satisfying {
		parties = append(parties, ack.RelyingParty)
	}
	sort.Strings(parties)
	payload := CertificateCutoverReleased{RunID: reissue.RunID, AssetID: reissue.AssetID, IdentityID: reissue.IdentityID,
		PredecessorEpoch: policy.PredecessorEpoch, RelyingParties: parties,
		AckSetDigest: hex.EncodeToString(retirement.AckSetDigest(quorum.Satisfying))}
	// Queue first: a crash after the queue and before the event leaves the
	// cutover held, and the next pass finds the job already queued.
	if err := w.store.WithTenant(ctx, cutover.TenantID, func(tx pgx.Tx) error {
		return enqueueHostReissue(ctx, tx, w.outbox, cutover.TenantID, reissue)
	}); err != nil {
		return false, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	id := uuid.NewSHA1(cutoverReleaseNamespace, []byte(cutover.TenantID+"\x00"+reissue.RunID+"\x00"+reissue.AssetID)).String()
	ev, err := w.log.Append(ctx, events.Event{ID: id, Type: EventCertificateCutoverReleased, TenantID: cutover.TenantID, Data: data})
	if err != nil {
		return false, err
	}
	return true, w.progress.Apply(ctx, ev)
}

// acknowledgmentPolicy is the identity's retirement policy with the highest
// predecessor epoch: the acknowledgment policy its relying parties answer. A
// policy PCAS has already retired still counts, so a cutover is not stranded
// when the same quorum retired the identity's predecessor key first; the
// quorum is still evaluated over acknowledgments inside the window.
func (w *CutoverReleaseWorker) acknowledgmentPolicy(ctx context.Context, tenantID, identityID string) (pcasstore.RetirementPolicy, bool, error) {
	policies, err := w.repo.ListRetirementPolicies(ctx, tenantID, false)
	if err != nil {
		return pcasstore.RetirementPolicy{}, false, err
	}
	var best pcasstore.RetirementPolicy
	found := false
	for _, policy := range policies {
		if policy.IdentityID != identityID || (policy.Status != "active" && policy.Status != "retired") {
			continue
		}
		if !found || policy.PredecessorEpoch > best.PredecessorEpoch {
			best, found = policy, true
		}
	}
	return best, found, nil
}

// tenantAcks reads the tenant's signed relying-party acknowledgments.
func (w *CutoverReleaseWorker) tenantAcks(ctx context.Context, tenantID string) ([]retirement.SignedAck, error) {
	var evs []events.Event
	if err := w.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := w.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return w.log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head, []string{succession.TypeRPAck}, func(e events.Event) error {
			evs = append(evs, e)
			return nil
		})
	}); err != nil {
		return nil, fmt.Errorf("pqcmigration: read relying-party acknowledgments: %w", err)
	}
	return retirement.AcksFromEvents(evs)
}
