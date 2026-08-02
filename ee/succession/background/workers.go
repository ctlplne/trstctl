// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package background wires the PCAS scheduled mechanisms into the served binary:
// signed checkpoints, posture/misissuance monitors, and evidence-gated retirement.
package background

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/kem"
	"trstctl.com/trstctl/ee/succession/monitor"
	"trstctl.com/trstctl/ee/succession/recovery"
	"trstctl.com/trstctl/ee/succession/retirement"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

type Options struct {
	Store  *corestore.Store
	Log    *events.Log
	Signer server.SignerProvider
	PCAS   config.PCAS
}

func NewWorkers(opts Options) []server.BackgroundWorker {
	var out []server.BackgroundWorker
	repo := pcasstore.New(opts.Store)
	if opts.PCAS.Checkpoints.Enabled {
		out = append(out, &checkpointWorker{
			store: opts.Store, repo: repo, log: opts.Log, signer: opts.Signer,
			interval: intervalOr(opts.PCAS.Checkpoints.Interval, time.Minute),
			handle:   opts.PCAS.Checkpoints.SigningKeyHandle,
			alg:      crypto.Algorithm(opts.PCAS.Checkpoints.SigningAlgorithm),
		})
	}
	if opts.PCAS.Monitors.Enabled {
		out = append(out, &misissuanceWorker{
			store: opts.Store, repo: repo, log: opts.Log,
			interval: intervalOr(opts.PCAS.Monitors.Interval, time.Minute),
		})
	}
	if opts.PCAS.Retirement.Enabled {
		out = append(out, &retirementWorker{
			store: opts.Store, repo: repo, log: opts.Log, signer: opts.Signer,
			interval:       intervalOr(opts.PCAS.Retirement.Interval, time.Minute),
			validityWindow: intervalOr(opts.PCAS.Retirement.ValidityWindow, 24*time.Hour),
		})
	}
	return out
}

func intervalOr(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

type checkpointWorker struct {
	store    *corestore.Store
	repo     *pcasstore.Repo
	log      *events.Log
	signer   server.SignerProvider
	interval time.Duration
	handle   string
	alg      crypto.Algorithm
}

func (w *checkpointWorker) Name() string { return "pcas.checkpoints" }

func (w *checkpointWorker) Run(ctx context.Context) error {
	if err := w.runOnce(ctx); err != nil {
		return err
	}
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.runOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (w *checkpointWorker) runOnce(ctx context.Context) error {
	if w.store == nil || w.repo == nil || w.signer == nil {
		return errors.New("pcas checkpoint worker: store and signer are required")
	}
	cpSigner, err := w.checkpointSigner(ctx)
	if err != nil {
		return err
	}
	tenants, err := w.store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("pcas checkpoint worker: list tenants: %w", err)
	}
	for _, t := range tenants {
		records, err := w.repo.ListRecords(ctx, t.TenantID)
		if err != nil {
			return err
		}
		// Bind the real head of the tenant's append-only transparency log into
		// every checkpoint minted this round (PCAS-claim-29). The log is rebuilt
		// deterministically from the persisted succession ledger (records are
		// returned in a stable identity,epoch order and, being append-only, are
		// never removed or reordered), so its Merkle root is a pure function of the
		// record set: stable across restarts, and divergent only when the record
		// set diverges. Two checkpoints that disagree on the log head at one tree
		// size therefore evidence equivocation — which the earlier synthesized
		// placeholder root could not. (PCAS-audit E-3b.)
		logHead, err := transparencyHead(records)
		if err != nil {
			return fmt.Errorf("pcas checkpoint worker: transparency-log head: %w", err)
		}
		logTreeSize, err := checkpointTreeSize(logHead.TreeSize)
		if err != nil {
			return fmt.Errorf("pcas checkpoint worker: %w", err)
		}
		for _, rec := range latestByIdentity(records) {
			fields := recordFields(rec)
			issuedAt := time.Now().UTC()
			cp := succession.SignedEpochCheckpoint{
				DeploymentScope: fields.DeploymentScope,
				IdentityID:      rec.IdentityID,
				TenantID:        t.TenantID,
				Epoch:           rec.Epoch,
				Algorithm:       crypto.Algorithm(rec.SuccessorAlg),
				PublicKeyDER:    rec.SuccessorPub,
				LogTreeSize:     logTreeSize,
				LogRootHash:     logHead.RootHash,
				IssuedAt:        issuedAt.Unix(),
			}
			signed, err := succession.SignEpochCheckpoint(crypto.SignerFromDigestSigner(cpSigner), cp)
			if err != nil {
				return fmt.Errorf("pcas checkpoint worker: sign checkpoint: %w", err)
			}
			raw, err := json.Marshal(signed)
			if err != nil {
				return err
			}
			if err := w.repo.SaveCheckpoint(ctx, t.TenantID, pcasstore.EpochCheckpoint{
				IdentityID:     signed.IdentityID,
				Epoch:          signed.Epoch,
				LogTreeSize:    signed.LogTreeSize,
				LogRoot:        signed.LogRootHash,
				Signature:      signed.Signature,
				CheckpointJSON: raw,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *checkpointWorker) checkpointSigner(ctx context.Context) (*signing.RemoteSigner, error) {
	client := w.signer.Client()
	if client == nil {
		return nil, errors.New("pcas checkpoint worker: signer is not available")
	}
	rs, err := client.SignerForHandleWithPurpose(ctx, w.handle, signing.PurposeGeneric)
	if err == nil {
		return rs, nil
	}
	rs, err = client.GenerateKeyHandle(ctx, w.alg, w.handle)
	if err != nil {
		return nil, fmt.Errorf("pcas checkpoint worker: provision signer-held checkpoint key: %w", err)
	}
	return rs, nil
}

type misissuanceWorker struct {
	store    *corestore.Store
	repo     *pcasstore.Repo
	log      *events.Log
	interval time.Duration
}

func (w *misissuanceWorker) Name() string { return "pcas.misissuance" }

func (w *misissuanceWorker) Run(ctx context.Context) error {
	if err := w.runOnce(ctx); err != nil {
		return err
	}
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.runOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (w *misissuanceWorker) runOnce(ctx context.Context) error {
	if w.store == nil || w.repo == nil {
		return errors.New("pcas misissuance worker: store is required")
	}
	tenants, err := w.store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("pcas misissuance worker: list tenants: %w", err)
	}
	for _, t := range tenants {
		rows, err := w.repo.ListRecords(ctx, t.TenantID)
		if err != nil {
			return err
		}
		records := make([]succession.SuccessionRecord, 0, len(rows))
		for _, row := range rows {
			if rec, ok := decodeRecord(row.Encoded); ok {
				records = append(records, rec)
			} else if paired, ok := decodePaired(row.Encoded); ok {
				records = append(records, paired.Base)
			}
		}
		if len(records) < 2 {
			continue
		}
		det, ok, err := monitor.New(map[string][]byte{}, nil).Scan(ctx, records)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		a, err := succession.Commit(det.Proof.RecordA.Fields)
		if err != nil {
			return err
		}
		b, err := succession.Commit(det.Proof.RecordB.Fields)
		if err != nil {
			return err
		}
		if exists, err := w.misissuanceExists(ctx, t.TenantID, det.Proof.RecordA.Fields.IdentityID, det.Proof.RecordA.Fields.Epoch, a, b); err != nil || exists {
			if err != nil {
				return err
			}
			continue
		}
		proof, err := json.Marshal(det.Proof)
		if err != nil {
			return err
		}
		if det.Event.Type != "" && w.log != nil {
			if _, err := w.log.Append(ctx, det.Event); err != nil {
				return fmt.Errorf("pcas misissuance worker: append event: %w", err)
			}
		}
		if err := w.repo.SaveMisissuance(ctx, t.TenantID, pcasstore.Misissuance{
			IdentityID:    det.Proof.RecordA.Fields.IdentityID,
			Epoch:         det.Proof.RecordA.Fields.Epoch,
			RecordADigest: a,
			RecordBDigest: b,
			SignerA:       det.SignerA,
			SignerB:       det.SignerB,
			ProofJSON:     proof,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w *misissuanceWorker) misissuanceExists(ctx context.Context, tenantID, identityID string, epoch uint64, a, b []byte) (bool, error) {
	findings, err := w.repo.ListMisissuance(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, f := range findings {
		if f.IdentityID == identityID && f.Epoch == epoch &&
			bytes.Equal(f.RecordADigest, a) && bytes.Equal(f.RecordBDigest, b) {
			return true, nil
		}
	}
	return false, nil
}

type retirementWorker struct {
	store          *corestore.Store
	repo           *pcasstore.Repo
	log            *events.Log
	signer         server.SignerProvider
	interval       time.Duration
	validityWindow time.Duration
}

func (w *retirementWorker) Name() string { return "pcas.retirement" }

func (w *retirementWorker) Run(ctx context.Context) error {
	if err := w.runOnce(ctx); err != nil {
		return err
	}
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.runOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (w *retirementWorker) runOnce(ctx context.Context) error {
	if w.store == nil || w.repo == nil || w.log == nil || w.signer == nil {
		return errors.New("pcas retirement worker: store, ledger, and signer are required")
	}
	client := w.signer.Client()
	if client == nil {
		return errors.New("pcas retirement worker: signer is not available")
	}
	ledgerEvents, err := collectEvents(ctx, w.log)
	if err != nil {
		return err
	}
	tenants, err := w.store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("pcas retirement worker: list tenants: %w", err)
	}
	for _, tenant := range tenants {
		policies, err := w.repo.ListRetirementPolicies(ctx, tenant.TenantID, true)
		if err != nil {
			return err
		}
		for _, policy := range policies {
			if alreadyRetired(ledgerEvents, tenant.TenantID, policy.IdentityID, policy.PredecessorEpoch) {
				if err := w.repo.MarkRetirementRetired(ctx, tenant.TenantID, policy.IdentityID, policy.PredecessorEpoch); err != nil {
					return err
				}
				continue
			}
			if err := w.evaluatePolicy(ctx, client, tenant.TenantID, policy, ledgerEvents); err != nil && !errors.Is(err, retirement.ErrQuorumNotMet) {
				return err
			}
		}
	}
	return nil
}

func (w *retirementWorker) evaluatePolicy(ctx context.Context, client *signing.Client, tenantID string, policy pcasstore.RetirementPolicy, ledgerEvents []events.Event) error {
	roster, err := decodeRPRoster(policy.RosterJSON)
	if err != nil {
		return err
	}
	if len(roster) == 0 {
		return nil
	}
	window := w.validityWindow
	if policy.ValidityWindowSeconds > 0 {
		d, err := validityWindowDuration(policy.ValidityWindowSeconds)
		if err != nil {
			return fmt.Errorf("pcas retirement worker: identity %s epoch %d: %w", policy.IdentityID, policy.PredecessorEpoch, err)
		}
		window = d
	}
	ctrl, err := retirement.New(retirement.Config{
		Roster: roster,
		Policy: retirement.QuorumPolicy{
			Threshold:      policy.Threshold,
			ValidityWindow: window,
		},
		Ledger: w.log,
	})
	if err != nil {
		return err
	}
	successorRec, found, err := successorForPredecessor(ctx, w.repo, tenantID, policy.IdentityID, policy.PredecessorEpoch)
	if err != nil || !found {
		return err
	}
	predecessorHandle := policy.PredecessorHandle
	if predecessorHandle == "" {
		predecessorHandle = succession.KeyHandle(policy.IdentityID, policy.PredecessorEpoch)
	}
	worker := retirement.NewWorker(ctrl)
	_, err = worker.EvaluateCutover(ctx,
		retirement.Target{TenantID: tenantID, IdentityID: policy.IdentityID, Epoch: policy.PredecessorEpoch},
		retirement.Successor{
			Epoch:        successorRec.Epoch,
			Algorithm:    successorRec.SuccessorAlg,
			Class:        succession.ClassPurePQ,
			PublicKeyDER: successorRec.SuccessorPub,
		},
		successorRec.PredecessorAlg,
		crypto.SHA256Sum(successorRec.Encoded),
		ledgerEvents,
		retirement.FuncPredecessor{
			ZeroizeFn: func(ctx context.Context, _ string) error { return client.ZeroizeKey(ctx, predecessorHandle) },
		},
		func(ctx context.Context) error {
			jobs, err := w.repo.ListRewrapJobs(ctx, tenantID, policy.IdentityID, policy.PredecessorEpoch)
			if err != nil {
				return err
			}
			if len(jobs) == 0 {
				return nil
			}
			complete, err := w.repo.RewrapComplete(ctx, tenantID, policy.IdentityID, policy.PredecessorEpoch)
			if err != nil {
				return err
			}
			if !complete {
				return kem.ErrRewrapIncomplete
			}
			return nil
		},
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	return w.repo.MarkRetirementRetired(ctx, tenantID, policy.IdentityID, policy.PredecessorEpoch)
}

type rpRosterEntry struct {
	RelyingParty string `json:"relying_party"`
	PublicDER    []byte `json:"public_der"`
}

func decodeRPRoster(raw json.RawMessage) (retirement.Roster, error) {
	var entries []rpRosterEntry
	if len(raw) == 0 {
		return retirement.Roster{}, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("pcas retirement worker: decode roster: %w", err)
	}
	roster := retirement.Roster{}
	for _, e := range entries {
		if e.RelyingParty != "" && len(e.PublicDER) > 0 {
			roster[e.RelyingParty] = e.PublicDER
		}
	}
	return roster, nil
}

func collectEvents(ctx context.Context, log *events.Log) ([]events.Event, error) {
	var out []events.Event
	if log == nil {
		return out, nil
	}
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		out = append(out, e)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("pcas retirement worker: replay ledger: %w", err)
	}
	return out, nil
}

func alreadyRetired(events []events.Event, tenantID, identityID string, epoch uint64) bool {
	for _, e := range events {
		if e.Type != succession.TypeRetirement || e.TenantID != tenantID {
			continue
		}
		p, err := succession.Decode(e)
		if err != nil {
			continue
		}
		r, ok := p.(succession.RetirementV1)
		if ok && r.TenantID == tenantID && r.IdentityID == identityID && r.Epoch == epoch {
			return true
		}
	}
	return false
}

func latestByIdentity(records []pcasstore.Record) []pcasstore.Record {
	byID := map[string]pcasstore.Record{}
	for _, rec := range records {
		if cur, ok := byID[rec.IdentityID]; !ok || rec.Epoch > cur.Epoch {
			byID[rec.IdentityID] = rec
		}
	}
	out := make([]pcasstore.Record, 0, len(byID))
	for _, rec := range byID {
		out = append(out, rec)
	}
	return out
}

func successorForPredecessor(ctx context.Context, repo *pcasstore.Repo, tenantID, identityID string, predecessorEpoch uint64) (pcasstore.Record, bool, error) {
	records, err := repo.FetchChain(ctx, tenantID, identityID)
	if err != nil {
		return pcasstore.Record{}, false, err
	}
	for _, rec := range records {
		if rec.PredecessorEpoch == predecessorEpoch {
			return rec, true, nil
		}
	}
	return pcasstore.Record{}, false, nil
}

// transparencyHead rebuilds a tenant's append-only transparency log from its
// persisted succession records and returns the log head. The records must be
// supplied in the stable order the ledger returns them (identity, then epoch);
// each record's stored canonical encoding is one append-only leaf. The head is a
// pure, deterministic function of the record set — identical across processes,
// machines, and restarts for the same records, and different whenever the record
// set differs — which is what lets two checkpoints' bound heads evidence
// equivocation (PCAS-claim-29). The log is unsigned here because it is used only to
// derive the Merkle root; the checkpoint that carries the root is itself signed.
func transparencyHead(records []pcasstore.Record) (translog.STH, error) {
	tlog := translog.New(nil)
	for _, rec := range records {
		if _, _, err := tlog.Append(rec.Encoded); err != nil {
			return translog.STH{}, err
		}
	}
	return tlog.Head()
}

// checkpointTreeSize carries a transparency-log tree size from the translog
// package's Go int into the uint64 the signed checkpoint binds. A tree size is a
// leaf count and is never negative in practice; the guard makes that provable at
// the conversion and fails the checkpoint round closed rather than signing a
// wrapped, astronomically large tree size that no verifier could reconcile with
// the log it can rebuild (PCAS-claim-29).
func checkpointTreeSize(treeSize int) (uint64, error) {
	if treeSize < 0 {
		return 0, fmt.Errorf("transparency-log tree size %d is negative", treeSize)
	}
	return uint64(treeSize), nil
}

// maxValidityWindowSeconds is the largest whole-second window representable as a
// time.Duration, which counts nanoseconds in a signed 64-bit integer:
// math.MaxInt64 nanoseconds divided by 1e9 nanoseconds per second (~292 years).
const maxValidityWindowSeconds uint64 = math.MaxInt64 / 1_000_000_000

// validityWindowDuration converts a retirement policy's persisted validity
// window — stored and carried on the API as a uint64 second count — into a
// time.Duration. Windows beyond maxValidityWindowSeconds are not representable,
// so the worker rejects them instead of wrapping into a negative duration, which
// would silently treat every relying-party attestation as already expired and
// stall the quorum.
func validityWindowDuration(seconds uint64) (time.Duration, error) {
	if seconds > maxValidityWindowSeconds {
		return 0, fmt.Errorf("validity window of %d seconds exceeds the maximum representable window of %d seconds", seconds, maxValidityWindowSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func recordFields(rec pcasstore.Record) succession.CommitmentFields {
	if decoded, ok := decodeRecord(rec.Encoded); ok {
		return decoded.Fields
	}
	if paired, ok := decodePaired(rec.Encoded); ok {
		return paired.Base.Fields
	}
	if recovered, ok := decodeRecovery(rec.Encoded); ok {
		return recovered.Fields
	}
	return succession.CommitmentFields{
		IdentityID:       rec.IdentityID,
		Epoch:            rec.Epoch,
		PredecessorEpoch: rec.PredecessorEpoch,
		PredecessorAlg:   crypto.Algorithm(rec.PredecessorAlg),
		SuccessorAlg:     crypto.Algorithm(rec.SuccessorAlg),
		SuccessorPub:     rec.SuccessorPub,
	}
}

func decodeRecord(raw []byte) (succession.SuccessionRecord, bool) {
	var rec succession.SuccessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Fields.IdentityID == "" {
		return succession.SuccessionRecord{}, false
	}
	return rec, true
}

func decodePaired(raw []byte) (kem.PairedRecord, bool) {
	var rec kem.PairedRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Base.Fields.IdentityID == "" {
		return kem.PairedRecord{}, false
	}
	return rec, true
}

func decodeRecovery(raw []byte) (recovery.RecoveryRecord, bool) {
	var rec recovery.RecoveryRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Fields.IdentityID == "" {
		return recovery.RecoveryRecord{}, false
	}
	return rec, true
}
