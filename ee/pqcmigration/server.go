// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	licensedCryptoMigrationReissueDestination     = "licensed_crypto.migration.reissue"
	licensedCryptoMigrationRollbackDestination    = "licensed_crypto.migration.rollback"
	licensedCryptoMigrationTLSPostureDestination  = "connector.licensed_crypto.migration.tls_posture"
	licensedCryptoMigrationTLSRollbackDestination = "connector.licensed_crypto.migration.tls_posture.rollback"
	eventTLSRollbackRequested                     = "licensed_crypto.migration.tls_posture.rollback_requested"
)

type pqcMigrationService struct {
	store        *store.Store
	log          *events.Log
	outbox       *orchestrator.Outbox
	deployer     connector.TLSPostureDeployer
	progress     *ProgressProjection
	integrityKey seal.KeyWrapper
}

func NewOutboxFactory(projection *ProgressProjection) editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		if projection == nil {
			return nil, errors.New("pqcmigration: outbox requires the shared runtime progress projection")
		}
		return &outboxHandler{
			store: d.Store, log: d.Log, idem: d.Idempotency, issue: d.IssueProtocolLeaf,
			deployer: d.TLSPostureDeployer, progress: projection,
			integrityKey: d.OutboxIntegrityKey,
		}, nil
	}
}

type outboxHandler struct {
	store        *store.Store
	log          *events.Log
	idem         *orchestrator.Idempotency
	issue        editionseam.ProtocolLeafIssuer
	deployer     connector.TLSPostureDeployer
	progress     *ProgressProjection
	integrityKey seal.KeyWrapper
	// These hooks are package-private crash/retry seams used by adversarial
	// tests. Production factories always leave them nil and use the durable
	// idempotency ledger plus event log/store projector.
	idempotencyDo   func(context.Context, string, string, func(context.Context) ([]byte, error)) ([]byte, error)
	appendEvent     func(context.Context, string, string, any) error
	lookupPrepared  func(context.Context, string, pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error)
	lookupCompleted func(context.Context, string, pqcMigrationTLSPosturePayload, []byte) (TLSFindingCompleted, bool, error)
	afterTLSApply   func() error
}

func (h *outboxHandler) doIdempotent(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if h.idempotencyDo != nil {
		return h.idempotencyDo(ctx, tenantID, key, fn)
	}
	if h.idem == nil {
		return nil, errors.New("pqcmigration: idempotency ledger is not configured")
	}
	return h.idem.Do(ctx, tenantID, key, fn)
}

func (h *outboxHandler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	switch m.Destination {
	case licensedCryptoMigrationReissueDestination:
		return true, h.handlePQCReissue(ctx, m)
	case licensedCryptoMigrationRollbackDestination:
		return true, h.handlePQCRollback(ctx, m)
	case licensedCryptoMigrationTLSPostureDestination:
		return true, h.handleTLSPosture(ctx, m)
	case licensedCryptoMigrationTLSRollbackDestination:
		return true, h.handleTLSPostureRollback(ctx, m)
	default:
		return false, nil
	}
}

// DeliverLicensedTerminalFailure projects retry exhaustion as a redacted
// per-finding terminal fact. The sealed payload is opened only to recover bound
// identifiers; receiver errors and target config never enter the event.
func (h *outboxHandler) DeliverLicensedTerminalFailure(ctx context.Context, m orchestrator.Message, _ error) (bool, error) {
	switch m.Destination {
	case licensedCryptoMigrationTLSPostureDestination:
		var payload pqcMigrationTLSPosturePayload
		wrapped, err := openTLSPostureOutbox(h.integrityKey, m.TenantID, m.Destination, m.IdempotencyKey, m.Payload, &payload)
		if err != nil {
			return true, err
		}
		if payload.RunID != wrapped.RunID || payload.AssetID != wrapped.AssetID || payload.TargetRevision != wrapped.TargetRevision {
			return true, errors.New("pqcmigration: sealed terminal-failure metadata mismatch")
		}
		return true, h.appendProjected(ctx, m.TenantID, EventTLSFindingFailed, TLSFindingFailure{
			RunID: payload.RunID, AssetID: payload.AssetID, FindingKind: payload.FindingKind,
			TargetID: payload.TargetID, Connector: payload.Connector,
			Reason: "TLS posture delivery attempts exhausted", Status: TLSFindingFailed,
		})
	case licensedCryptoMigrationTLSRollbackDestination:
		var payload pqcMigrationTLSRollbackPayload
		wrapped, err := openTLSPostureOutbox(h.integrityKey, m.TenantID, m.Destination, m.IdempotencyKey, m.Payload, &payload)
		if err != nil {
			return true, err
		}
		if len(payload.Restores) == 0 || payload.RunID != wrapped.RunID ||
			payload.Restores[0].AssetID != wrapped.AssetID || payload.Mutation.TargetRevision != wrapped.TargetRevision {
			return true, errors.New("pqcmigration: sealed rollback terminal-failure metadata mismatch")
		}
		for _, restore := range payload.Restores {
			if err := h.appendProjected(ctx, m.TenantID, EventTLSFindingFailed, TLSFindingFailure{
				RunID: payload.RunID, AssetID: restore.AssetID, FindingKind: restore.FindingKind,
				TargetID: restore.TargetID, Connector: payload.Mutation.Connector,
				Reason: "TLS posture rollback attempts exhausted", Status: TLSFindingRollbackFailed,
			}); err != nil {
				return true, err
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

type pqcMigrationReissuePayload = projections.LicensedCryptoMigrationReissue
type pqcMigrationTLSPosturePayload = projections.LicensedCryptoMigrationTLSPosture

type pqcMigrationRollbackPayload struct {
	RunID   string                                               `json:"run_id"`
	Reason  string                                               `json:"reason"`
	Restore projections.LicensedCryptoMigrationRollbackCompleted `json:"restore"`
}

type pqcMigrationTLSRollbackPayload struct {
	RunID    string                       `json:"run_id"`
	Reason   string                       `json:"reason"`
	Mutation connector.TLSPostureMutation `json:"mutation"`
	Restores []TLSAssetRestore            `json:"restores"`
}

type sealedTLSRollbackIntent struct {
	TargetID       string          `json:"target_id"`
	AssetIDs       []string        `json:"asset_ids"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
}

type tlsRollbackRequested struct {
	RunID   string                    `json:"run_id"`
	Intents []sealedTLSRollbackIntent `json:"intents"`
}

func (s *pqcMigrationService) Start(ctx context.Context, tenantID string, req APIRequest) (Response, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return Response{}, errors.New("server: PQC migration requires store, event log, and outbox")
	}
	bindings := make([]TLSBinding, 0, len(req.TLSBindings))
	for _, binding := range req.TLSBindings {
		bindings = append(bindings, TLSBinding{
			AssetID: binding.AssetID, TargetID: binding.TargetID, Desired: clonePosture(binding.Desired),
		})
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return Response{}, err
	}
	plan, err := BuildPlan(pqcMigrationAssets(assets), Request{
		AssetIDs: req.AssetIDs, TargetAlgorithm: req.TargetAlgorithm, Protocol: req.Protocol,
		RollbackOnFailure: req.RollbackOnFailure, TLSBindings: bindings,
	})
	if err != nil {
		var missing AssetNotFoundError
		if errors.As(err, &missing) {
			return Response{}, pgx.ErrNoRows
		}
		return Response{}, err
	}
	runID := uuid.NewString()
	reissuePayloads := make([]pqcMigrationReissuePayload, 0, len(plan.Reissues))
	for _, reissue := range plan.Reissues {
		asset := reissue.Asset
		reissuePayloads = append(reissuePayloads, pqcMigrationReissuePayload{
			RunID: runID, AssetID: asset.ID, Kind: asset.Kind, Location: asset.Location,
			Algorithm: asset.Algorithm, KeyBits: asset.KeyBits, AssetProtocol: asset.Protocol,
			Cipher: asset.Cipher, Library: asset.Library, Strength: asset.Strength,
			QuantumVulnerable: asset.QuantumVulnerable, OutOfPolicy: asset.OutOfPolicy,
			Reasons: append([]string(nil), asset.Reasons...), TargetAlgorithm: reissue.TargetAlgorithm,
			EffectiveAlgorithm: reissue.EffectiveAlgorithm, Protocol: reissue.Protocol,
			RollbackOnFailure: reissue.RollbackOnFailure,
		})
	}
	tlsPayloads := make([]pqcMigrationTLSPosturePayload, 0, len(plan.TLSRollouts))
	targetPostures := make(map[string]connector.TLSPosture, len(plan.TLSRollouts))
	for _, rollout := range plan.TLSRollouts {
		if s.deployer == nil {
			return Response{}, errors.New("pqcmigration: TLS posture deployer is not configured")
		}
		target, err := s.store.GetDeploymentTarget(ctx, tenantID, rollout.TargetID)
		if err != nil {
			return Response{}, err
		}
		if err := validateTLSRolloutTarget(target, s.deployer); err != nil {
			return Response{}, err
		}
		if prior, exists := targetPostures[target.ID]; exists && !connector.EqualTLSPosture(prior, rollout.Desired) {
			return Response{}, fmt.Errorf("pqcmigration: findings bound to target %s request conflicting TLS postures", target.ID)
		}
		targetPostures[target.ID] = clonePosture(rollout.Desired)
		asset := rollout.Asset
		tlsPayloads = append(tlsPayloads, pqcMigrationTLSPosturePayload{
			RunID: runID, AssetID: asset.ID, Kind: asset.Kind, FindingKind: rollout.FindingKind,
			Location: asset.Location, Algorithm: asset.Algorithm, KeyBits: asset.KeyBits,
			AssetProtocol: asset.Protocol, Cipher: asset.Cipher, Library: asset.Library,
			Strength: asset.Strength, QuantumVulnerable: asset.QuantumVulnerable,
			OutOfPolicy: asset.OutOfPolicy, Reasons: append([]string(nil), asset.Reasons...),
			TargetID: target.ID, TargetRevision: target.RevisionID, Connector: target.Type,
			Target: target.Name, TargetConfig: append(json.RawMessage(nil), target.Config...),
			Desired: clonePosture(rollout.Desired), RollbackOnFailure: rollout.RollbackOnFailure,
		})
	}
	for i := range tlsPayloads {
		payload := tlsPayloads[i]
		idempotencyKey := "licensed-crypto-migration-tls:" + payload.RunID + ":" + payload.AssetID
		sealedPayload, err := sealTLSPostureOutbox(
			s.integrityKey, tenantID, licensedCryptoMigrationTLSPostureDestination, idempotencyKey,
			payload.RunID, payload.AssetID, payload.TargetRevision, payload,
		)
		if err != nil {
			return Response{}, err
		}
		// The event is the crash-recovery owner of the exact ciphertext, never a
		// second plaintext copy of redirect-capable connector configuration.
		tlsPayloads[i].TargetConfig = nil
		tlsPayloads[i].SealedOutboxPayload = append(json.RawMessage(nil), sealedPayload...)
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = ProtocolACME
	}
	totalQueued := len(reissuePayloads) + len(tlsPayloads)
	started := projections.LicensedCryptoMigrationStarted{
		RunID: runID, AssetIDs: append([]string(nil), req.AssetIDs...), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: protocol,
		RollbackOnFailure: req.RollbackOnFailure, Queued: totalQueued,
		Reissues:    append([]projections.LicensedCryptoMigrationReissue(nil), reissuePayloads...),
		TLSPostures: append([]projections.LicensedCryptoMigrationTLSPosture(nil), tlsPayloads...),
	}
	data, err := json.Marshal(started)
	if err != nil {
		return Response{}, err
	}
	ev, err := s.log.Append(ctx, events.Event{Type: projections.EventLicensedCryptoMigrationStarted, TenantID: tenantID, Data: data})
	if err != nil {
		return Response{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := projections.New(s.store).ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		for _, payload := range reissuePayloads {
			body, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    licensedCryptoMigrationReissueDestination,
				IdempotencyKey: "licensed-crypto-migration:" + payload.RunID + ":" + payload.AssetID,
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		for _, payload := range tlsPayloads {
			if len(payload.SealedOutboxPayload) == 0 {
				return errors.New("pqcmigration: TLS posture intent is missing its sealed outbox payload")
			}
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: licensedCryptoMigrationTLSPostureDestination,
				IdempotencyKey: "licensed-crypto-migration-tls:" + payload.RunID + ":" + payload.AssetID,
				Payload:        append([]byte(nil), payload.SealedOutboxPayload...),
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return Response{}, err
	}
	return Response{
		RunID: runID, Queued: totalQueued, CertificateReissuesQueued: len(reissuePayloads),
		TLSFindingsQueued: len(tlsPayloads), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: protocol,
		RollbackConfigured: req.RollbackOnFailure,
		MigrationProgress:  api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:           time.Now().UTC(),
	}, nil
}

func validateTLSRolloutTarget(target store.DeploymentTarget, deployer connector.TLSPostureDeployer) error {
	if deployer == nil {
		return errors.New("pqcmigration: TLS posture deployer is not configured")
	}
	if !target.Enabled || target.ID == "" || target.RevisionID == "" || target.Type == "" || target.Name == "" {
		return fmt.Errorf("pqcmigration: deployment target %s is disabled or incomplete", target.ID)
	}
	if !deployer.SupportsTLSPosture(target.Type) {
		return fmt.Errorf("pqcmigration: deployment target %s connector %s does not support TLS posture mutation", target.ID, target.Type)
	}
	return nil
}

func (s *pqcMigrationService) Progress(ctx context.Context, tenantID, runID string) (RunProgressResponse, error) {
	if s.log == nil || s.progress == nil || tenantID == "" || runID == "" {
		return RunProgressResponse{}, pgx.ErrNoRows
	}
	found := false
	if err := s.log.Replay(ctx, 0, func(e events.Event) error {
		if found || e.TenantID != tenantID || e.Type != projections.EventLicensedCryptoMigrationStarted {
			return nil
		}
		var started projections.LicensedCryptoMigrationStarted
		if err := json.Unmarshal(e.Data, &started); err != nil {
			return err
		}
		found = started.RunID == runID
		return nil
	}); err != nil {
		return RunProgressResponse{}, err
	}
	if !found {
		return RunProgressResponse{}, pgx.ErrNoRows
	}
	resp := RunProgressResponse{RunID: runID, Findings: s.progress.Snapshot(tenantID, runID)}
	resp.Total = len(resp.Findings)
	for _, finding := range resp.Findings {
		switch finding.Status {
		case TLSFindingQueued:
			resp.Queued++
		case TLSFindingApplied:
			resp.Applied++
		case TLSFindingFailed, TLSFindingRollbackFailed:
			resp.Failed++
		case TLSFindingRolledBack:
			resp.RolledBack++
		}
	}
	return resp, nil
}

type tlsRollbackGroup struct {
	firstSequence uint64
	first         TLSFindingCompleted
	completed     []TLSFindingCompleted
}

func (s *pqcMigrationService) Rollback(ctx context.Context, tenantID, runID string, req RollbackRequest) (RollbackResponse, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return RollbackResponse{}, errors.New("server: PQC rollback requires store, event log, and outbox")
	}
	wanted := make(map[string]bool, len(req.AssetIDs))
	for _, id := range req.AssetIDs {
		if id == "" || wanted[id] {
			return RollbackResponse{}, errors.New("pqcmigration: rollback asset ids must be non-empty and unique")
		}
		wanted[id] = true
	}
	certCompleted := make(map[string]projections.LicensedCryptoMigrationAssetCompleted)
	tlsStarted := make(map[string]projections.LicensedCryptoMigrationTLSPosture)
	tlsPrepared := make(map[string]TLSFindingPrepared)
	tlsCompleted := make(map[string]TLSFindingCompleted)
	tlsSequence := make(map[string]uint64)
	tlsFailed := make(map[string]bool)
	rolledBack := make(map[string]bool)
	if err := s.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != tenantID {
			return nil
		}
		switch e.Type {
		case projections.EventLicensedCryptoMigrationStarted:
			var started projections.LicensedCryptoMigrationStarted
			if err := json.Unmarshal(e.Data, &started); err != nil {
				return err
			}
			if started.RunID == runID {
				for _, intent := range started.TLSPostures {
					tlsStarted[intent.AssetID] = intent
				}
			}
		case projections.EventLicensedCryptoMigrationAssetCompleted:
			var completed projections.LicensedCryptoMigrationAssetCompleted
			if err := json.Unmarshal(e.Data, &completed); err != nil {
				return err
			}
			if completed.RunID == runID {
				certCompleted[completed.AssetID] = completed
			}
		case projections.EventLicensedCryptoMigrationRollbackCompleted:
			var completed projections.LicensedCryptoMigrationRollbackCompleted
			if err := json.Unmarshal(e.Data, &completed); err != nil {
				return err
			}
			if completed.RunID == runID {
				rolledBack[completed.AssetID] = true
			}
		case EventTLSFindingCompleted:
			var completed TLSFindingCompleted
			if err := json.Unmarshal(e.Data, &completed); err != nil {
				return err
			}
			if completed.Intent.RunID == runID {
				tlsCompleted[completed.Intent.AssetID] = completed
				tlsSequence[completed.Intent.AssetID] = e.Sequence
			}
		case EventTLSFindingPrepared:
			var prepared TLSFindingPrepared
			if err := json.Unmarshal(e.Data, &prepared); err != nil {
				return err
			}
			if prepared.RunID == runID {
				tlsPrepared[prepared.AssetID] = prepared
			}
		case EventTLSFindingRollbackCompleted:
			var completed TLSFindingRollbackCompleted
			if err := json.Unmarshal(e.Data, &completed); err != nil {
				return err
			}
			if completed.RunID == runID {
				for _, restore := range completed.Restores {
					rolledBack[restore.AssetID] = true
				}
			}
		case EventTLSFindingFailed:
			var failed TLSFindingFailure
			if err := json.Unmarshal(e.Data, &failed); err != nil {
				return err
			}
			if failed.RunID == runID {
				tlsFailed[failed.AssetID] = true
			}
		}
		return nil
	}); err != nil {
		return RollbackResponse{}, err
	}
	certPayloads := make([]pqcMigrationRollbackPayload, 0, len(req.AssetIDs))
	groups := make(map[string]*tlsRollbackGroup)
	foundWanted := make(map[string]bool, len(wanted))
	for assetID, completed := range certCompleted {
		if !wanted[assetID] || rolledBack[assetID] {
			continue
		}
		foundWanted[assetID] = true
		restore := projections.LicensedCryptoMigrationRollbackCompleted{
			RunID: runID, AssetID: completed.AssetID, Kind: completed.Kind, Location: completed.Location,
			Algorithm: completed.OriginalAlgorithm, KeyBits: completed.OriginalKeyBits,
			Protocol: completed.OriginalProtocol, Cipher: completed.OriginalCipher,
			Library: completed.OriginalLibrary, Strength: completed.OriginalStrength,
			QuantumVulnerable: completed.OriginalQuantumVulnerable,
			OutOfPolicy:       completed.OriginalOutOfPolicy, Reasons: append([]string(nil), completed.OriginalReasons...),
			Reason: req.Reason,
		}
		certPayloads = append(certPayloads, pqcMigrationRollbackPayload{RunID: runID, Reason: req.Reason, Restore: restore})
	}
	for assetID, completed := range tlsCompleted {
		if rolledBack[assetID] {
			continue
		}
		targetID := completed.Intent.TargetID
		group := groups[targetID]
		if group == nil {
			group = &tlsRollbackGroup{firstSequence: tlsSequence[assetID], first: completed}
			groups[targetID] = group
		}
		if tlsSequence[assetID] < group.firstSequence {
			group.firstSequence, group.first = tlsSequence[assetID], completed
		}
		group.completed = append(group.completed, completed)
	}
	tlsPayloads := make([]pqcMigrationTLSRollbackPayload, 0, len(groups))
	for targetID, group := range groups {
		if err := validateTLSRollbackTargetReady(targetID, tlsStarted, tlsCompleted, tlsFailed, rolledBack); err != nil {
			return RollbackResponse{}, err
		}
		sort.Slice(group.completed, func(i, j int) bool {
			return group.completed[i].Intent.AssetID < group.completed[j].Intent.AssetID
		})
		selected := 0
		for _, completed := range group.completed {
			if wanted[completed.Intent.AssetID] {
				selected++
			}
		}
		if selected == 0 {
			continue
		}
		if selected != len(group.completed) {
			return RollbackResponse{}, fmt.Errorf("pqcmigration: rollback must include every applied finding bound to target %s", targetID)
		}
		first := group.first
		prepared, ok := tlsPrepared[first.Intent.AssetID]
		if !ok || prepared.TargetID != first.Intent.TargetID || prepared.TargetRevision != first.Intent.TargetRevision ||
			!connector.EqualTLSPosture(prepared.Previous, first.Receipt.Previous) {
			return RollbackResponse{}, fmt.Errorf("pqcmigration: target %s has no matching durable pre-mutation posture", targetID)
		}
		forwardIntent, err := openCompletedTLSForwardIntent(s.integrityKey, tenantID, first)
		if err != nil {
			return RollbackResponse{}, err
		}
		payload := pqcMigrationTLSRollbackPayload{
			RunID: runID, Reason: req.Reason,
			Mutation: connector.TLSPostureMutation{
				RunID: runID, FindingID: "rollback:" + targetID, FindingKind: "rollback",
				TargetID: first.Intent.TargetID, TargetRevision: first.Intent.TargetRevision,
				Connector: first.Intent.Connector, Target: first.Intent.Target,
				TargetConfig: append(json.RawMessage(nil), forwardIntent.TargetConfig...),
				Desired:      clonePosture(first.Receipt.Previous),
			},
		}
		expected := clonePosture(first.Receipt.Observed)
		payload.Mutation.ExpectedPrevious = &expected
		for _, completed := range group.completed {
			intent := completed.Intent
			foundWanted[intent.AssetID] = true
			payload.Restores = append(payload.Restores, TLSAssetRestore{
				RunID: runID, AssetID: intent.AssetID, Kind: intent.Kind, Location: intent.Location,
				Algorithm: intent.Algorithm, KeyBits: intent.KeyBits, Protocol: intent.AssetProtocol,
				Cipher: intent.Cipher, Library: intent.Library, Strength: intent.Strength,
				QuantumVulnerable: intent.QuantumVulnerable, OutOfPolicy: intent.OutOfPolicy,
				Reasons: append([]string(nil), intent.Reasons...), FindingKind: intent.FindingKind,
				TargetID: intent.TargetID,
			})
		}
		tlsPayloads = append(tlsPayloads, payload)
	}
	for id := range wanted {
		if !foundWanted[id] {
			return RollbackResponse{}, fmt.Errorf("pqcmigration: asset %s has no applied, rollback-eligible result in run %s", id, runID)
		}
	}
	if len(certPayloads) == 0 && len(tlsPayloads) == 0 {
		return RollbackResponse{}, pgx.ErrNoRows
	}
	sort.Slice(tlsPayloads, func(i, j int) bool {
		return tlsPayloads[i].Mutation.TargetID < tlsPayloads[j].Mutation.TargetID
	})
	sealedTLS := make([]sealedTLSRollbackIntent, 0, len(tlsPayloads))
	for _, payload := range tlsPayloads {
		if len(payload.Restores) == 0 {
			return RollbackResponse{}, errors.New("pqcmigration: TLS rollback payload has no asset restores")
		}
		idempotencyKey := "licensed-crypto-migration-tls-rollback:" + runID + ":" + payload.Mutation.TargetID
		body, err := sealTLSPostureOutbox(
			s.integrityKey, tenantID, licensedCryptoMigrationTLSRollbackDestination, idempotencyKey,
			payload.RunID, payload.Restores[0].AssetID, payload.Mutation.TargetRevision, payload,
		)
		if err != nil {
			return RollbackResponse{}, err
		}
		assetIDs := make([]string, 0, len(payload.Restores))
		for _, restore := range payload.Restores {
			assetIDs = append(assetIDs, restore.AssetID)
		}
		sealedTLS = append(sealedTLS, sealedTLSRollbackIntent{
			TargetID: payload.Mutation.TargetID, AssetIDs: assetIDs, IdempotencyKey: idempotencyKey,
			Payload: append(json.RawMessage(nil), body...),
		})
	}
	var rollbackEvent *events.Event
	if len(sealedTLS) > 0 {
		data, err := json.Marshal(tlsRollbackRequested{RunID: runID, Intents: sealedTLS})
		if err != nil {
			return RollbackResponse{}, err
		}
		ev, err := s.log.Append(ctx, events.Event{Type: eventTLSRollbackRequested, TenantID: tenantID, Data: data})
		if err != nil {
			return RollbackResponse{}, err
		}
		rollbackEvent = &ev
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if rollbackEvent != nil {
			if err := projections.New(s.store).ApplyTx(ctx, tx, *rollbackEvent); err != nil {
				return err
			}
		}
		for _, payload := range certPayloads {
			body, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    licensedCryptoMigrationRollbackDestination,
				IdempotencyKey: "licensed-crypto-migration-rollback:" + payload.RunID + ":" + payload.Restore.AssetID,
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		for _, intent := range sealedTLS {
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: licensedCryptoMigrationTLSRollbackDestination,
				IdempotencyKey: intent.IdempotencyKey,
				Payload:        append([]byte(nil), intent.Payload...),
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return RollbackResponse{}, err
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return RollbackResponse{}, err
	}
	return RollbackResponse{
		RunID: runID, Queued: len(foundWanted), Reason: req.Reason,
		MigrationProgress: api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:          time.Now().UTC(),
	}, nil
}

func openCompletedTLSForwardIntent(key seal.KeyWrapper, tenantID string, completed TLSFindingCompleted) (pqcMigrationTLSPosturePayload, error) {
	intent := completed.Intent
	if len(intent.SealedOutboxPayload) == 0 {
		return pqcMigrationTLSPosturePayload{}, errors.New("pqcmigration: applied TLS finding is missing its sealed forward intent")
	}
	idempotencyKey := "licensed-crypto-migration-tls:" + intent.RunID + ":" + intent.AssetID
	var opened pqcMigrationTLSPosturePayload
	wrapper, err := openTLSPostureOutbox(
		key, tenantID, licensedCryptoMigrationTLSPostureDestination, idempotencyKey,
		intent.SealedOutboxPayload, &opened,
	)
	if err != nil {
		return pqcMigrationTLSPosturePayload{}, err
	}
	if wrapper.RunID != intent.RunID || wrapper.AssetID != intent.AssetID ||
		wrapper.TargetRevision != intent.TargetRevision || opened.RunID != intent.RunID ||
		opened.AssetID != intent.AssetID || opened.TargetID != intent.TargetID ||
		opened.TargetRevision != intent.TargetRevision || opened.Connector != intent.Connector ||
		opened.Target != intent.Target || !connector.EqualTLSPosture(opened.Desired, intent.Desired) {
		return pqcMigrationTLSPosturePayload{}, errors.New("pqcmigration: sealed forward intent does not match completed finding")
	}
	if len(opened.TargetConfig) == 0 {
		return pqcMigrationTLSPosturePayload{}, errors.New("pqcmigration: sealed forward intent has no target configuration")
	}
	return opened, nil
}

func validateTLSRollbackTargetReady(
	targetID string,
	started map[string]projections.LicensedCryptoMigrationTLSPosture,
	completed map[string]TLSFindingCompleted,
	failed, rolledBack map[string]bool,
) error {
	seen := false
	for assetID, intent := range started {
		if intent.TargetID != targetID {
			continue
		}
		seen = true
		if rolledBack[assetID] || failed[assetID] {
			continue
		}
		if _, applied := completed[assetID]; !applied {
			return fmt.Errorf("pqcmigration: target %s still has unresolved queued finding %s", targetID, assetID)
		}
	}
	if !seen {
		return fmt.Errorf("pqcmigration: target %s has no bound start intent in the run", targetID)
	}
	return nil
}

func (h *outboxHandler) handlePQCReissue(ctx context.Context, m orchestrator.Message) error {
	if h.store == nil || h.log == nil || (h.idem == nil && h.idempotencyDo == nil) || h.issue == nil {
		return errors.New("pqcmigration: outbox handler requires store, event log, idempotency, and protocol issuer")
	}
	var payload pqcMigrationReissuePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration reissue payload: %w", err)
	}
	_, err := h.doIdempotent(ctx, m.TenantID, "licensed-crypto-migration-reissue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		csrDER, err := buildPQCMigrationHybridCSR(payload.Location)
		if err != nil {
			return nil, err
		}
		leafDER, err := h.issue(ctx, m.TenantID, payload.Protocol, "licensed-crypto-migration:"+payload.RunID+":"+payload.AssetID, csrDER)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			return nil, err
		}
		if err := setHybridLeafInfo(&info, leafDER); err != nil {
			return nil, err
		}
		completed := projections.LicensedCryptoMigrationAssetCompleted{
			RunID: payload.RunID, AssetID: payload.AssetID, Kind: payload.Kind, Location: payload.Location,
			OriginalAlgorithm: payload.Algorithm, OriginalKeyBits: payload.KeyBits,
			OriginalProtocol: payload.AssetProtocol, OriginalCipher: payload.Cipher,
			OriginalLibrary: payload.Library, OriginalStrength: payload.Strength,
			OriginalQuantumVulnerable: payload.QuantumVulnerable,
			OriginalOutOfPolicy:       payload.OutOfPolicy,
			OriginalReasons:           append([]string(nil), payload.Reasons...),
			TargetAlgorithm:           payload.TargetAlgorithm, EffectiveAlgorithm: info.KeyAlgorithm,
			EffectiveKeyBits: info.PublicKeyBits, Protocol: payload.Protocol,
			CertificateFingerprint: info.SHA256Fingerprint,
			RollbackRef:            "cbom-asset:" + payload.AssetID + ":algorithm:" + payload.Algorithm,
		}
		if err := h.appendProjected(ctx, m.TenantID, projections.EventLicensedCryptoMigrationAssetCompleted, completed); err != nil {
			return nil, err
		}
		return []byte(info.SHA256Fingerprint), nil
	})
	return err
}

func (h *outboxHandler) handleTLSPosture(ctx context.Context, m orchestrator.Message) error {
	if (h.appendEvent == nil && (h.store == nil || h.log == nil)) || (h.idem == nil && h.idempotencyDo == nil) || h.deployer == nil {
		return errors.New("pqcmigration: TLS posture handler requires store, event log, idempotency, and deployer")
	}
	var payload pqcMigrationTLSPosturePayload
	wrapped, err := openTLSPostureOutbox(h.integrityKey, m.TenantID, m.Destination, m.IdempotencyKey, m.Payload, &payload)
	if err != nil {
		return err
	}
	if payload.RunID != wrapped.RunID || payload.AssetID != wrapped.AssetID || payload.TargetRevision != wrapped.TargetRevision {
		return errors.New("pqcmigration: sealed TLS posture metadata does not match intent")
	}
	payload.SealedOutboxPayload = nil
	_, err = h.doIdempotent(ctx, m.TenantID, "licensed-crypto-migration-tls:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		recovered, found, err := h.completedTLSFinding(ctx, m.TenantID, payload, m.Payload)
		if err != nil {
			return nil, err
		}
		if found {
			return json.Marshal(recovered.Receipt)
		}
		mutation := connector.TLSPostureMutation{
			RunID: payload.RunID, FindingID: payload.AssetID, FindingKind: payload.FindingKind,
			TargetID: payload.TargetID, TargetRevision: payload.TargetRevision,
			Connector: payload.Connector, Target: payload.Target,
			TargetConfig: append(json.RawMessage(nil), payload.TargetConfig...),
			Desired:      clonePosture(payload.Desired), TenantID: m.TenantID,
		}
		previous, prepared, err := h.preparedTLSPosture(ctx, m.TenantID, payload)
		if err != nil {
			return nil, err
		}
		if !prepared {
			previous, err = h.deployer.ReadTLSPosture(ctx, mutation)
			if err != nil {
				return nil, err
			}
			if err := h.appendProjected(ctx, m.TenantID, EventTLSFindingPrepared, TLSFindingPrepared{
				RunID: payload.RunID, AssetID: payload.AssetID, FindingKind: payload.FindingKind,
				TargetID: payload.TargetID, TargetRevision: payload.TargetRevision,
				Connector: payload.Connector, Previous: clonePosture(previous),
			}); err != nil {
				return nil, err
			}
		}
		expected := clonePosture(previous)
		mutation.ExpectedPrevious = &expected
		receipt, err := h.deployer.ApplyTLSPosture(ctx, mutation)
		if err != nil {
			return nil, err
		}
		if h.afterTLSApply != nil {
			if err := h.afterTLSApply(); err != nil {
				return nil, err
			}
		}
		eventIntent := payload
		eventIntent.TargetConfig = nil
		eventIntent.SealedOutboxPayload = append(json.RawMessage(nil), m.Payload...)
		completed := TLSFindingCompleted{Intent: eventIntent, Receipt: receipt}
		if err := h.appendProjected(ctx, m.TenantID, EventTLSFindingCompleted, completed); err != nil {
			return nil, err
		}
		return json.Marshal(receipt)
	})
	return err
}

func (h *outboxHandler) completedTLSFinding(ctx context.Context, tenantID string, intent pqcMigrationTLSPosturePayload, sealedPayload []byte) (TLSFindingCompleted, bool, error) {
	if h.lookupCompleted != nil {
		return h.lookupCompleted(ctx, tenantID, intent, sealedPayload)
	}
	if h.log == nil {
		// Focused unit handlers supply append/lookup hooks and begin without a
		// completion. Production always owns the event log.
		return TLSFindingCompleted{}, false, nil
	}
	var completed TLSFindingCompleted
	found := false
	err := h.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != EventTLSFindingCompleted {
			return nil
		}
		var candidate TLSFindingCompleted
		if err := json.Unmarshal(ev.Data, &candidate); err != nil {
			return err
		}
		if candidate.Intent.RunID != intent.RunID || candidate.Intent.AssetID != intent.AssetID {
			return nil
		}
		if err := validateCompletedTLSFinding(intent, sealedPayload, candidate); err != nil {
			return err
		}
		if found && (!connector.EqualTLSPosture(completed.Receipt.Previous, candidate.Receipt.Previous) ||
			!connector.EqualTLSPosture(completed.Receipt.Observed, candidate.Receipt.Observed)) {
			return errors.New("pqcmigration: conflicting completed TLS finding events")
		}
		completed, found = candidate, true
		return nil
	})
	return completed, found, err
}

func validateCompletedTLSFinding(intent pqcMigrationTLSPosturePayload, sealedPayload []byte, candidate TLSFindingCompleted) error {
	if candidate.Intent.RunID != intent.RunID || candidate.Intent.AssetID != intent.AssetID ||
		candidate.Intent.FindingKind != intent.FindingKind || candidate.Intent.TargetID != intent.TargetID ||
		candidate.Intent.TargetRevision != intent.TargetRevision || candidate.Intent.Connector != intent.Connector ||
		candidate.Intent.Target != intent.Target || !connector.EqualTLSPosture(candidate.Intent.Desired, intent.Desired) ||
		!bytes.Equal(candidate.Intent.SealedOutboxPayload, sealedPayload) ||
		candidate.Receipt.RunID != intent.RunID || candidate.Receipt.FindingID != intent.AssetID ||
		candidate.Receipt.FindingKind != intent.FindingKind || candidate.Receipt.TargetID != intent.TargetID ||
		candidate.Receipt.TargetRevision != intent.TargetRevision || candidate.Receipt.Connector != intent.Connector ||
		!connector.EqualTLSPosture(candidate.Receipt.Observed, intent.Desired) {
		return errors.New("pqcmigration: completed TLS finding binding mismatch")
	}
	if err := connector.ValidateObservedTLSPosture(candidate.Receipt.Previous); err != nil {
		return fmt.Errorf("pqcmigration: completed TLS finding previous posture: %w", err)
	}
	return nil
}

func (h *outboxHandler) preparedTLSPosture(ctx context.Context, tenantID string, intent pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error) {
	if h.lookupPrepared != nil {
		return h.lookupPrepared(ctx, tenantID, intent)
	}
	if h.log == nil {
		return connector.TLSPosture{}, false, errors.New("pqcmigration: prepared TLS posture lookup requires the event log")
	}
	var previous connector.TLSPosture
	found := false
	err := h.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != EventTLSFindingPrepared {
			return nil
		}
		var prepared TLSFindingPrepared
		if err := json.Unmarshal(ev.Data, &prepared); err != nil {
			return err
		}
		if prepared.RunID != intent.RunID || prepared.AssetID != intent.AssetID {
			return nil
		}
		if prepared.FindingKind != intent.FindingKind || prepared.TargetID != intent.TargetID ||
			prepared.TargetRevision != intent.TargetRevision || prepared.Connector != intent.Connector {
			return errors.New("pqcmigration: prepared TLS posture binding mismatch")
		}
		if found && !connector.EqualTLSPosture(previous, prepared.Previous) {
			return errors.New("pqcmigration: conflicting prepared TLS posture events")
		}
		previous, found = clonePosture(prepared.Previous), true
		return nil
	})
	return previous, found, err
}

func (h *outboxHandler) handleTLSPostureRollback(ctx context.Context, m orchestrator.Message) error {
	if (h.appendEvent == nil && (h.store == nil || h.log == nil)) || (h.idem == nil && h.idempotencyDo == nil) || h.deployer == nil {
		return errors.New("pqcmigration: TLS posture rollback requires store, event log, idempotency, and deployer")
	}
	var payload pqcMigrationTLSRollbackPayload
	wrapped, err := openTLSPostureOutbox(h.integrityKey, m.TenantID, m.Destination, m.IdempotencyKey, m.Payload, &payload)
	if err != nil {
		return err
	}
	if len(payload.Restores) == 0 || payload.RunID != wrapped.RunID ||
		payload.Restores[0].AssetID != wrapped.AssetID || payload.Mutation.TargetRevision != wrapped.TargetRevision {
		return errors.New("pqcmigration: sealed TLS rollback metadata does not match intent")
	}
	_, err = h.doIdempotent(ctx, m.TenantID, "licensed-crypto-migration-tls-rollback:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		mutation := payload.Mutation
		mutation.TenantID = m.TenantID
		mutation.TargetConfig = append(json.RawMessage(nil), mutation.TargetConfig...)
		mutation.Desired = clonePosture(mutation.Desired)
		if mutation.ExpectedPrevious != nil {
			expected := clonePosture(*mutation.ExpectedPrevious)
			mutation.ExpectedPrevious = &expected
		}
		receipt, err := h.deployer.RestoreTLSPosture(ctx, mutation)
		if err != nil {
			return nil, err
		}
		completed := TLSFindingRollbackCompleted{
			RunID: payload.RunID, Restores: append([]TLSAssetRestore(nil), payload.Restores...), Receipt: receipt,
		}
		if err := h.appendProjected(ctx, m.TenantID, EventTLSFindingRollbackCompleted, completed); err != nil {
			return nil, err
		}
		return json.Marshal(receipt)
	})
	return err
}

func setHybridLeafInfo(info *certinfo.Info, leafDER []byte) error {
	hybrid, err := eepqc.InspectHybridLeaf(leafDER)
	if err != nil {
		return err
	}
	if hybrid.CompositeAlgorithmOID == eepqc.CompositeMLDSA44ECDSAP256SHA256OID &&
		hybrid.MLDSAAlgorithm == eepqc.MLDSA44 &&
		hybrid.TraditionalAlgorithm == crypto.ECDSAP256 {
		info.KeyAlgorithm = eepqc.HybridMLDSA44ECDSAP256Algorithm
	}
	return nil
}

func (h *outboxHandler) handlePQCRollback(ctx context.Context, m orchestrator.Message) error {
	if h.store == nil || h.log == nil || (h.idem == nil && h.idempotencyDo == nil) {
		return errors.New("pqcmigration: rollback handler requires store, event log, and idempotency")
	}
	var payload pqcMigrationRollbackPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration rollback payload: %w", err)
	}
	_, err := h.doIdempotent(ctx, m.TenantID, "licensed-crypto-migration-rollback:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		payload.Restore.Reason = payload.Reason
		if err := h.appendProjected(ctx, m.TenantID, projections.EventLicensedCryptoMigrationRollbackCompleted, payload.Restore); err != nil {
			return nil, err
		}
		return []byte(payload.Restore.AssetID), nil
	})
	return err
}

func (h *outboxHandler) appendProjected(ctx context.Context, tenantID, eventType string, payload any) error {
	if h.appendEvent != nil {
		return h.appendEvent(ctx, tenantID, eventType, payload)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev, err := h.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	opts := []projections.Option{}
	if h.progress != nil {
		opts = append(opts, WithProgressProjection(h.progress))
	}
	return projections.New(h.store, opts...).Apply(ctx, ev)
}

func buildPQCMigrationHybridCSR(location string) ([]byte, error) {
	domain := dnsNameFromLocation(location)
	// Crypto agility here is compile-time DI in the prior-art style of Go
	// crypto.Signer: the concrete generators are linked behind internal/crypto. It
	// is not a JCA/OpenSSL ENGINE/PKCS#11-style runtime provider registration path,
	// and policy never feeds a runtime crypto engine.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	mldsaKey, err := eepqc.GenerateKey(eepqc.MLDSA44)
	if err != nil {
		return nil, err
	}
	defer mldsaKey.Destroy()
	hybridExt, err := eepqc.HybridLeafCSRExtraExtension(key.Public(), mldsaKey)
	if err != nil {
		return nil, err
	}
	return crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: domain, DNSNames: []string{domain}, ExtraExtensions: []crypto.CertificateExtension{hybridExt},
	}, key)
}

func dnsNameFromLocation(location string) string {
	host := strings.TrimSpace(location)
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "pqc-migration.local"
	}
	return host
}

func pqcMigrationAssets(assets []store.CryptoAsset) []Asset {
	out := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		out = append(out, Asset{
			ID: asset.ID, Kind: asset.Kind, Location: asset.Location,
			Algorithm: asset.Algorithm, KeyBits: asset.KeyBits, Protocol: asset.Protocol,
			Cipher: asset.Cipher, Library: asset.Library, Strength: asset.Strength,
			QuantumVulnerable: asset.QuantumVulnerable, OutOfPolicy: asset.OutOfPolicy,
			Reasons: append([]string(nil), asset.Reasons...),
		})
	}
	return out
}
