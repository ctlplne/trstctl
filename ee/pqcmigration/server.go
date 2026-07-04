// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	licensedCryptoMigrationReissueDestination  = "licensed_crypto.migration.reissue"
	licensedCryptoMigrationRollbackDestination = "licensed_crypto.migration.rollback"
)

type pqcMigrationService struct {
	store  *store.Store
	log    *events.Log
	outbox *orchestrator.Outbox
}

func NewOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		return &outboxHandler{store: d.Store, log: d.Log, idem: d.Idempotency, issue: d.IssueProtocolLeaf}, nil
	}
}

type outboxHandler struct {
	store *store.Store
	log   *events.Log
	idem  *orchestrator.Idempotency
	issue editionseam.ProtocolLeafIssuer
}

func (h *outboxHandler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	switch m.Destination {
	case licensedCryptoMigrationReissueDestination:
		return true, h.handlePQCReissue(ctx, m)
	case licensedCryptoMigrationRollbackDestination:
		return true, h.handlePQCRollback(ctx, m)
	default:
		return false, nil
	}
}

type pqcMigrationReissuePayload = projections.LicensedCryptoMigrationReissue

type pqcMigrationRollbackPayload struct {
	RunID   string                                               `json:"run_id"`
	Reason  string                                               `json:"reason"`
	Restore projections.LicensedCryptoMigrationRollbackCompleted `json:"restore"`
}

func (s *pqcMigrationService) Start(ctx context.Context, tenantID string, req APIRequest) (Response, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return Response{}, errors.New("server: PQC migration requires store, event log, and outbox")
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return Response{}, err
	}
	plan, err := BuildPlan(pqcMigrationAssets(assets), Request{
		AssetIDs: req.AssetIDs, TargetAlgorithm: req.TargetAlgorithm, Protocol: req.Protocol,
		RollbackOnFailure: req.RollbackOnFailure,
	})
	if err != nil {
		var missing AssetNotFoundError
		if errors.As(err, &missing) {
			return Response{}, pgx.ErrNoRows
		}
		return Response{}, err
	}
	runID := uuid.NewString()
	payloads := make([]pqcMigrationReissuePayload, 0, len(req.AssetIDs))
	for _, reissue := range plan.Reissues {
		asset := reissue.Asset
		payloads = append(payloads, pqcMigrationReissuePayload{
			RunID: runID, AssetID: asset.ID, Kind: asset.Kind, Location: asset.Location,
			Algorithm: asset.Algorithm, KeyBits: asset.KeyBits, AssetProtocol: asset.Protocol,
			Cipher: asset.Cipher, Library: asset.Library, Strength: asset.Strength,
			QuantumVulnerable: asset.QuantumVulnerable, OutOfPolicy: asset.OutOfPolicy,
			Reasons: append([]string(nil), asset.Reasons...), TargetAlgorithm: reissue.TargetAlgorithm,
			EffectiveAlgorithm: reissue.EffectiveAlgorithm, Protocol: reissue.Protocol,
			RollbackOnFailure: reissue.RollbackOnFailure,
		})
	}
	started := projections.LicensedCryptoMigrationStarted{
		RunID: runID, AssetIDs: append([]string(nil), req.AssetIDs...), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: req.Protocol,
		RollbackOnFailure: req.RollbackOnFailure, Queued: len(payloads),
		Reissues: append([]projections.LicensedCryptoMigrationReissue(nil), payloads...),
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
		for _, payload := range payloads {
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
		return nil
	}); err != nil {
		return Response{}, err
	}
	return Response{
		RunID: runID, Queued: len(payloads), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: req.Protocol,
		RollbackConfigured: req.RollbackOnFailure,
		MigrationProgress:  api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:           time.Now().UTC(),
	}, nil
}

func (s *pqcMigrationService) Rollback(ctx context.Context, tenantID, runID string, req RollbackRequest) (RollbackResponse, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return RollbackResponse{}, errors.New("server: PQC rollback requires store, event log, and outbox")
	}
	wanted := make(map[string]bool, len(req.AssetIDs))
	for _, id := range req.AssetIDs {
		wanted[id] = true
	}
	payloads := make([]pqcMigrationRollbackPayload, 0, len(req.AssetIDs))
	if err := s.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != tenantID || e.Type != projections.EventLicensedCryptoMigrationAssetCompleted {
			return nil
		}
		var completed projections.LicensedCryptoMigrationAssetCompleted
		if err := json.Unmarshal(e.Data, &completed); err != nil {
			return err
		}
		if completed.RunID != runID || !wanted[completed.AssetID] {
			return nil
		}
		restore := projections.LicensedCryptoMigrationRollbackCompleted{
			RunID: runID, AssetID: completed.AssetID, Kind: completed.Kind, Location: completed.Location,
			Algorithm: completed.OriginalAlgorithm, KeyBits: completed.OriginalKeyBits,
			Protocol: completed.OriginalProtocol, Cipher: completed.OriginalCipher,
			Library: completed.OriginalLibrary, Strength: completed.OriginalStrength,
			QuantumVulnerable: completed.OriginalQuantumVulnerable,
			OutOfPolicy:       completed.OriginalOutOfPolicy,
			Reasons:           append([]string(nil), completed.OriginalReasons...),
			Reason:            req.Reason,
		}
		payloads = append(payloads, pqcMigrationRollbackPayload{RunID: runID, Reason: req.Reason, Restore: restore})
		return nil
	}); err != nil {
		return RollbackResponse{}, err
	}
	if len(payloads) == 0 {
		return RollbackResponse{}, pgx.ErrNoRows
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, payload := range payloads {
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
		return nil
	}); err != nil {
		return RollbackResponse{}, err
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return RollbackResponse{}, err
	}
	return RollbackResponse{
		RunID: runID, Queued: len(payloads), Reason: req.Reason,
		MigrationProgress: api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:          time.Now().UTC(),
	}, nil
}

func (h *outboxHandler) handlePQCReissue(ctx context.Context, m orchestrator.Message) error {
	if h.store == nil || h.log == nil || h.idem == nil || h.issue == nil {
		return errors.New("pqcmigration: outbox handler requires store, event log, idempotency, and protocol issuer")
	}
	var payload pqcMigrationReissuePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration reissue payload: %w", err)
	}
	_, err := h.idem.Do(ctx, m.TenantID, "licensed-crypto-migration-reissue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
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
	if h.store == nil || h.log == nil || h.idem == nil {
		return errors.New("pqcmigration: rollback handler requires store, event log, and idempotency")
	}
	var payload pqcMigrationRollbackPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration rollback payload: %w", err)
	}
	_, err := h.idem.Do(ctx, m.TenantID, "licensed-crypto-migration-rollback:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		payload.Restore.Reason = payload.Reason
		if err := h.appendProjected(ctx, m.TenantID, projections.EventLicensedCryptoMigrationRollbackCompleted, payload.Restore); err != nil {
			return nil, err
		}
		return []byte(payload.Restore.AssetID), nil
	})
	return err
}

func (h *outboxHandler) appendProjected(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev, err := h.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return projections.New(h.store).Apply(ctx, ev)
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
