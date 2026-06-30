package server

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

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/pqc"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	pqcMigrationReissueDestination  = "pqc.migration.reissue"
	pqcMigrationRollbackDestination = "pqc.migration.rollback"
)

type pqcMigrationService struct {
	store  *store.Store
	log    *events.Log
	outbox *orchestrator.Outbox
}

func (s *Server) buildPQCMigrationService(d Deps) api.PQCMigrationService {
	return &pqcMigrationService{store: d.Store, log: d.Log, outbox: s.outbox}
}

type pqcMigrationReissuePayload struct {
	RunID              string   `json:"run_id"`
	AssetID            string   `json:"asset_id"`
	Kind               string   `json:"kind"`
	Location           string   `json:"location"`
	Algorithm          string   `json:"algorithm"`
	KeyBits            int      `json:"key_bits,omitempty"`
	AssetProtocol      string   `json:"asset_protocol,omitempty"`
	Cipher             string   `json:"cipher,omitempty"`
	Library            string   `json:"library,omitempty"`
	Strength           string   `json:"strength"`
	QuantumVulnerable  bool     `json:"quantum_vulnerable"`
	OutOfPolicy        bool     `json:"out_of_policy"`
	Reasons            []string `json:"reasons,omitempty"`
	TargetAlgorithm    string   `json:"target_algorithm"`
	EffectiveAlgorithm string   `json:"effective_algorithm"`
	Protocol           string   `json:"protocol"`
	RollbackOnFailure  bool     `json:"rollback_on_failure"`
}

type pqcMigrationRollbackPayload struct {
	RunID   string                                    `json:"run_id"`
	Reason  string                                    `json:"reason"`
	Restore projections.PQCMigrationRollbackCompleted `json:"restore"`
}

func (s *pqcMigrationService) Start(ctx context.Context, tenantID string, req api.PQCMigrationRequest) (api.PQCMigrationResponse, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return api.PQCMigrationResponse{}, errors.New("server: PQC migration requires store, event log, and outbox")
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return api.PQCMigrationResponse{}, err
	}
	plan, err := pqcmigration.BuildPlan(pqcMigrationAssets(assets), pqcmigration.Request{
		AssetIDs: req.AssetIDs, TargetAlgorithm: req.TargetAlgorithm, Protocol: req.Protocol,
		RollbackOnFailure: req.RollbackOnFailure,
	})
	if err != nil {
		var missing pqcmigration.AssetNotFoundError
		if errors.As(err, &missing) {
			return api.PQCMigrationResponse{}, pgx.ErrNoRows
		}
		return api.PQCMigrationResponse{}, err
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
	started := projections.PQCMigrationStarted{
		RunID: runID, AssetIDs: append([]string(nil), req.AssetIDs...), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: pqcmigration.EffectiveHybridTLS, Protocol: req.Protocol,
		RollbackOnFailure: req.RollbackOnFailure, Queued: len(payloads),
	}
	data, err := json.Marshal(started)
	if err != nil {
		return api.PQCMigrationResponse{}, err
	}
	ev, err := s.log.Append(ctx, events.Event{Type: projections.EventPQCMigrationStarted, TenantID: tenantID, Data: data})
	if err != nil {
		return api.PQCMigrationResponse{}, err
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
				Destination:    pqcMigrationReissueDestination,
				IdempotencyKey: "pqc-migration:" + payload.RunID + ":" + payload.AssetID,
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return api.PQCMigrationResponse{}, err
	}
	return api.PQCMigrationResponse{
		RunID: runID, Queued: len(payloads), TargetAlgorithm: req.TargetAlgorithm,
		EffectiveAlgorithm: pqcmigration.EffectiveHybridTLS, Protocol: req.Protocol,
		RollbackConfigured: req.RollbackOnFailure,
		MigrationProgress:  api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:           time.Now().UTC(),
	}, nil
}

func (s *pqcMigrationService) Rollback(ctx context.Context, tenantID, runID string, req api.PQCMigrationRollbackRequest) (api.PQCMigrationRollbackResponse, error) {
	if s.store == nil || s.log == nil || s.outbox == nil {
		return api.PQCMigrationRollbackResponse{}, errors.New("server: PQC rollback requires store, event log, and outbox")
	}
	wanted := make(map[string]bool, len(req.AssetIDs))
	for _, id := range req.AssetIDs {
		wanted[id] = true
	}
	payloads := make([]pqcMigrationRollbackPayload, 0, len(req.AssetIDs))
	if err := s.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != tenantID || e.Type != projections.EventPQCMigrationAssetCompleted {
			return nil
		}
		var completed projections.PQCMigrationAssetCompleted
		if err := json.Unmarshal(e.Data, &completed); err != nil {
			return err
		}
		if completed.RunID != runID || !wanted[completed.AssetID] {
			return nil
		}
		restore := projections.PQCMigrationRollbackCompleted{
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
		return api.PQCMigrationRollbackResponse{}, err
	}
	if len(payloads) == 0 {
		return api.PQCMigrationRollbackResponse{}, pgx.ErrNoRows
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, payload := range payloads {
			body, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    pqcMigrationRollbackDestination,
				IdempotencyKey: "pqc-migration-rollback:" + payload.RunID + ":" + payload.Restore.AssetID,
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return api.PQCMigrationRollbackResponse{}, err
	}
	assets, err := s.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return api.PQCMigrationRollbackResponse{}, err
	}
	return api.PQCMigrationRollbackResponse{
		RunID: runID, Queued: len(payloads), Reason: req.Reason,
		MigrationProgress: api.CBOMInventoryFromAssets(assets).MigrationProgress,
		QueuedAt:          time.Now().UTC(),
	}, nil
}

func (d *issuanceDispatcher) handlePQCReissue(ctx context.Context, m orchestrator.Message) error {
	var payload pqcMigrationReissuePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration reissue payload: %w", err)
	}
	_, err := d.idem.Do(ctx, m.TenantID, "pqc-migration-reissue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		csrDER, err := buildPQCMigrationHybridCSR(payload.Location)
		if err != nil {
			return nil, err
		}
		issuer := &protocolIssuer{
			issue: d.issue, issueHybrid: d.issueHybrid, orch: d.orch, idem: d.idem, store: d.store,
			log: d.log, caID: IssuingCAID(), defaultProfile: d.defaultProfile,
			leafProfile: d.leafProfile, ensureCRL: d.ensureCRL, publishCRL: d.publishCRL,
		}
		leafDER, err := issuer.IssueProtocolLeaf(ctx, m.TenantID, payload.Protocol, "pqc-migration:"+payload.RunID+":"+payload.AssetID, csrDER, protocolLeafTTL)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			return nil, err
		}
		completed := projections.PQCMigrationAssetCompleted{
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
		if err := d.appendProjected(ctx, m.TenantID, projections.EventPQCMigrationAssetCompleted, completed); err != nil {
			return nil, err
		}
		return []byte(info.SHA256Fingerprint), nil
	})
	return err
}

func (d *issuanceDispatcher) handlePQCRollback(ctx context.Context, m orchestrator.Message) error {
	var payload pqcMigrationRollbackPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode PQC migration rollback payload: %w", err)
	}
	_, err := d.idem.Do(ctx, m.TenantID, "pqc-migration-rollback:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		payload.Restore.Reason = payload.Reason
		if err := d.appendProjected(ctx, m.TenantID, projections.EventPQCMigrationRollbackCompleted, payload.Restore); err != nil {
			return nil, err
		}
		return []byte(payload.Restore.AssetID), nil
	})
	return err
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
	mldsaKey, err := pqc.GenerateKey(crypto.MLDSA44)
	if err != nil {
		return nil, err
	}
	defer mldsaKey.Destroy()
	hybridExt, err := pqc.HybridLeafCSRExtraExtension(key.Public(), mldsaKey)
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

func pqcMigrationAssets(assets []store.CryptoAsset) []pqcmigration.Asset {
	out := make([]pqcmigration.Asset, 0, len(assets))
	for _, asset := range assets {
		out = append(out, pqcmigration.Asset{
			ID: asset.ID, Kind: asset.Kind, Location: asset.Location,
			Algorithm: asset.Algorithm, KeyBits: asset.KeyBits, Protocol: asset.Protocol,
			Cipher: asset.Cipher, Library: asset.Library, Strength: asset.Strength,
			QuantumVulnerable: asset.QuantumVulnerable, OutOfPolicy: asset.OutOfPolicy,
			Reasons: append([]string(nil), asset.Reasons...),
		})
	}
	return out
}
