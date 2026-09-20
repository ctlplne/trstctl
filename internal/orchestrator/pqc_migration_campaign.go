// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const MaxPQCMigrationCampaignFindings = 100

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PQCMigrationCampaignStartRequest starts a core tracking campaign over existing
// CBOM findings. It contains no execution settings because fleet execution is a
// separate, optional Enterprise capability.
type PQCMigrationCampaignStartRequest struct {
	ID                string    `json:"id,omitempty"`
	Name              string    `json:"name"`
	Owner             string    `json:"owner"`
	Deadline          time.Time `json:"deadline"`
	Wave              string    `json:"wave"`
	ReadinessCriteria []string  `json:"readiness_criteria"`
	FindingIDs        []string  `json:"finding_ids"`
	readinessBindings map[string]string
	requireBindings   bool
}

type PQCMigrationCampaignUpdateRequest struct {
	Owner                 string     `json:"owner,omitempty"`
	Deadline              *time.Time `json:"deadline,omitempty"`
	Wave                  string     `json:"wave,omitempty"`
	ReadinessCriteria     []string   `json:"readiness_criteria,omitempty"`
	ReadinessStatus       string     `json:"readiness_status,omitempty"`
	ReadinessEvidenceRefs []string   `json:"readiness_evidence_refs,omitempty"`
}

type PQCMigrationFindingDispositionRequest struct {
	Disposition     string   `json:"disposition"`
	Method          string   `json:"method"`
	Reason          string   `json:"reason"`
	EvidenceRefs    []string `json:"evidence_refs,omitempty"`
	EvidenceDigests []string `json:"evidence_digests"`
}

// PQCMigrationCampaignClosureBuilder constructs and signs the closure event from
// the campaign snapshot read under the command transaction's campaign lock.
// Keeping the callback inside that lock prevents the signature from racing a
// readiness, ownership, wave, or finding-disposition event.
type PQCMigrationCampaignClosureBuilder func(store.PQCMigrationCampaign) (projections.PQCMigrationCampaignClosed, error)

// StartCryptoReadinessAction creates the existing event-sourced campaign, but
// only after binding every selected CBOM finding to its exact production graph
// row and one owner actually attributed by that row.
func (o *Orchestrator) StartCryptoReadinessAction(ctx context.Context, tenantID string, in PQCMigrationCampaignStartRequest) (store.PQCMigrationCampaign, error) {
	dataset, err := cryptoreadiness.Build(ctx, o.store, tenantID)
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	rows := make(map[string]cryptoreadiness.Item, len(dataset.Items))
	for _, item := range dataset.Items {
		rows[strings.TrimPrefix(item.Asset.ID, "crypto:")] = item
	}
	owner := strings.TrimSpace(in.Owner)
	bindings := make(map[string]string, len(in.FindingIDs))
	for _, rawID := range in.FindingIDs {
		findingID := strings.TrimSpace(rawID)
		item, ok := rows[findingID]
		if !ok {
			return store.PQCMigrationCampaign{}, fmt.Errorf("CBOM finding %s has no current crypto readiness row", findingID)
		}
		if !containsString(item.Owners, owner) {
			return store.PQCMigrationCampaign{}, fmt.Errorf("owner %q is not attributed to CBOM finding %s by current graph readiness", owner, findingID)
		}
		digest, err := cryptoreadiness.RowDigest(tenantID, item.CryptoReadinessRow)
		if err != nil {
			return store.PQCMigrationCampaign{}, err
		}
		bindings[findingID] = digest
	}
	in.readinessBindings = bindings
	in.requireBindings = true
	return o.StartPQCMigrationCampaign(ctx, tenantID, in)
}

func (o *Orchestrator) StartPQCMigrationCampaign(ctx context.Context, tenantID string, in PQCMigrationCampaignStartRequest) (store.PQCMigrationCampaign, error) {
	payload, err := o.normalizePQCMigrationCampaign(ctx, tenantID, in)
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.LockPQCMigrationCampaignTx(ctx, tx, tenantID, payload.ID); err != nil {
			return err
		}
		_, err := o.store.GetPQCMigrationCampaignTx(ctx, tx, tenantID, payload.ID)
		switch {
		case err == nil:
			return store.ErrPQCCampaignExists
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		default:
			return o.appendCoreCampaignEventTx(ctx, tx, tenantID, projections.EventPQCMigrationCampaignStarted, payload)
		}
	})
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	return o.store.GetPQCMigrationCampaign(ctx, tenantID, payload.ID)
}

func (o *Orchestrator) UpdatePQCMigrationCampaign(ctx context.Context, tenantID, campaignID string, in PQCMigrationCampaignUpdateRequest) (store.PQCMigrationCampaign, error) {
	campaignID = strings.TrimSpace(campaignID)
	owner := strings.TrimSpace(in.Owner)
	if _, err := o.validatePQCMigrationCampaignTopology(ctx, tenantID, campaignID, owner); err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.LockPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID); err != nil {
			return err
		}
		campaign, err := o.store.GetPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID)
		if err != nil {
			return err
		}
		if campaign.Status != "open" {
			return store.ErrPQCCampaignClosed
		}
		payload, err := normalizePQCMigrationCampaignUpdate(campaign, in)
		if err != nil {
			return err
		}
		return o.appendCoreCampaignEventTx(ctx, tx, tenantID, projections.EventPQCMigrationCampaignUpdated, payload)
	})
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	return o.store.GetPQCMigrationCampaign(ctx, tenantID, campaignID)
}

func (o *Orchestrator) DispositionPQCMigrationFinding(ctx context.Context, tenantID, campaignID, findingID string, in PQCMigrationFindingDispositionRequest) (store.PQCMigrationCampaign, error) {
	campaignID = strings.TrimSpace(campaignID)
	findingID = strings.TrimSpace(findingID)
	if _, err := o.validatePQCMigrationCampaignTopology(ctx, tenantID, campaignID, ""); err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.LockPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID); err != nil {
			return err
		}
		campaign, err := o.store.GetPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID)
		if err != nil {
			return err
		}
		if campaign.Status != "open" {
			return store.ErrPQCCampaignClosed
		}
		found := false
		for _, finding := range campaign.Findings {
			if finding.FindingID == findingID {
				found = true
				break
			}
		}
		if !found {
			return pgx.ErrNoRows
		}
		payload, err := normalizePQCMigrationFindingDisposition(campaign.ID, findingID, in)
		if err != nil {
			return err
		}
		return o.appendCoreCampaignEventTx(ctx, tx, tenantID, projections.EventPQCMigrationCampaignFindingDispositioned, payload)
	})
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	return o.store.GetPQCMigrationCampaign(ctx, tenantID, campaignID)
}

func (o *Orchestrator) ClosePQCMigrationCampaign(ctx context.Context, tenantID, campaignID string, build PQCMigrationCampaignClosureBuilder) (store.PQCMigrationCampaign, error) {
	campaignID = strings.TrimSpace(campaignID)
	if build == nil {
		return store.PQCMigrationCampaign{}, errors.New("PQC migration campaign closure builder is required")
	}
	if _, err := o.validatePQCMigrationCampaignTopology(ctx, tenantID, campaignID, ""); err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.LockPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID); err != nil {
			return err
		}
		campaign, err := o.store.GetPQCMigrationCampaignTx(ctx, tx, tenantID, campaignID)
		if err != nil {
			return err
		}
		if campaign.Status != "open" {
			return store.ErrPQCCampaignClosed
		}
		if campaign.ReadinessStatus != "passed" || campaign.PendingCount != 0 {
			return fmt.Errorf("%w: readiness=%s pending=%d", store.ErrPQCCampaignNotReady, campaign.ReadinessStatus, campaign.PendingCount)
		}
		closure, err := build(campaign)
		if err != nil {
			return err
		}
		if strings.TrimSpace(closure.CampaignID) != campaignID {
			return errors.New("PQC migration campaign closure does not match locked campaign")
		}
		return o.appendCoreCampaignEventTx(ctx, tx, tenantID, projections.EventPQCMigrationCampaignClosed, closure)
	})
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	return o.store.GetPQCMigrationCampaign(ctx, tenantID, campaignID)
}

func (o *Orchestrator) appendCoreCampaignEventTx(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload any) error {
	evData, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: evData})
	if err != nil {
		return err
	}
	return o.proj.ApplyTx(ctx, tx, ev)
}

func (o *Orchestrator) normalizePQCMigrationCampaign(ctx context.Context, tenantID string, in PQCMigrationCampaignStartRequest) (projections.PQCMigrationCampaignStarted, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	} else if _, err := uuid.Parse(id); err != nil {
		return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("campaign id must be a UUID")
	}
	name := trimBounded(in.Name, 160)
	owner := trimBounded(in.Owner, 180)
	wave := trimBounded(in.Wave, 120)
	if name == "" || owner == "" || wave == "" {
		return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("name, owner, and wave are required")
	}
	if in.Deadline.IsZero() {
		return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("deadline is required")
	}
	criteria, err := normalizeRequiredStrings(in.ReadinessCriteria, 20, 240, "readiness_criteria")
	if err != nil {
		return projections.PQCMigrationCampaignStarted{}, err
	}
	if len(in.FindingIDs) == 0 || len(in.FindingIDs) > MaxPQCMigrationCampaignFindings {
		return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("finding_ids must contain between 1 and %d findings", MaxPQCMigrationCampaignFindings)
	}
	assets, err := o.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return projections.PQCMigrationCampaignStarted{}, err
	}
	byID := make(map[string]store.CryptoAsset, len(assets))
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	findings := make([]projections.PQCMigrationCampaignFinding, 0, len(in.FindingIDs))
	seen := make(map[string]bool, len(in.FindingIDs))
	for _, rawID := range in.FindingIDs {
		findingID := strings.TrimSpace(rawID)
		if _, err := uuid.Parse(findingID); err != nil {
			return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("finding_id must be a UUID")
		}
		if seen[findingID] {
			return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("duplicate finding_id %s", findingID)
		}
		seen[findingID] = true
		asset, ok := byID[findingID]
		if !ok {
			return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("CBOM finding %s not found for tenant", findingID)
		}
		if !asset.QuantumVulnerable && !asset.OutOfPolicy {
			return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("CBOM finding %s is not marked quantum-vulnerable or out-of-policy", findingID)
		}
		finding := projections.PQCMigrationCampaignFinding{
			FindingID: asset.ID, Kind: asset.Kind, Location: asset.Location,
			Algorithm: asset.Algorithm, KeyBits: asset.KeyBits, Protocol: asset.Protocol,
			Cipher: asset.Cipher,
		}
		finding.ReadinessDigest = in.readinessBindings[findingID]
		if in.requireBindings && finding.ReadinessDigest == "" {
			return projections.PQCMigrationCampaignStarted{}, fmt.Errorf("CBOM finding %s lacks required crypto readiness binding", findingID)
		}
		digestInput, err := json.Marshal(finding)
		if err != nil {
			return projections.PQCMigrationCampaignStarted{}, err
		}
		finding.FindingDigest = "sha256:" + crypto.SHA256Hex(digestInput)
		findings = append(findings, finding)
	}
	return projections.PQCMigrationCampaignStarted{
		ID: id, Name: name, OwnerRef: owner, Deadline: in.Deadline.UTC(),
		Wave: wave, ReadinessCriteria: criteria, Findings: findings,
	}, nil
}

// validatePQCMigrationCampaignTopology leaves legacy manual campaigns alone.
// A graph-bound action, however, may mutate only while every row digest and its
// attributed owner still match current production graph authority.
func (o *Orchestrator) validatePQCMigrationCampaignTopology(ctx context.Context, tenantID, campaignID, requestedOwner string) (store.PQCMigrationCampaign, error) {
	campaign, err := o.store.GetPQCMigrationCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	bound := false
	for _, finding := range campaign.Findings {
		if finding.ReadinessDigest != "" {
			bound = true
			break
		}
	}
	if !bound {
		return campaign, nil
	}
	dataset, err := cryptoreadiness.Build(ctx, o.store, tenantID)
	if err != nil {
		return store.PQCMigrationCampaign{}, err
	}
	rows := make(map[string]cryptoreadiness.Item, len(dataset.Items))
	for _, item := range dataset.Items {
		rows[strings.TrimPrefix(item.Asset.ID, "crypto:")] = item
	}
	owner := campaign.OwnerRef
	if requestedOwner != "" {
		owner = requestedOwner
	}
	for _, finding := range campaign.Findings {
		if finding.ReadinessDigest == "" {
			continue
		}
		item, ok := rows[finding.FindingID]
		if !ok {
			return store.PQCMigrationCampaign{}, fmt.Errorf("%w: finding %s no longer has a readiness row", store.ErrPQCCampaignTopologyStale, finding.FindingID)
		}
		digest, err := cryptoreadiness.RowDigest(tenantID, item.CryptoReadinessRow)
		if err != nil {
			return store.PQCMigrationCampaign{}, err
		}
		if digest != finding.ReadinessDigest || !containsString(item.Owners, owner) {
			return store.PQCMigrationCampaign{}, fmt.Errorf("%w: finding %s or owner %q changed", store.ErrPQCCampaignTopologyStale, finding.FindingID, owner)
		}
	}
	return campaign, nil
}

func normalizePQCMigrationCampaignUpdate(campaign store.PQCMigrationCampaign, in PQCMigrationCampaignUpdateRequest) (projections.PQCMigrationCampaignUpdated, error) {
	owner := campaign.OwnerRef
	if strings.TrimSpace(in.Owner) != "" {
		owner = trimBounded(in.Owner, 180)
	}
	deadline := campaign.Deadline
	if in.Deadline != nil {
		if in.Deadline.IsZero() {
			return projections.PQCMigrationCampaignUpdated{}, fmt.Errorf("deadline must not be zero")
		}
		deadline = in.Deadline.UTC()
	}
	wave := campaign.Wave
	if strings.TrimSpace(in.Wave) != "" {
		wave = trimBounded(in.Wave, 120)
	}
	criteria := campaign.ReadinessCriteria
	if in.ReadinessCriteria != nil {
		var err error
		criteria, err = normalizeRequiredStrings(in.ReadinessCriteria, 20, 240, "readiness_criteria")
		if err != nil {
			return projections.PQCMigrationCampaignUpdated{}, err
		}
	}
	readiness := campaign.ReadinessStatus
	if strings.TrimSpace(in.ReadinessStatus) != "" {
		readiness = strings.ToLower(strings.TrimSpace(in.ReadinessStatus))
		if readiness != "pending" && readiness != "passed" && readiness != "blocked" {
			return projections.PQCMigrationCampaignUpdated{}, fmt.Errorf("readiness_status must be pending, passed, or blocked")
		}
	}
	refs := campaign.ReadinessEvidenceRefs
	if in.ReadinessEvidenceRefs != nil {
		var err error
		refs, err = normalizeEvidenceRefs(in.ReadinessEvidenceRefs)
		if err != nil {
			return projections.PQCMigrationCampaignUpdated{}, err
		}
	}
	if readiness == "passed" && len(refs) == 0 {
		return projections.PQCMigrationCampaignUpdated{}, fmt.Errorf("passed readiness requires evidence references")
	}
	return projections.PQCMigrationCampaignUpdated{
		CampaignID: campaign.ID, OwnerRef: owner, Deadline: deadline, Wave: wave,
		ReadinessCriteria: criteria, ReadinessStatus: readiness,
		ReadinessEvidenceRefs: refs, UpdatedAt: time.Now().UTC(),
	}, nil
}

func normalizePQCMigrationFindingDisposition(campaignID, findingID string, in PQCMigrationFindingDispositionRequest) (projections.PQCMigrationCampaignFindingDispositioned, error) {
	disposition := strings.ToLower(strings.TrimSpace(in.Disposition))
	if disposition != "remediated" && disposition != "excepted" {
		return projections.PQCMigrationCampaignFindingDispositioned{}, fmt.Errorf("disposition must be remediated or excepted")
	}
	method := trimBounded(in.Method, 120)
	reason := trimBounded(in.Reason, 500)
	if method == "" || reason == "" {
		return projections.PQCMigrationCampaignFindingDispositioned{}, fmt.Errorf("method and reason are required")
	}
	refs, err := normalizeEvidenceRefs(in.EvidenceRefs)
	if err != nil {
		return projections.PQCMigrationCampaignFindingDispositioned{}, err
	}
	digests, err := normalizeRequiredStrings(in.EvidenceDigests, 20, 80, "evidence_digests")
	if err != nil {
		return projections.PQCMigrationCampaignFindingDispositioned{}, err
	}
	for _, digest := range digests {
		if !sha256DigestPattern.MatchString(digest) {
			return projections.PQCMigrationCampaignFindingDispositioned{}, fmt.Errorf("evidence_digests must use sha256:<64 lowercase hex>")
		}
	}
	return projections.PQCMigrationCampaignFindingDispositioned{
		CampaignID: campaignID, FindingID: findingID, Disposition: disposition,
		RemediationMethod: method, Reason: reason, EvidenceRefs: refs,
		EvidenceDigests: digests, DispositionedAt: time.Now().UTC(),
	}, nil
}

func normalizeRequiredStrings(values []string, maxItems, maxLen int, field string) ([]string, error) {
	if len(values) == 0 || len(values) > maxItems {
		return nil, fmt.Errorf("%s must contain between 1 and %d values", field, maxItems)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = trimBounded(value, maxLen)
		if value == "" {
			return nil, fmt.Errorf("%s values must not be empty", field)
		}
		out = append(out, value)
	}
	return out, nil
}
