// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/keyposture"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// ErrDistrustRemovalIneligible means a finding is not a distrusted root the
// host agent can remove; the error text says why.
var ErrDistrustRemovalIneligible = errors.New("orchestrator: the finding is not a removable distrusted root")

// DistrustRemovalConnector names the receipt's connector column.
const DistrustRemovalConnector = "trust-store"

// DistrustedRootTarget is what one removal acts on, read from the finding the
// host agent reported and the control plane rated.
type DistrustedRootTarget struct {
	FindingID      string `json:"finding_id"`
	AgentID        string `json:"agent_id"`
	Host           string `json:"host"`
	AnchorPath     string `json:"anchor_path"`
	Fingerprint    string `json:"fingerprint"`
	DistrustEntry  string `json:"distrust_entry"`
	DistrustReason string `json:"distrust_reason"`
}

// DistrustedRootRemovalTarget decides whether a finding is a distrusted root
// the host agent can remove (eMudhra, Part 4): an agent-discovered OS
// trust-store anchor at an absolute path, which the control plane's own
// distrust list names itself, by key or certificate hash. Java keystores, NSS
// databases, browser exports and the Windows store hold anchors no single file
// removal can take out, so they are refused here.
func DistrustedRootRemovalTarget(f store.DiscoveryFinding) (DistrustedRootTarget, error) {
	ineligible := func(reason string) (DistrustedRootTarget, error) {
		return DistrustedRootTarget{}, fmt.Errorf("%w: %s", ErrDistrustRemovalIneligible, reason)
	}
	if f.Kind != "trust-store" {
		return ineligible("only an agent-discovered trust-store anchor can be removed")
	}
	meta := map[string]any{}
	if len(f.Metadata) > 0 && json.Unmarshal(f.Metadata, &meta) != nil {
		return ineligible("the finding's metadata does not parse")
	}
	text := func(key string) string {
		value, _ := meta[key].(string)
		return strings.TrimSpace(value)
	}
	verdict := keyposture.FromMetadata(meta)
	if !verdict.Distrusted() || verdict.DistrustHow != "itself" {
		return ineligible("the distrust list must name this certificate itself, by key or certificate hash")
	}
	if text("trust_store_kind") != "os" {
		return ineligible("only an OS trust-store anchor file can be removed; remove it from a Java, NSS, browser or Windows store with that store's own tool")
	}
	path, ok := strings.CutPrefix(f.Ref, "os/")
	if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ineligible("the finding does not name an absolute trust-store file")
	}
	agentID := text("agent_id")
	if _, err := uuid.Parse(agentID); err != nil {
		return ineligible("the finding does not name the host agent that found it")
	}
	fingerprint := strings.ToLower(strings.TrimSpace(f.Fingerprint))
	if decoded, err := hex.DecodeString(fingerprint); err != nil || len(decoded) != 32 {
		return ineligible("the finding has no exact SHA-256 certificate fingerprint")
	}
	return DistrustedRootTarget{
		FindingID: f.ID, AgentID: agentID, Host: text("host"), AnchorPath: path, Fingerprint: fingerprint,
		DistrustEntry: verdict.DistrustEntry, DistrustReason: verdict.DistrustReason,
	}, nil
}

// DistrustedRootRemovalRequest is one reviewed removal.
type DistrustedRootRemovalRequest struct {
	FindingID      string
	Fingerprint    string
	AnchorPath     string
	Reason         string
	RequestedBy    string
	IdempotencyKey string
}

type distrustRemovalQueuedDetail struct {
	FindingID     string `json:"finding_id"`
	AgentID       string `json:"agent_id"`
	Host          string `json:"host,omitempty"`
	AnchorPath    string `json:"anchor_path"`
	DistrustEntry string `json:"distrust_entry"`
	Reason        string `json:"reason,omitempty"`
	RequestedBy   string `json:"requested_by,omitempty"`
}

func distrustRemovalReceiptID(tenantID, findingID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("distrust-removal-receipt\x00"+tenantID+"\x00"+findingID+"\x00"+key)).String()
}

// RequestDistrustedRootRemoval queues one exact removal for the host agent
// that found the anchor, and its pending receipt, in one tenant transaction
// (AN-2, AN-6). It rechecks the finding inside the transaction: a finding
// that changed after review is refused. The host agent acts only when its own
// distrust list names the certificate it reads at that path.
func (o *Orchestrator) RequestDistrustedRootRemoval(ctx context.Context, tenantID string,
	in DistrustedRootRemovalRequest) (store.ConnectorDeliveryReceipt, error) {
	req := DistrustedRootRemovalRequest{
		FindingID: strings.TrimSpace(in.FindingID), Fingerprint: strings.ToLower(strings.TrimSpace(in.Fingerprint)),
		AnchorPath: strings.TrimSpace(in.AnchorPath), Reason: strings.TrimSpace(in.Reason),
		RequestedBy: strings.TrimSpace(in.RequestedBy), IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	}
	if _, err := uuid.Parse(req.FindingID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: removal needs an exact finding id")
	}
	if req.IdempotencyKey == "" {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: removal needs an idempotency key")
	}
	if req.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			req.RequestedBy = actor.Subject
		}
	}
	finding, err := o.store.GetDiscoveryFinding(ctx, tenantID, req.FindingID)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	target, err := DistrustedRootRemovalTarget(finding)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if target.Fingerprint != req.Fingerprint || target.AnchorPath != req.AnchorPath {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: the finding's fingerprint or path changed after review",
			store.ErrIdempotencyConflict)
	}
	intent, err := json.Marshal(relay.TrustDistributionIntent{
		Operation: relay.TrustRemoveDistrusted, FindingID: finding.ID, AnchorPath: target.AnchorPath,
		AnchorFingerprint: target.Fingerprint, RequiredAgentID: target.AgentID,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	detail, err := json.Marshal(distrustRemovalQueuedDetail{
		FindingID: finding.ID, AgentID: target.AgentID, Host: target.Host, AnchorPath: target.AnchorPath,
		DistrustEntry: target.DistrustEntry, Reason: req.Reason, RequestedBy: req.RequestedBy,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	outboxKey := "distrust-removal:" + finding.ID + ":" + req.IdempotencyKey
	receiptID := distrustRemovalReceiptID(tenantID, finding.ID, req.IdempotencyKey)
	var receipt store.ConnectorDeliveryReceipt
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"outbox-enqueue-if-absent\x1f"+tenantID+"\x1f"+outboxKey); err != nil {
			return err
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: relay.KindTrustDistribute,
			IdempotencyKey: outboxKey, Payload: intent,
			EffectLane:        TrustAnchorEffectLane(target.AgentID, target.AnchorPath),
			RequiredAgentRole: "host", RequiredAgentID: target.AgentID,
		})
		if err != nil {
			return err
		}
		var outboxID int64
		if err := tx.QueryRow(ctx,
			`SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			tenantID, outboxKey).Scan(&outboxID); err != nil {
			return err
		}
		receipt, err = o.recordQueuedDistrustRemovalReceiptTx(ctx, tx, tenantID, receiptID, outboxID,
			target, string(detail), req.IdempotencyKey, !inserted)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: queue distrusted root removal: %w", err)
	}
	return receipt, nil
}

func (o *Orchestrator) recordQueuedDistrustRemovalReceiptTx(ctx context.Context, tx pgx.Tx, tenantID, receiptID string,
	outboxID int64, target DistrustedRootTarget, detail, idempotencyKey string, retry bool) (store.ConnectorDeliveryReceipt, error) {
	payload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
		ID: receiptID, OutboxID: &outboxID, Destination: relay.KindTrustDistribute,
		Connector: DistrustRemovalConnector, Target: target.Host + ":" + target.AnchorPath,
		Fingerprint: target.Fingerprint, Status: servedstatus.ConnectorTrustAnchorRemovalQueued,
		Reason:         "distrusted root removal queued for " + target.DistrustEntry,
		Detail:         detail,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	eventID := "distrust-removal-queued:" + receiptID
	var ev events.Event
	found := false
	if retry {
		if ev, found, err = o.log.EventByID(ctx, eventID); err != nil {
			return store.ConnectorDeliveryReceipt{}, err
		}
	}
	if !found {
		if ev, err = o.log.Append(ctx, events.Event{ID: eventID,
			Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: payload}); err != nil {
			return store.ConnectorDeliveryReceipt{}, err
		}
	}
	if ev.ID != eventID || ev.TenantID != tenantID || ev.SchemaVersion != events.DefaultSchemaVersion ||
		ev.Type != projections.EventConnectorDeliveryRecorded || !bytes.Equal(ev.Data, payload) {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: queued removal receipt differs from the retained event", store.ErrIdempotencyConflict)
	}
	if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	return o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
}
