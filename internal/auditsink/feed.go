// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
)

const (
	ProviderSplunkHEC = "splunk-hec"
	ProviderSentinel  = "sentinel"
)

// FeedBatch is the exact immutable work unit stored in the outbox. Credentials
// remain references; Records are already tenant-filtered and privacy-redacted by
// the audit read service. Retrying this payload cannot silently pick up a newer
// history generation.
type FeedBatch struct {
	BatchID              string              `json:"batch_id"`
	DestinationID        string              `json:"destination_id"`
	Provider             string              `json:"provider"`
	EndpointURL          string              `json:"endpoint_url"`
	TokenRef             string              `json:"token_ref"`
	AllowPrivateEndpoint bool                `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string            `json:"private_egress_cidrs,omitempty"`
	StartSequence        uint64              `json:"start_sequence"`
	EndSequence          uint64              `json:"end_sequence"`
	PrevHash             string              `json:"prev_hash,omitempty"`
	ChainHead            string              `json:"chain_head"`
	Records              []auditchain.Record `json:"records"`
}

// NormalizeProvider keeps the API, event schema, dispatcher, and console on one
// closed vocabulary.
func NormalizeProvider(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "splunk", "splunk-hec", "hec":
		return ProviderSplunkHEC, true
	case "sentinel", "azure-sentinel", "azure-monitor":
		return ProviderSentinel, true
	default:
		return "", false
	}
}

type collectorRecord struct {
	Sequence     uint64          `json:"sequence,omitempty"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TenantID     string          `json:"tenant_id,omitempty"`
	Time         string          `json:"time"`
	ActorSubject string          `json:"actor_subject,omitempty"`
	ActorRoles   []string        `json:"actor_roles,omitempty"`
	ChainHash    string          `json:"chain_hash,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

type splunkCollectorEvent struct {
	Time       float64           `json:"time"`
	Source     string            `json:"source"`
	SourceType string            `json:"sourcetype"`
	Fields     map[string]string `json:"fields,omitempty"`
	Event      collectorRecord   `json:"event"`
}

type sentinelCollectorRecord struct {
	TimeGenerated string          `json:"TimeGenerated"`
	BatchID       string          `json:"BatchId"`
	Sequence      uint64          `json:"Sequence,omitempty"`
	RecordID      string          `json:"RecordId"`
	EventType     string          `json:"EventType"`
	TenantID      string          `json:"TenantId,omitempty"`
	ActorSubject  string          `json:"ActorSubject,omitempty"`
	ActorRoles    string          `json:"ActorRoles,omitempty"`
	ChainHash     string          `json:"ChainHash,omitempty"`
	Data          json.RawMessage `json:"Data,omitempty"`
}

type collectorProof struct {
	Kind      string `json:"trstctl_record"`
	BatchID   string `json:"batch_id"`
	PrevHash  string `json:"prev_hash"`
	ChainHead string `json:"chain_head"`
	Count     int    `json:"count"`
}

func collectorRecordFromAudit(record auditchain.Record) collectorRecord {
	out := collectorRecord{
		Sequence: record.Sequence, ID: record.ID, Type: record.Type, TenantID: record.TenantID,
		Time: record.Time.UTC().Format(time.RFC3339Nano), ChainHash: record.Hash, Data: record.Data,
	}
	if record.Actor != nil {
		out.ActorSubject = record.Actor.Subject
		out.ActorRoles = append([]string(nil), record.Actor.Roles...)
	}
	return out
}

// WriteCollectorBatch maps the immutable internal audit shape to each native
// receiver contract. This package intentionally depends only on auditchain: the
// general audit service imports auditsink for writes, so importing the export
// package here would make the event spine circular.
func WriteCollectorBatch(w io.Writer, batch FeedBatch) error {
	provider, ok := NormalizeProvider(batch.Provider)
	if !ok || provider != batch.Provider {
		return fmt.Errorf("auditsink: unsupported audit-feed provider %q", batch.Provider)
	}
	proof, err := json.Marshal(collectorProof{
		Kind: "chain_trailer", BatchID: batch.BatchID, PrevHash: batch.PrevHash,
		ChainHead: batch.ChainHead, Count: len(batch.Records),
	})
	if err != nil {
		return err
	}
	when := time.Unix(0, 0).UTC()
	if len(batch.Records) > 0 {
		when = batch.Records[len(batch.Records)-1].Time.UTC()
	}
	trailer := collectorRecord{
		ID: "audit-feed-trailer:" + batch.BatchID, Type: "trstctl.audit.chain_trailer",
		Time: when.Format(time.RFC3339Nano), Data: proof,
	}
	switch provider {
	case ProviderSplunkHEC:
		enc := json.NewEncoder(w)
		fields := map[string]string{"trstctl_batch_id": batch.BatchID}
		for _, record := range batch.Records {
			if err := enc.Encode(splunkCollectorEvent{
				Time:   float64(record.Time.UTC().UnixNano()) / float64(time.Second),
				Source: "trstctl", SourceType: "trstctl:audit", Fields: fields,
				Event: collectorRecordFromAudit(record),
			}); err != nil {
				return err
			}
		}
		return enc.Encode(splunkCollectorEvent{
			Time:   float64(when.UnixNano()) / float64(time.Second),
			Source: "trstctl", SourceType: "trstctl:audit", Fields: fields, Event: trailer,
		})
	case ProviderSentinel:
		rows := make([]sentinelCollectorRecord, 0, len(batch.Records)+1)
		for _, record := range batch.Records {
			subject, roles := "", ""
			if record.Actor != nil {
				subject, roles = record.Actor.Subject, strings.Join(record.Actor.Roles, " ")
			}
			rows = append(rows, sentinelCollectorRecord{
				TimeGenerated: record.Time.UTC().Format(time.RFC3339Nano), BatchID: batch.BatchID, Sequence: record.Sequence,
				RecordID: record.ID, EventType: record.Type, TenantID: record.TenantID,
				ActorSubject: subject, ActorRoles: roles, ChainHash: record.Hash, Data: record.Data,
			})
		}
		rows = append(rows, sentinelCollectorRecord{
			TimeGenerated: when.Format(time.RFC3339Nano), BatchID: batch.BatchID, RecordID: trailer.ID,
			EventType: trailer.Type, Data: proof,
		})
		return json.NewEncoder(w).Encode(rows)
	default:
		return fmt.Errorf("auditsink: unsupported audit-feed provider %q", batch.Provider)
	}
}
