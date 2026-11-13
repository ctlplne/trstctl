// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventDocRecordRecorded records one sync of a customer's documentation
// record (MSP-14): what was written where, or why the sync failed. The
// tenant is the customer.
const EventDocRecordRecorded = "provider.doc_record.recorded"

// DocRecordEvent is the payload of provider.doc_record.recorded.
type DocRecordEvent struct {
	TargetID     string     `json:"target_id"`
	OrgID        string     `json:"org_id,omitempty"`
	RecordID     string     `json:"record_id,omitempty"`
	Digest       string     `json:"digest,omitempty"`
	Certificates int        `json:"certificates,omitempty"`
	NextExpiry   *time.Time `json:"next_expiry,omitempty"`
	OK           bool       `json:"ok,omitempty"`
	Reason       string     `json:"reason,omitempty"`
}

var docRecordDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateDocRecordEvent checks a provider.doc_record.recorded payload.
func ValidateDocRecordEvent(p DocRecordEvent) error {
	if !billingTargetIDPattern.MatchString(p.TargetID) {
		return fmt.Errorf("a documentation record names a valid target, not %q", p.TargetID)
	}
	if len(p.OrgID) > 128 || len(p.RecordID) > 128 || len(p.Reason) > 2000 || p.Certificates < 0 {
		return fmt.Errorf("a documentation record field is out of range")
	}
	if p.OK {
		if strings.TrimSpace(p.OrgID) == "" || strings.TrimSpace(p.RecordID) == "" || !docRecordDigestPattern.MatchString(p.Digest) {
			return fmt.Errorf("a synced documentation record names its organization, record and digest")
		}
		return nil
	}
	if strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("a failed documentation record sync says why")
	}
	return nil
}

func (p *Projector) applyDocRecordTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventDocRecordRecorded {
		return false, nil
	}
	var d DocRecordEvent
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidateDocRecordEvent(d); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyDocRecordTx(ctx, tx, store.DocRecordChange{TenantID: e.TenantID, TargetID: d.TargetID, OrgID: d.OrgID,
		RecordID: d.RecordID, Digest: d.Digest, Certificates: d.Certificates, NextExpiry: d.NextExpiry, OK: d.OK, Reason: d.Reason, At: e.Time},
		e.Sequence)
}
