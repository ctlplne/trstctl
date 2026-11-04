// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AWSHoneyTrailObjectEventID names the one event a trail log file is recorded
// with (N4).
func AWSHoneyTrailObjectEventID(tenantID, accountConfigID, objectKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("aws-honey-trail-object\x00"+tenantID+"\x00"+accountConfigID+"\x00"+objectKey)).String()
}

// RecordAWSHoneyTrailObject records one read trail log file and the decoy
// uses in it as honeytoken.aws.trail_object_scanned, and projects it. A file
// already recorded keeps its first record: a second read, even one that
// matched a decoy created since, appends nothing and projects that record
// again, which changes nothing.
func (o *Orchestrator) RecordAWSHoneyTrailObject(ctx context.Context, tenantID string, scan store.AWSHoneyTrailObjectScan) error {
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	id := AWSHoneyTrailObjectEventID(tenantID, scan.AccountConfigID, scan.ObjectKey)
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventAWSHoneyTrailObjectScanned, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != id || ev.Type != projections.EventAWSHoneyTrailObjectScanned || ev.TenantID != tenantID {
		return fmt.Errorf("%w: trail log file event %s is another event", store.ErrIdempotencyConflict, id)
	}
	return nil
}
