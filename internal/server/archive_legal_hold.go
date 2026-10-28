// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A208: the outbox delivery that sets or clears a person's S3 legal hold on
// one archive object. It reads the hold back and records applied or released
// only when the bucket says so; a bucket or object that cannot take the hold
// records failed with the reason.
type archiveLegalHoldDelivery struct {
	orch    *orchestrator.Orchestrator
	objects objectstore.Store
	now     func() time.Time
}

func (d *archiveLegalHoldDelivery) Deliver(ctx context.Context, m orchestrator.Message) error {
	if d == nil || d.orch == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: archive legal holds are not configured"))
	}
	var pl store.ArchiveLegalHoldEffect
	if err := json.Unmarshal(m.Payload, &pl); err != nil || pl.ID == "" || pl.Object == "" {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: archive legal hold payload: %v", err))
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	fail := func(detail string) error {
		return d.orch.RecordArchiveLegalHoldOutcome(ctx, m.TenantID, pl.ID, "failed", detail, now())
	}
	locker, ok := d.objects.(objectstore.Locker)
	if !ok || d.objects == nil {
		return fail("the archive object store does not support S3 Object Lock")
	}
	switch err := locker.SetLegalHold(ctx, pl.Object, pl.On); {
	case errors.Is(err, objectstore.ErrNoObjectLock):
		return fail("the bucket does not have S3 Object Lock enabled")
	case errors.Is(err, objectstore.ErrNotFound):
		return fail("the object is not in the archive")
	case err != nil:
		return err
	}
	state, err := locker.Lock(ctx, pl.Object)
	if err != nil {
		return err
	}
	if state.LegalHold != pl.On {
		return fmt.Errorf("server: the bucket reads the legal hold on %s as %v after setting it %v; retrying", pl.Object, state.LegalHold, pl.On)
	}
	status := "released"
	if pl.On {
		status = "applied"
	}
	return d.orch.RecordArchiveLegalHoldOutcome(ctx, m.TenantID, pl.ID, status, "", now())
}
