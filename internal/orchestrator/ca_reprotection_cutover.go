// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordCertificateReprotectionCutover appends one first-writer event after a
// signed, verified host receipt. The projector applies its certificate and
// identity changes atomically. A retry after a lost response reuses the exact
// event, including its original timestamp and payload.
func (o *Orchestrator) RecordCertificateReprotectionCutover(ctx context.Context,
	tenantID string, cut store.CertificateReprotectionCutover) error {
	if o == nil || o.store == nil || o.log == nil || tenantID == "" || cut.IdentityID == "" || cut.JobID == "" {
		return store.ErrCertificateReprotectionConflict
	}
	if err := store.ValidateCertificateReprotectionCutover(tenantID, cut); err != nil {
		return err
	}
	raw, err := json.Marshal(cut)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("ca-reprotection-cutover\x00"+tenantID+"\x00"+cut.JobID)).String()
	return o.store.WithIdentityIssuanceFence(ctx, tenantID, cut.IdentityID, func(fenced context.Context) error {
		ev, err := o.emitPrepared(fenced, events.Event{ID: id, TenantID: tenantID,
			Type: projections.EventCertificateReprotectionCutover, SchemaVersion: 1, Data: raw})
		if err != nil {
			return err
		}
		if ev.ID != id || ev.TenantID != tenantID || ev.Type != projections.EventCertificateReprotectionCutover ||
			ev.SchemaVersion != 1 || !sameCertificateReprotectionObservation(tenantID, ev.Data, cut) {
			return fmt.Errorf("%w: retained CA re-protection cutover differs from signed receipt", store.ErrCertificateReprotectionConflict)
		}
		return nil
	})
}

// A retry can carry a fresh agent signature and timestamp after a lost
// response. The signed observation, job attempt and every cutover binding must
// still be identical; the source event keeps its first verified signature.
func sameCertificateReprotectionObservation(tenantID string, priorRaw []byte, next store.CertificateReprotectionCutover) bool {
	var prior store.CertificateReprotectionCutover
	if json.Unmarshal(priorRaw, &prior) != nil || store.ValidateCertificateReprotectionCutover(tenantID, prior) != nil ||
		!store.SameAgentJobReceiptObservation(prior.ReceiptStatement, next.ReceiptStatement) {
		return false
	}
	prior.ReceiptStatement, next.ReceiptStatement = "", ""
	prior.ReceiptSignature, next.ReceiptSignature = "", ""
	prior.ReceiptSignerFingerprint, next.ReceiptSignerFingerprint = "", ""
	return reflect.DeepEqual(prior, next)
}
