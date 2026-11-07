// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"errors"
	"strconv"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const ServiceReconcileApprovalKind = "pam_service_reconcile"

// ValidateServiceDependentRotationApproval is also a pre-append fence. Invalid
// pending authority must never become an immutable command that poisons replay.
func ValidateServiceDependentRotationApproval(v ServiceDependentRotationQueued) error {
	digest, err := v.Intent.Digest()
	if err != nil {
		return err
	}
	a := v.Approval
	if v.Intent.Mode == "" {
		if a != nil {
			return errors.New("dependent rotation: ordinary mode cannot carry reconcile authority")
		}
		return nil
	}
	version := v.Intent.ExpectedVersion
	if version < 1 {
		return errors.New("dependent reconciliation: positive retained vault version required")
	}
	if v.Intent.Mode != servicedependents.Reconcile || a == nil || !canonicalUUID(a.RequestID) || a.IntentDigest == "" || a.ResourceKind != ServiceReconcileApprovalKind || a.Action != "reconcile" || a.ResourceID != v.Intent.Plan.ID || a.Requester == "" || a.Requester != v.Actor || a.FromState != "version:"+strconv.Itoa(v.Intent.ExpectedVersion) || a.ToState != digest || a.TargetVersion != uint64(version) || a.RequiredApprovals < 1 || a.RequiredApprovals > 5 || len(a.EvidenceRefs) != 1 || a.EvidenceRefs[0] != "service-dependent-intent:"+digest || a.Issuance != nil {
		return errors.New("dependent rotation: exact independently approved reconciliation required")
	}
	return nil
}

const ServiceDependentReconcileSchemaVersion = 2

// The historical ordinary source stays closed. Separate reconciliation authority
// is readable only in schema two, including on canonical worker recovery.
func ValidateServiceDependentRotationSource(event events.Event, v ServiceDependentRotationQueued) error {
	version := schemaVersionOf(event)
	if len(event.Data) > 0 {
		if version == 1 {
			var historical privacyServiceDependentRotationQueuedV1
			if err := decodePublishedDependentSource(event.Data, &historical); err != nil {
				return err
			}
		} else {
			var historical privacyServiceDependentRotationQueuedV2
			if err := decodePublishedDependentSource(event.Data, &historical); err != nil {
				return err
			}
		}
	}
	if v.Intent.Plan.Version != servicedependents.RotationPlanVersion || v.Intent.Plan.Manifest != nil {
		return errors.New("dependent rotation: published inline source cannot carry paged manifest authority")
	}

	if event.Type != EventServiceDependentRotationQueued || event.ID != v.Intent.Plan.ID || v.Child.ID != event.ID || v.Child.DependentChangeID != event.ID || v.At.IsZero() {
		return errors.New("dependent rotation: canonical command identity differs")
	}
	if version == 1 {
		if v.Intent.Mode != "" || v.Approval != nil {
			return errors.New("dependent rotation: legacy source cannot carry reconciliation authority")
		}
	} else if version != ServiceDependentReconcileSchemaVersion || v.Intent.Mode != servicedependents.Reconcile {
		return errors.New("dependent rotation: reconciliation source version differs")
	}
	return ValidateServiceDependentRotationApproval(v)
}
