// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// addOperatorRecordPrivacyShapes closes the records operators keep about their
// own estate: report and archive legal holds, tenant custom roles and host
// recovery checks. Their privacy posture is refusal (a free-text reason is the
// actor's own words), so each needs only its exact payload shape.
func addOperatorRecordPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	for key, shape := range map[privacyEventPolicyKey]events.PrivacyPayloadShape{
		// A206: a report run's legal hold (a free-text reason the person wrote,
		// the person being the event's actor) and its retention expiry (a run,
		// a digest, a window and a time).
		{EventComplianceReportLegalHoldPlaced, 1}:         privacyPayloadShape[ComplianceReportLegalHold](),
		{EventComplianceReportLegalHoldReleased, 1}:       privacyPayloadShape[ComplianceReportLegalHold](),
		{EventComplianceReportArtifactExpiryRequested, 1}: privacyPayloadShape[ComplianceReportArtifactExpiry](),
		{EventComplianceReportArtifactExpired, 1}:         privacyPayloadShape[ComplianceReportArtifactExpiry](),
		{EventComplianceReportArtifactExpiryDeferred, 1}:  privacyPayloadShape[ComplianceReportArtifactExpiryDeferred](),
		// A208: an archive object's legal hold (a free-text reason the person
		// wrote, the person being the event's actor) and its read-back.
		{EventArchiveLegalHoldPlaced, 1}:           privacyPayloadShape[ArchiveLegalHoldPlaced](),
		{EventArchiveLegalHoldReleaseRequested, 1}: privacyPayloadShape[ArchiveLegalHoldRelease](),
		{EventArchiveLegalHoldRecorded, 1}:         privacyPayloadShape[ArchiveLegalHoldRecorded](),
		// A207: a tenant custom role's name, description and permissions.
		{EventTenantCustomRoleUpserted, 1}: privacyPayloadShape[TenantCustomRoleUpserted](),
		{EventTenantCustomRoleDeleted, 1}:  privacyPayloadShape[TenantCustomRoleDeleted](),
		// A210: a recovery check of a contained host target: identifiers, closed
		// states, digests and the signed job receipt; the requester is the actor.
		{EventEndpointRecoveryCheckRequested, 1}: privacyPayloadShape[EndpointRecoveryCheckRequested](),
		{EventEndpointRecoveryChecked, 1}:        privacyPayloadShape[EndpointRecoveryChecked](),
		{EventEndpointRecoveryCheckFailed, 1}:    privacyPayloadShape[EndpointRecoveryCheckFailed](),
		// A216: a drafted CA rollover: the authority, band, expiry, the opened
		// ceremony and the plan it binds, or why none was opened.
		{EventCARolloverDrafted, 1}: privacyPayloadShape[CARolloverDrafted](),
	} {
		shapes[key] = shape
	}
}
