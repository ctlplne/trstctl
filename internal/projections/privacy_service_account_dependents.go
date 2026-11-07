// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

// Keep the published ordinary command shape independent of new reset authority.
type privacyServiceDependentRotationIntentV1 struct {
	Plan            servicedependents.RotationPlan   `json:"plan"`
	ExpectedVersion int                              `json:"expected_version"`
	ProviderBinding string                           `json:"provider_binding"`
	Probes          []servicedependents.ProbeBinding `json:"probes"`
}
type privacyServiceDependentRotationQueuedV1 struct {
	Intent privacyServiceDependentRotationIntentV1 `json:"intent"`
	Child  SecretStaticRotationQueued              `json:"child"`
	Actor  string                                  `json:"actor"`
	At     time.Time                               `json:"at"`
}

// Native selectors, configuration hashes and signed metadata are exact
// operational evidence. The human requesting the read remains an erasable identity.
func addServiceDependentPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	exact := events.PrivacyFieldOpaqueExact
	identity := events.PrivacyFieldIdentityExact
	policies[privacyEventPolicyKey{EventServiceReconciliationReviewProposed, 1}] = privacyRules(privacyRule("/intent", exact), privacyRule("/actor", identity), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentRotationQueued, 1}] = privacyRules(privacyRule("/intent", exact), privacyRule("/child", exact), privacyRule("/actor", identity), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentRotationQueued, ServiceDependentReconcileSchemaVersion}] = privacyRules(privacyRule("/intent", exact), privacyRule("/child", exact), privacyRule("/actor", identity), privacyRule("/at", exact), privacyRule("/approval/request_id", exact), privacyRule("/approval/intent_digest", exact), privacyRule("/approval/requester", identity), privacyRule("/approval/resource_kind", exact), privacyRule("/approval/resource_id", exact), privacyRule("/approval/action", exact), privacyRule("/approval/from_state", exact), privacyRule("/approval/to_state", exact), privacyRule("/approval/target_version", exact), privacyRule("/approval/required_approvals", exact), privacyRule("/approval/reason", events.PrivacyFieldFreeTextClear), privacyRule("/approval/evidence_refs", exact), privacyRule("/approval/issuance", exact))
	policies[privacyEventPolicyKey{EventServiceDependentRotationInverse, 1}] = privacyRules(privacyRule("/rotation_id", exact), privacyRule("/intent_digest", exact), privacyRule("/failure", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentDirectoryApplyStarted, 1}] = privacyRules(privacyRule("/rotation_id", exact), privacyRule("/intent_digest", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentDirectoryRestored, 1}] = privacyRules(privacyRule("/rotation_id", exact), privacyRule("/intent_digest", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentStepQueued, 1}] = privacyRules(privacyRule("/step", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentStepObserved, 1}] = privacyRules(privacyRule("/report", exact), privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentHostSaved, 1}] = privacyRules(privacyRule("/account", exact), privacyRule("/agent_id", exact), privacyRule("/enabled", exact), privacyRule("/actor", identity), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentScanQueued, 1}] = privacyRules(privacyRule("/intent", exact), privacyRule("/actor", identity), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentScanObserved, 1}] = privacyRules(privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/report", exact), privacyRule("/evidence_digest", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentScanFailed, 1}] = privacyRules(privacyRule("/run_id", exact), privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/reason", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
}
func addServiceDependentPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventServiceReconciliationReviewProposed, 1}] = privacyPayloadShape[ServiceReconciliationReview]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationQueued, 1}] = privacyPayloadShape[privacyServiceDependentRotationQueuedV1]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationQueued, ServiceDependentReconcileSchemaVersion}] = privacyPayloadShape[ServiceDependentRotationQueued]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationInverse, 1}] = privacyPayloadShape[ServiceDependentRotationInverse]()
	shapes[privacyEventPolicyKey{EventServiceDependentDirectoryApplyStarted, 1}] = privacyPayloadShape[ServiceDependentDirectoryApplyStarted]()
	shapes[privacyEventPolicyKey{EventServiceDependentDirectoryRestored, 1}] = privacyPayloadShape[ServiceDependentDirectoryRestored]()
	shapes[privacyEventPolicyKey{EventServiceDependentStepQueued, 1}] = privacyPayloadShape[ServiceDependentStepQueued]()
	shapes[privacyEventPolicyKey{EventServiceDependentStepObserved, 1}] = privacyPayloadShape[ServiceDependentStepObserved]()
	shapes[privacyEventPolicyKey{EventServiceDependentHostSaved, 1}] = privacyPayloadShape[ServiceDependentHostSaved]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanQueued, 1}] = privacyPayloadShape[ServiceDependentScanQueued]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanObserved, 1}] = privacyPayloadShape[ServiceDependentScanObserved]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanFailed, 1}] = privacyPayloadShape[ServiceDependentScanFailed]()
}
