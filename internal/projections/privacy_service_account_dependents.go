// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"time"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

// Published inline sources retain their exact original nested plan shape.
// A later optional manifest field must not retroactively widen these versions.
type privacyServiceDependentRotationPlanV1 struct {
	Version    int                              `json:"version"`
	ID         string                           `json:"id"`
	Account    servicedependents.AccountBinding `json:"account"`
	SecretName string                           `json:"secret_name"`
	Hosts      []servicedependents.RotationHost `json:"hosts"`
	Order      []servicedependents.DependentRef `json:"order"`
	CreatedAt  time.Time                        `json:"created_at"`
	ExpiresAt  time.Time                        `json:"expires_at"`
	Digest     string                           `json:"digest"`
}
type privacyServiceDependentRotationIntentV2 struct {
	Mode            string                                `json:"mode,omitempty"`
	Reconcile       *servicedependents.ReconcilePrincipal `json:"reconcile,omitempty"`
	Plan            privacyServiceDependentRotationPlanV1 `json:"plan"`
	ExpectedVersion int                                   `json:"expected_version"`
	ProviderBinding string                                `json:"provider_binding"`
	Probes          []servicedependents.ProbeBinding      `json:"probes"`
}
type privacyServiceDependentRotationQueuedV2 struct {
	Approval *store.OperationApprovalUse             `json:"approval,omitempty"`
	Intent   privacyServiceDependentRotationIntentV2 `json:"intent"`
	Child    SecretStaticRotationQueued              `json:"child"`
	Actor    string                                  `json:"actor"`
	At       time.Time                               `json:"at"`
}
type privacyServiceReconciliationReviewV1 struct {
	Intent privacyServiceDependentRotationIntentV2 `json:"intent"`
	Actor  string                                  `json:"actor"`
	At     time.Time                               `json:"at"`
}

// Keep the published ordinary command shape independent of new reset authority.
type privacyServiceDependentRotationIntentV1 struct {
	Plan            privacyServiceDependentRotationPlanV1 `json:"plan"`
	ExpectedVersion int                                   `json:"expected_version"`
	ProviderBinding string                                `json:"provider_binding"`
	Probes          []servicedependents.ProbeBinding      `json:"probes"`
}
type privacyServiceDependentRotationQueuedV1 struct {
	Intent privacyServiceDependentRotationIntentV1 `json:"intent"`
	Child  SecretStaticRotationQueued              `json:"child"`
	Actor  string                                  `json:"actor"`
	At     time.Time                               `json:"at"`
}

// The original step source cannot grow replacement authority retroactively.
type privacyServiceDependentStepV1 struct {
	RotationID   string                         `json:"rotation_id"`
	PlanDigest   string                         `json:"plan_digest"`
	ID           string                         `json:"step_id"`
	Direction    string                         `json:"direction"`
	Action       string                         `json:"action"`
	Ref          servicedependents.DependentRef `json:"ref"`
	AccountSID   string                         `json:"account_sid"`
	ProbeID      string                         `json:"probe_id"`
	Service      *windependents.Service         `json:"service,omitempty"`
	Task         *windependents.Task            `json:"task,omitempty"`
	Pool         *windependents.Pool            `json:"pool,omitempty"`
	PreviousPIDs []uint32                       `json:"previous_pids,omitempty"`
	Challenge    string                         `json:"challenge,omitempty"`
	NotBefore    time.Time                      `json:"not_before"`
	Deadline     time.Time                      `json:"deadline"`
}
type privacyServiceDependentRecoveryStepV1 struct {
	Recovery     *servicedependents.StepRecoveryBinding `json:"recovery,omitempty"`
	RotationID   string                                 `json:"rotation_id"`
	PlanDigest   string                                 `json:"plan_digest"`
	ID           string                                 `json:"step_id"`
	Direction    string                                 `json:"direction"`
	Action       string                                 `json:"action"`
	Ref          servicedependents.DependentRef         `json:"ref"`
	AccountSID   string                                 `json:"account_sid"`
	ProbeID      string                                 `json:"probe_id"`
	Service      *windependents.Service                 `json:"service,omitempty"`
	Task         *windependents.Task                    `json:"task,omitempty"`
	Pool         *windependents.Pool                    `json:"pool,omitempty"`
	PreviousPIDs []uint32                               `json:"previous_pids,omitempty"`
	Challenge    string                                 `json:"challenge,omitempty"`
	NotBefore    time.Time                              `json:"not_before"`
	Deadline     time.Time                              `json:"deadline"`
}
type privacyServiceDependentStepRecoveryQueuedV1 struct {
	Previous             privacyServiceDependentRecoveryStepV1 `json:"previous_step"`
	Step                 privacyServiceDependentRecoveryStepV1 `json:"step"`
	PreviousStatus       string                                `json:"previous_status"`
	PreviousReportDigest string                                `json:"previous_report_digest,omitempty"`
	CurrentVersion       int                                   `json:"current_vault_version"`
	ReviewDigest         string                                `json:"recovery_digest"`
	Actor                string                                `json:"actor"`
	Reason               string                                `json:"reason"`
	At                   time.Time                             `json:"at"`
}
type privacyServiceDependentStepQueuedV1 struct {
	Step privacyServiceDependentStepV1 `json:"step"`
	At   time.Time                     `json:"at"`
}

// Native selectors, configuration hashes and signed metadata are exact
// operational evidence. The human requesting the read remains an erasable identity.
func addServiceDependentPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	exact := events.PrivacyFieldOpaqueExact
	policies[privacyEventPolicyKey{EventServiceDependentManifestOpened, 1}] = privacyRules(privacyRule("/header", exact), privacyRule("/actor", events.PrivacyFieldIdentityExact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentManifestPageRecorded, 1}] = privacyRules(privacyRule("/page", exact), privacyRule("/actor", events.PrivacyFieldIdentityExact), privacyRule("/at", exact))
	policies[privacyEventPolicyKey{EventServiceDependentManifestSealed, 1}] = privacyRules(privacyRule("/seal", exact), privacyRule("/actor", events.PrivacyFieldIdentityExact), privacyRule("/at", exact))

	policies[privacyEventPolicyKey{EventServiceDependentStepRecoveryQueued, 1}] = privacyRules(privacyRule("/previous_step", exact), privacyRule("/step", exact), privacyRule("/previous_status", exact), privacyRule("/previous_report_digest", exact), privacyRule("/current_vault_version", exact), privacyRule("/recovery_digest", exact), privacyRule("/actor", events.PrivacyFieldIdentityExact), privacyRule("/reason", events.PrivacyFieldFreeTextClear), privacyRule("/at", exact))
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
	closePublishedDependentPrivacyContainers(policies)
}
func addServiceDependentPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventServiceDependentManifestOpened, 1}] = privacyPayloadShape[ServiceDependentManifestOpened]()
	shapes[privacyEventPolicyKey{EventServiceDependentManifestPageRecorded, 1}] = privacyPayloadShape[ServiceDependentManifestPageRecorded]()
	shapes[privacyEventPolicyKey{EventServiceDependentManifestSealed, 1}] = privacyPayloadShape[ServiceDependentManifestSealed]()

	shapes[privacyEventPolicyKey{EventServiceReconciliationReviewProposed, 1}] = privacyPayloadShape[privacyServiceReconciliationReviewV1]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationQueued, 1}] = privacyPayloadShape[privacyServiceDependentRotationQueuedV1]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationQueued, ServiceDependentReconcileSchemaVersion}] = privacyPayloadShape[privacyServiceDependentRotationQueuedV2]()
	shapes[privacyEventPolicyKey{EventServiceDependentRotationInverse, 1}] = privacyPayloadShape[ServiceDependentRotationInverse]()
	shapes[privacyEventPolicyKey{EventServiceDependentDirectoryApplyStarted, 1}] = privacyPayloadShape[ServiceDependentDirectoryApplyStarted]()
	shapes[privacyEventPolicyKey{EventServiceDependentDirectoryRestored, 1}] = privacyPayloadShape[ServiceDependentDirectoryRestored]()
	shapes[privacyEventPolicyKey{EventServiceDependentStepQueued, 1}] = privacyPayloadShape[privacyServiceDependentStepQueuedV1]()
	shapes[privacyEventPolicyKey{EventServiceDependentStepRecoveryQueued, 1}] = privacyPayloadShape[privacyServiceDependentStepRecoveryQueuedV1]()
	shapes[privacyEventPolicyKey{EventServiceDependentStepObserved, 1}] = privacyPayloadShape[ServiceDependentStepObserved]()
	shapes[privacyEventPolicyKey{EventServiceDependentHostSaved, 1}] = privacyPayloadShape[ServiceDependentHostSaved]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanQueued, 1}] = privacyPayloadShape[ServiceDependentScanQueued]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanObserved, 1}] = privacyPayloadShape[ServiceDependentScanObserved]()
	shapes[privacyEventPolicyKey{EventServiceDependentScanFailed, 1}] = privacyPayloadShape[ServiceDependentScanFailed]()
}

// Closed direct fields preserve the old version's native authority while each
// public snapshot remains byte-exact during human identity erasure. Closing an
// entire /intent or /step subtree would hide newly added authority from shape
// validation even when its reflection-derived schema is frozen.
func closePublishedDependentPrivacyContainers(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	replace := func(key privacyEventPolicyKey, path string, fields []string) {
		policy := policies[key]
		rules := make([]events.PrivacyFieldRule, 0, len(policy.Rules)+len(fields))
		for _, rule := range policy.Rules {
			if rule.Path != path {
				rules = append(rules, rule)
			}
		}
		for _, field := range fields {
			rules = append(rules, privacyRule(path+"/"+field, events.PrivacyFieldOpaqueExact))
		}
		policy.Rules = rules
		policies[key] = policy
	}
	for _, key := range []privacyEventPolicyKey{{EventServiceDependentRotationQueued, 1}, {EventServiceDependentRotationQueued, 2}, {EventServiceReconciliationReviewProposed, 1}} {
		fields := []string{"expected_version", "provider_binding", "probes"}
		if key.EventType != EventServiceDependentRotationQueued || key.Version != 1 {
			fields = append(fields, "mode", "reconcile")
		}
		// /intent/plan is deliberately absent here; its original direct fields close
		// individually so a later optional manifest cannot hide in a legacy plan.
		replace(key, "/intent", fields)
		replace(key, "/intent/plan", []string{"version", "id", "account", "secret_name", "hosts", "order", "created_at", "expires_at", "digest"})
	}
	fields := []string{"rotation_id", "plan_digest", "step_id", "direction", "action", "ref", "account_sid", "probe_id", "service", "task", "pool", "previous_pids", "challenge", "not_before", "deadline"}
	replace(privacyEventPolicyKey{EventServiceDependentStepQueued, 1}, "/step", fields)
	recovery := append(append([]string(nil), fields...), "recovery")
	replace(privacyEventPolicyKey{EventServiceDependentStepRecoveryQueued, 1}, "/step", recovery)
	replace(privacyEventPolicyKey{EventServiceDependentStepRecoveryQueued, 1}, "/previous_step", recovery)
}
