// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacyref"
)

func TestEveryProjectorKnownSchemaHasClosedPrivacyPolicy(t *testing.T) {
	types := make([]string, 0, len(knownSchemaVersions))
	for eventType := range knownSchemaVersions {
		types = append(types, eventType)
	}
	sort.Strings(types)
	for _, eventType := range types {
		versions := make([]int, 0, len(knownSchemaVersions[eventType]))
		for version := range knownSchemaVersions[eventType] {
			versions = append(versions, version)
		}
		sort.Ints(versions)
		for _, version := range versions {
			if !events.HasPrivacyEventPolicy(eventType, version) {
				t.Errorf("projector-known event %s v%d has no closed privacy policy", eventType, version)
			}
			if _, _, err := events.PseudonymizeEventDataForSubject(
				[]byte(`{"unregistered_subject_path":"privacy-policy-subject"}`),
				"tenant-a", "privacy-policy-subject", eventType, version,
			); err == nil {
				t.Errorf("projector-known event %s v%d accepted an undeclared subject path", eventType, version)
			}
		}
	}
}

func TestExactProjectorPrivacyPoliciesHaveVersionSpecificPayloadShapes(t *testing.T) {
	policies := exactProjectorPrivacyPolicies()
	shapes := exactProjectorPrivacyPayloadShapes()
	if len(shapes) != len(policies) {
		t.Fatalf("exact projector privacy shape denominator = %d, want %d policies", len(shapes), len(policies))
	}
	for key := range policies {
		if _, ok := shapes[key]; !ok {
			t.Errorf("exact projector privacy policy %s v%d has no version-specific payload shape", key.EventType, key.Version)
		}
	}
	for key := range shapes {
		if _, ok := policies[key]; !ok {
			t.Errorf("orphan exact projector privacy payload shape %s v%d has no policy", key.EventType, key.Version)
		}
	}
}

func TestRejectProjectorPrivacyPayloadShapesCoverEveryVersionCoordinate(t *testing.T) {
	exact := exactProjectorPrivacyPayloadShapes()
	reject := projectorPrivacyPayloadShapes()
	externallyRegistered := make(map[privacyEventPolicyKey]struct{})
	for _, schema := range events.CoreProductionPrivacyEventSchemas() {
		externallyRegistered[privacyEventPolicyKey{
			EventType: schema.EventType, Version: schema.SchemaVersion,
		}] = struct{}{}
	}
	for _, version := range []int{1, CodeSigningApprovalEventSchemaVersion, CodeSigningPrivacySafeEventSchemaVersion} {
		externallyRegistered[privacyEventPolicyKey{EventType: EventCodeSigningCommanded, Version: version}] = struct{}{}
	}
	for _, eventType := range []string{
		EventApplicationSecretCreated,
		EventApplicationSecretRotated,
		EventApplicationSecretRecovered,
		EventApplicationSecretDeleted,
	} {
		for _, version := range []int{
			1,
			ApplicationSecretMutationSchemaVersion,
			ApplicationSecretPrivacyDispositionSchemaVersion,
		} {
			externallyRegistered[privacyEventPolicyKey{EventType: eventType, Version: version}] = struct{}{}
		}
	}

	for eventType, versions := range knownSchemaVersions {
		for version := range versions {
			key := privacyEventPolicyKey{EventType: eventType, Version: version}
			if _, ok := exact[key]; ok {
				continue
			}
			if _, ok := externallyRegistered[key]; ok {
				continue
			}
			if _, ok := reject[key]; !ok {
				t.Errorf("reject projector event %s v%d has no coordinate-specific payload shape", eventType, version)
			}
		}
	}
	for key := range reject {
		versions, known := knownSchemaVersions[key.EventType]
		if !known || !versions[key.Version] {
			t.Errorf("orphan reject payload shape %s v%d is not a projector-known coordinate", key.EventType, key.Version)
		}
	}
}

func TestRejectProjectorPrivacyShapesDoNotCrossSchemaVersionLabels(t *testing.T) {
	const subject = "privacy-policy-subject"
	assertRejectsSubject := func(t *testing.T, data []byte, eventType string, version int) {
		t.Helper()
		if _, _, err := events.PseudonymizeEventDataForSubject(
			data, "tenant-a", subject, eventType, version,
		); err == nil || !strings.Contains(err.Error(), "rejects subject-bearing") {
			t.Fatalf("%s v%d did not reach its exact reject policy: %v", eventType, version, err)
		}
	}
	assertWrongVersionShape := func(t *testing.T, data []byte, eventType string, version int) {
		t.Helper()
		if _, _, err := events.PseudonymizeEventDataForSubject(
			data, "tenant-a", subject, eventType, version,
		); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
			t.Fatalf("%s v%d accepted another version's field labels: %v", eventType, version, err)
		}
	}

	legacyCA := []byte(`{"ca_id":"privacy-policy-subject","common_name":"Legacy Root","ceremony_id":"ceremony-a","signer_handle":"signer-a"}`)
	currentCA := []byte(`{"ca_id":"privacy-policy-subject","common_name":"Current Root","kind":"root","certificate_pem":"public-certificate","signer_handle":"signer-a","serial":"01","not_after":"2026-08-12T00:00:00Z","max_path_len":1,"ceremony_id":"ceremony-a"}`)
	assertRejectsSubject(t, legacyCA, EventCARootCreated, 1)
	assertRejectsSubject(t, currentCA, EventCARootCreated, CAAuthorityCreatedEventSchemaVersion)
	assertWrongVersionShape(t, currentCA, EventCARootCreated, 1)
	assertWrongVersionShape(t, legacyCA, EventCARootCreated, CAAuthorityCreatedEventSchemaVersion)

	legacySync := []byte(`{"id":"job-a","secret_name":"privacy-policy-subject","secret_version":1,"target":"target-a","remote_key":"remote-a","value_digest":"sha256:value","idempotency_key":"stable-key","sealed":"YQ=="}`)
	currentSync := []byte(`{"tenant_epoch":"epoch-a","id":"job-a","secret_name":"privacy-policy-subject","secret_version":1,"target":"target-a","remote_key":"remote-a","value_digest":"sha256:value","idempotency_key":"stable-key","sealed":"YQ=="}`)
	assertRejectsSubject(t, legacySync, EventSecretSyncQueued, 1)
	assertRejectsSubject(t, currentSync, EventSecretSyncQueued, SecretSyncEventSchemaVersion)
	assertWrongVersionShape(t, currentSync, EventSecretSyncQueued, 1)
	assertWrongVersionShape(t, legacySync, EventSecretSyncQueued, SecretSyncEventSchemaVersion)

	legacyManagedKeyRequested := []byte(`{"operation_id":"operation-a","provider":"privacy-policy-subject","action":"rotate","key_id":"key-a","algorithm":"","request_binding":"binding-a"}`)
	legacyManagedKeyCompleted := []byte(`{"operation_id":"operation-a","provider":"privacy-policy-subject","action":"rotate","key_id":"key-a","algorithm":"","request_binding":"binding-a","result_key_id":"key-b","public_der":"YQ==","state":"active"}`)
	currentOnlyManagedKey := []byte(`{"operation_id":"operation-a","provider":"privacy-policy-subject","action":"rotate","key_id":"key-a","algorithm":"","request_binding":"binding-a","requester":"operator-a","from_state":"active","to_state":"rotated","target_version":2,"idempotency_key_digest":"sha256:idempotency","approval_evidence_refs":[],"approval":{"request_id":"request-a"}}`)
	assertRejectsSubject(t, legacyManagedKeyRequested, EventManagedKeyCommandRequested, 1)
	assertRejectsSubject(t, legacyManagedKeyCompleted, EventManagedKeyCommandCompleted, 1)
	assertWrongVersionShape(t, currentOnlyManagedKey, EventManagedKeyCommandRequested, 1)
}

func TestEveryProjectorSubjectBearingPolicyPathHasMechanicalFixture(t *testing.T) {
	covered := 0
	for eventType, versions := range knownSchemaVersions {
		for version := range versions {
			count, err := events.ValidatePrivacyEventPolicySubjectFixtures(eventType, version)
			if err != nil {
				t.Errorf("projector event %s v%d subject fixture: %v", eventType, version, err)
			}
			covered += count
		}
	}
	if covered == 0 {
		t.Fatal("projector privacy catalog exercised no subject-bearing paths")
	}
}

func TestShortSubjectDoesNotCollideWithOpaqueKnownSchemaValues(t *testing.T) {
	for eventType, knownVersions := range knownSchemaVersions {
		for version := range knownVersions {
			data := []byte(`{"status":"active","algorithm":"saml","digest":"aa4a","kind":"ca","protocol":"data"}`)
			if eventType == EventCodeSigningCommanded {
				payload := CodeSigningCommanded{
					OperationID:   "data",
					Mode:          "saml",
					RequestHash:   "aa4a",
					SealedCommand: []byte("opaque-command"),
				}
				if version <= CodeSigningApprovalEventSchemaVersion {
					payload.IdempotencyKey = "stable-key"
				} else {
					payload.IdempotencyKeyRef = "sha256:aa4a"
					payload.RequestBinding = "data"
				}
				data = []byte(completePrivacyFixture[CodeSigningCommanded](t, mustPrivacyFixtureJSON(t, payload)))
			}
			rewritten, changed, err := events.PseudonymizeEventDataForSubject(
				data, "tenant-a", "a", eventType, version,
			)
			if err != nil || changed || !bytes.Equal(rewritten, data) {
				t.Errorf("%s v%d short-subject opaque collision: changed=%t err=%v data=%s",
					eventType, version, changed, err, rewritten)
			}
		}
	}
}

func decodePrivacyFixture[T any](data []byte) error {
	var value T
	return json.Unmarshal(data, &value)
}

func mustPrivacyFixtureJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal privacy fixture: %v", err)
	}
	return string(data)
}

// completePrivacyFixture decodes the subject-bearing fields through the exact
// event type, then marshals that type back to JSON. Required zero-value fields
// therefore stay present while optional fields stay omitted, matching the
// closed payload shape that production decoding owns.
func completePrivacyFixture[T any](t *testing.T, partial string) string {
	t.Helper()
	var value T
	decoder := json.NewDecoder(strings.NewReader(partial))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode typed privacy fixture: %v", err)
	}
	return mustPrivacyFixtureJSON(t, value)
}

func TestCatalogedPersonalDataEventPathsRewriteAndStillDecode(t *testing.T) {
	const subject = "privacy-policy-subject"
	placeholder := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", subject))
	type fixture struct {
		name, eventType string
		version         int
		data            string
		decode          func([]byte) error
		want            []string
		wantPlaceholder bool
	}
	fixtures := []fixture{
		{name: "owner", eventType: EventOwnerCreated, version: 1,
			data:   completePrivacyFixture[OwnerCreated](t, `{"name":"team/privacy-policy-subject","email":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[OwnerCreated], wantPlaceholder: true},
		{name: "issuance request", eventType: EventIssuanceRequestOpened, version: 1,
			data:   completePrivacyFixture[IssuanceRequestOpened](t, `{"subject":"spiffe://tenant/privacy-policy-subject","requester":"privacy-policy-subject","justification":"requested by privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestOpened], wantPlaceholder: true,
			want: []string{`"justification":""`}},
		{name: "issuance decision", eventType: EventIssuanceRequestDecided, version: 1,
			data:   completePrivacyFixture[IssuanceRequestDecided](t, `{"decided_by":"privacy-policy-subject","reason":"reviewed by privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestDecided], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "approval request", eventType: EventApprovalRequested, version: 1,
			data:   completePrivacyFixture[ApprovalRequested](t, `{"resource_name":"team/privacy-policy-subject","requester":"privacy-policy-subject","reason":"for privacy-policy-subject","evidence_refs":["ticket:privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[ApprovalRequested], wantPlaceholder: true,
			want: []string{`"reason":""`, `"evidence_refs":[]`}},
		{name: "approval decision", eventType: EventApprovalDecisionRecorded, version: 1,
			data:   completePrivacyFixture[ApprovalDecisionRecorded](t, `{"approver":"privacy-policy-subject","reason":"reviewed privacy-policy-subject"}`),
			decode: decodePrivacyFixture[ApprovalDecisionRecorded], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "identity created", eventType: EventIdentityCreated, version: 1,
			data:   completePrivacyFixture[IdentityCreated](t, `{"name":"team/privacy-policy-subject","attributes":{"owner":"privacy-policy-subject"}}`),
			decode: decodePrivacyFixture[IdentityCreated], wantPlaceholder: true,
			want: []string{`"attributes":{}`}},
		{name: "tenant member", eventType: EventTenantMemberUpserted, version: 1,
			data:   completePrivacyFixture[TenantMemberUpserted](t, `{"subject":"privacy-policy-subject","display_name":"team/privacy-policy-subject","email":"privacy-policy-subject","roles":["admin"]}`),
			decode: decodePrivacyFixture[TenantMemberUpserted], wantPlaceholder: true},
		{name: "tenant member offboard", eventType: EventTenantMemberOffboarded, version: 1,
			data:   completePrivacyFixture[TenantMemberOffboarded](t, `{"subject":"privacy-policy-subject","reason":"offboard privacy-policy-subject","offboarded_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[TenantMemberOffboarded], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "api token create", eventType: EventAPITokenCreated, version: 1,
			data:   completePrivacyFixture[APITokenCreated](t, `{"subject":"privacy-policy-subject","token_hash":"aa4a","scopes":["admin"]}`),
			decode: decodePrivacyFixture[APITokenCreated], wantPlaceholder: true},
		{name: "api token revoke", eventType: EventAPITokenRevoked, version: 1,
			data:   completePrivacyFixture[APITokenRevoked](t, `{"revoked_by":"privacy-policy-subject","reason":"revoked for privacy-policy-subject"}`),
			decode: decodePrivacyFixture[APITokenRevoked], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "agent heartbeat", eventType: EventAgentHeartbeat, version: 1,
			data:   completePrivacyFixture[AgentHeartbeat](t, `{"agent":"privacy-policy-subject","status":"active","roles":["admin"]}`),
			decode: decodePrivacyFixture[AgentHeartbeat], wantPlaceholder: true},
		{name: "agent renewal", eventType: EventAgentCertRenewed, version: 1,
			data:   completePrivacyFixture[AgentCertRenewed](t, `{"agent":"privacy-policy-subject","old_serial":"aa4a","new_serial":"bb4b"}`),
			decode: decodePrivacyFixture[AgentCertRenewed], wantPlaceholder: true},
		{name: "agent revocation", eventType: EventAgentCertRevoked, version: 1,
			data:   completePrivacyFixture[AgentCertRevoked](t, `{"agent":"privacy-policy-subject","reason":"revoke privacy-policy-subject"}`),
			decode: decodePrivacyFixture[AgentCertRevoked], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "agent offboard", eventType: EventAgentOffboarded, version: 1,
			data:   completePrivacyFixture[AgentOffboarded](t, `{"agent":"privacy-policy-subject","reason":"offboard privacy-policy-subject","offboarded_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[AgentOffboarded], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "profile author", eventType: EventProfileCreated, version: ProfileEventSchemaVersion,
			data:   completePrivacyFixture[ProfileVersioned](t, `{"created_by":"privacy-policy-subject","name":"active-profile","spec":{}}`),
			decode: decodePrivacyFixture[ProfileVersioned], wantPlaceholder: true},
		{name: "pam start", eventType: EventPAMSessionStarted, version: 1,
			data:   completePrivacyFixture[PAMSessionStarted](t, `{"subject":"privacy-policy-subject","requested_by":"privacy-policy-subject","reason":"for privacy-policy-subject","audit":{"operator":"privacy-policy-subject"}}`),
			decode: decodePrivacyFixture[PAMSessionStarted], wantPlaceholder: true,
			want: []string{`"reason":""`, `"audit":{}`}},
		{name: "pam expire", eventType: EventPAMSessionExpired, version: 1,
			data:   completePrivacyFixture[PAMSessionExpired](t, `{"reason":"expired by privacy-policy-subject"}`),
			decode: decodePrivacyFixture[PAMSessionExpired],
			want:   []string{`"reason":""`}},
		{name: "discovery source config", eventType: EventDiscoverySourceUpserted, version: 1,
			data:   completePrivacyFixture[DiscoverySourceUpserted](t, `{"name":"active-source","config":{"principal":"privacy-policy-subject","nested":[{"owner":"privacy-policy-subject"}]}}`),
			decode: decodePrivacyFixture[DiscoverySourceUpserted], wantPlaceholder: true},
		{name: "discovery requester", eventType: EventDiscoveryRunQueued, version: 1,
			data:   completePrivacyFixture[DiscoveryRunQueued](t, `{"requested_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[DiscoveryRunQueued], wantPlaceholder: true},
		{name: "discovery finding metadata", eventType: EventDiscoveryFindingRecorded, version: 1,
			data:   completePrivacyFixture[DiscoveryFindingRecorded](t, `{"metadata":{"principal":"privacy-policy-subject","nested":["privacy-policy-subject"]}}`),
			decode: decodePrivacyFixture[DiscoveryFindingRecorded], wantPlaceholder: true},
		{name: "discovery triage", eventType: EventDiscoveryFindingTriageChanged, version: 1,
			data:   completePrivacyFixture[DiscoveryFindingTriageChanged](t, `{"actor":"privacy-policy-subject","reason":"triaged by privacy-policy-subject","metadata_patch":{"owner":"privacy-policy-subject"}}`),
			decode: decodePrivacyFixture[DiscoveryFindingTriageChanged], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "notification threshold", eventType: EventNotificationThresholdDelivered, version: 1,
			data:   completePrivacyFixture[NotificationThresholdDelivered](t, `{"subject":"privacy-policy-subject","channel":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[NotificationThresholdDelivered], wantPlaceholder: true},
		{name: "notification routing", eventType: EventNotificationRoutingPolicyUpserted, version: 1,
			data:   completePrivacyFixture[NotificationRoutingPolicyUpserted](t, `{"owner_ref":"privacy-policy-subject","owner_email":"privacy-policy-subject","channels_by_severity":{"critical":["pager"]}}`),
			decode: decodePrivacyFixture[NotificationRoutingPolicyUpserted], wantPlaceholder: true,
			want: []string{`"owner_email":""`}},
		{name: "incident execution", eventType: EventIncidentExecutionRecorded, version: 1,
			data:   completePrivacyFixture[IncidentExecutionRecorded](t, `{"created_by":"privacy-policy-subject","reason":"run by privacy-policy-subject","evidence_bundle":"evidence privacy-policy-subject","failed_targets":["privacy-policy-subject"],"rollback_refs":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[IncidentExecutionRecorded], wantPlaceholder: true,
			want: []string{`"reason":""`, `"evidence_bundle":""`, `"failed_targets":[""]`, `"rollback_refs":[""]`}},
		{name: "fleet reissuance", eventType: EventIncidentFleetReissuanceRecorded, version: 1,
			data:   completePrivacyFixture[IncidentFleetReissuanceRecorded](t, `{"created_by":"privacy-policy-subject","reason":"run by privacy-policy-subject","halted_reason":"halted by privacy-policy-subject","evidence_bundle":"evidence privacy-policy-subject","failed_targets":["privacy-policy-subject"],"rollback_refs":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[IncidentFleetReissuanceRecorded], wantPlaceholder: true,
			want: []string{`"reason":""`, `"halted_reason":""`, `"evidence_bundle":""`, `"failed_targets":[""]`, `"rollback_refs":[""]`}},
		{name: "remediation run", eventType: EventRemediationPlaybookRunRecorded, version: 1,
			data:   completePrivacyFixture[RemediationPlaybookRunRecorded](t, `{"created_by":"privacy-policy-subject","reason":"run by privacy-policy-subject","terminal_reason":"ended by privacy-policy-subject","evidence_refs":["privacy-policy-subject"],"rollback_refs":["privacy-policy-subject"],"initial_response":{"operator":"privacy-policy-subject"}}`),
			decode: decodePrivacyFixture[RemediationPlaybookRunRecorded], wantPlaceholder: true,
			want: []string{`"reason":""`, `"terminal_reason":""`, `"evidence_refs":[""]`, `"rollback_refs":[""]`, `"initial_response":{}`}},
		{name: "access review campaign", eventType: EventNHIAccessReviewCampaignStarted, version: 1,
			data:   completePrivacyFixture[NHIAccessReviewCampaignStarted](t, `{"reviewer_subject":"privacy-policy-subject","requested_by":"privacy-policy-subject","items":[]}`),
			decode: decodePrivacyFixture[NHIAccessReviewCampaignStarted], wantPlaceholder: true},
		{name: "access review decision", eventType: EventNHIAccessReviewItemDecided, version: 1,
			data:   completePrivacyFixture[NHIAccessReviewItemDecided](t, `{"reviewer_subject":"privacy-policy-subject","reason":"reviewed by privacy-policy-subject","decision_evidence_refs":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[NHIAccessReviewItemDecided], wantPlaceholder: true,
			want: []string{`"reason":""`, `"decision_evidence_refs":[""]`}},
		{name: "access change request", eventType: EventAccessChangeRequestCreated, version: 1,
			data:   completePrivacyFixture[AccessChangeRequestCreated](t, `{"requester_subject":"privacy-policy-subject","reason":"requested by privacy-policy-subject","evidence_refs":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[AccessChangeRequestCreated], wantPlaceholder: true,
			want: []string{`"reason":""`, `"evidence_refs":[""]`}},
		{name: "access change decision", eventType: EventAccessChangeRequestDecided, version: 1,
			data:   completePrivacyFixture[AccessChangeRequestDecided](t, `{"approver_subject":"privacy-policy-subject","reason":"approved by privacy-policy-subject","decision_evidence_refs":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[AccessChangeRequestDecided], wantPlaceholder: true,
			want: []string{`"reason":""`, `"decision_evidence_refs":[""]`}},
		{name: "compliance recipient", eventType: EventComplianceReportScheduleUpserted, version: 1,
			data:   completePrivacyFixture[ComplianceReportScheduleUpserted](t, `{"recipient_ref":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[ComplianceReportScheduleUpserted], wantPlaceholder: true},
	}

	for _, eventType := range []string{
		EventIdentityIssued, EventIdentityDeployed, EventIdentityRevoked,
		EventIdentityRenewing, EventIdentityRenewed, EventIdentityRetired,
	} {
		for version := range knownSchemaVersions[eventType] {
			var (
				data            string
				wantPlaceholder bool
				want            = []string{`"reason":""`}
			)
			switch version {
			case 1:
				data = completePrivacyFixture[privacyIdentityTransitionV1](t,
					`{"identity_id":"identity-a","from":"active","to":"revoked","reason":"requested by privacy-policy-subject"}`)
			case LifecycleEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV2](t,
					`{"identity_id":"identity-a","from":"active","to":"revoked","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key"}`)
			case LifecycleSideEffectEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV3](t,
					`{"identity_id":"identity-a","from":"active","to":"revoked","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key"}`)
			case LifecycleApprovalEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV4](t,
					`{"identity_id":"identity-a","from":"active","to":"revoked","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key","approval":{"request_id":"request-a","intent_digest":"aa4a","requester":"privacy-policy-subject","resource_kind":"identity","resource_id":"identity-a","action":"revoke","from_state":"active","to_state":"revoked","target_version":1,"required_approvals":1,"reason":"approved for privacy-policy-subject","evidence_refs":["privacy-policy-subject"]}}`)
				wantPlaceholder = true
				want = append(want, `"evidence_refs":[""]`)
			case LifecycleIssuanceEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV5](t,
					`{"identity_id":"identity-a","from":"pending","to":"issued","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key","issuance":{"requested_ttl_seconds":3600,"effective_ttl_seconds":3600}}`)
			default:
				t.Fatalf("identity transition %s has no privacy fixture for schema v%d", eventType, version)
			}
			fixtures = append(fixtures, fixture{
				name: eventType + " personal paths", eventType: eventType, version: version,
				data: data, decode: decodePrivacyFixture[identityTransition],
				wantPlaceholder: wantPlaceholder, want: want,
			})
		}
	}

	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			rewritten, changed, err := events.PseudonymizeEventDataForSubject(
				[]byte(test.data), "tenant-a", subject, test.eventType, test.version,
			)
			if err != nil || !changed {
				t.Fatalf("privacy rewrite changed=%t err=%v data=%s", changed, err, rewritten)
			}
			if !json.Valid(rewritten) || bytes.Contains(rewritten, []byte(subject)) {
				t.Fatalf("privacy rewrite retained raw subject or invalid JSON: %s", rewritten)
			}
			if test.wantPlaceholder && !bytes.Contains(rewritten, []byte(placeholder)) {
				t.Fatalf("privacy rewrite did not write tenant placeholder %q: %s", placeholder, rewritten)
			}
			for _, want := range test.want {
				if !bytes.Contains(rewritten, []byte(want)) {
					t.Errorf("privacy rewrite missing %s: %s", want, rewritten)
				}
			}
			if err := test.decode(rewritten); err != nil {
				t.Fatalf("rewritten payload no longer decodes as %s v%d: %v", test.eventType, test.version, err)
			}
		})
	}
}

func TestOwnerPrivacyPolicyUsesExactPathsAndPreservesOpaqueShortSubject(t *testing.T) {
	input := []byte(`{"id":"aa4a","kind":"ca","name":"a","email":"a"}`)
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		input, "tenant-a", "a", EventOwnerCreated, 1,
	)
	if err != nil || !changed {
		t.Fatalf("owner privacy rewrite changed=%t err=%v", changed, err)
	}
	var got OwnerCreated
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "aa4a" || got.Kind != "ca" || got.Name == "a" || got.Email == "a" ||
		!strings.HasPrefix(got.Name, "erased:") || got.Name != got.Email {
		t.Fatalf("owner exact-path rewrite = %+v", got)
	}
}

func TestExplicitRejectPolicyDoesNotInferFieldsFromAnotherSchema(t *testing.T) {
	if _, _, err := events.PseudonymizeEventDataForSubject(
		[]byte(`{"name":"a"}`), "tenant-a", "a", EventTenantRegistered, 1,
	); err == nil || !strings.Contains(err.Error(), "rejects subject-bearing") {
		t.Fatalf("tenant.registered inherited another schema's name policy: %v", err)
	}
}
