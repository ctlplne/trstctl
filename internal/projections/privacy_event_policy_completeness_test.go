// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/store"
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

	legacyDelivery := []byte(`{"id":"delivery-a","destination":"notification.renewal_failure","notification_key_digest":"key","payload_digest":"payload","channel":"privacy-policy-subject","delivered_at":"2026-09-13T03:00:00Z"}`)
	currentDelivery := []byte(`{"id":"delivery-a","destination":"notification.renewal_failure","notification_key_digest":"key","payload_digest":"payload","channel":"email","delivered_at":"2026-09-13T03:00:00Z","routing_source":"inherited_policy","routing_policy_id":"privacy-policy-subject","routing_policy_scope":"asset","routing_policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`)
	assertRejectsSubject(t, legacyDelivery, EventNotificationDeliveryRecorded, 1)
	assertRejectsSubject(t, currentDelivery, EventNotificationDeliveryRecorded, NotificationDeliveryRoutingSchemaVersion)
	assertWrongVersionShape(t, currentDelivery, EventNotificationDeliveryRecorded, 1)
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
			if isLifecycleEvent(eventType) {
				switch version {
				case 1:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}))
				case LifecycleEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}, IdempotencyKey: "stable"}))
				case LifecycleSideEffectEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV3{privacyIdentityTransitionV2: privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}}}))
				case LifecycleApprovalEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV4{privacyIdentityTransitionV3: privacyIdentityTransitionV3{privacyIdentityTransitionV2: privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}}}, Approval: &store.OperationApprovalUse{}}))
				case LifecycleIssuanceEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV5{privacyIdentityTransitionV3: privacyIdentityTransitionV3{privacyIdentityTransitionV2: privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "requested", To: "issued"}}}, Issuance: &store.OperationApprovalIssuanceBinding{}}))
				case LifecycleOwnershipReadinessEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV6{privacyIdentityTransitionV3: privacyIdentityTransitionV3{privacyIdentityTransitionV2: privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}}}, OwnershipReadiness: &store.OwnershipReadinessEvidence{}}))
				case LifecycleCompletedSideEffectEventSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, privacyIdentityTransitionV7{
						privacyIdentityTransitionV2: privacyIdentityTransitionV2{privacyIdentityTransitionV1: privacyIdentityTransitionV1{IdentityID: "identity", From: "issued", To: "deployed"}},
						SideEffect:                  &identityTransitionEffect{Destination: "connector.deploy", IdempotencyKey: "event", Completed: true},
					}))
				}
			}
			if isApplicationSecretMutationEvent(eventType) {
				action := applicationSecretMutationAction(eventType)
				switch version {
				case 1:
					data = []byte(mustPrivacyFixtureJSON(t, applicationSecretLegacyRecoveryFence{
						Name: "secret", Action: action,
					}))
				case ApplicationSecretMutationSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, ApplicationSecretMutation{
						TenantEpoch: "epoch-a", Action: action, Name: "secret",
						ExpectedVersion: 1, ResultVersion: 2,
						IdempotencyKeyDigest: "aa4a", RequestBinding: "aa4a",
						CommandEvidence: "aa4a", Surface: "data",
					}))
				case ApplicationSecretPrivacyDispositionSchemaVersion:
					data = []byte(mustPrivacyFixtureJSON(t, ApplicationSecretPrivacyNameTombstone{
						Action: action, PrivacyDisposition: events.ApplicationSecretPrivacyDispositionNameTombstoned,
						PrivacySubjectRef: "aa4a", PrivacySourceSchemaVersion: 2,
						PrivacyAuthorityTombstone: true,
					}))
				default:
					t.Fatalf("application-secret event %s has no opaque fixture for schema v%d", eventType, version)
				}
			}
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

func applicationSecretMutationAction(eventType string) string {
	switch eventType {
	case EventApplicationSecretCreated:
		return "create"
	case EventApplicationSecretRotated:
		return "rotate"
	case EventApplicationSecretRecovered:
		return "recover"
	case EventApplicationSecretDeleted:
		return "delete"
	default:
		return ""
	}
}

func isApplicationSecretMutationEvent(eventType string) bool {
	switch eventType {
	case EventApplicationSecretCreated, EventApplicationSecretRotated,
		EventApplicationSecretRecovered, EventApplicationSecretDeleted:
		return true
	default:
		return false
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
		{name: "owner depth", eventType: EventOwnerCreated, version: OwnerDepthEventSchemaVersion,
			data:   completePrivacyFixture[OwnerCreated](t, `{"name":"team/privacy-policy-subject","email":"privacy-policy-subject","application_id":"privacy-policy-subject","service":"service/privacy-policy-subject","business_unit":"privacy-policy-subject","environment":"production","escalation_chain":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[OwnerCreated], wantPlaceholder: true},
		{name: "owner depth update", eventType: EventOwnerUpdated, version: OwnerDepthEventSchemaVersion,
			data:   completePrivacyFixture[OwnerUpdated](t, `{"name":"team/privacy-policy-subject","email":"privacy-policy-subject","application_id":"privacy-policy-subject","service":"service/privacy-policy-subject","business_unit":"privacy-policy-subject","environment":"production","escalation_chain":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[OwnerUpdated], wantPlaceholder: true},
		{name: "ownership attestation actor", eventType: EventOwnershipAttested, version: 1,
			data:   completePrivacyFixture[OwnershipAttested](t, `{"attested_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[OwnershipAttested], wantPlaceholder: true},
		{name: "ownership re-attestation recipients", eventType: EventOwnerReattestationRequested, version: 1,
			data:   completePrivacyFixture[OwnerReattestationRequested](t, `{"owner_name":"team/privacy-policy-subject","owner_email":"privacy-policy-subject","escalation_recipients":["privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[OwnerReattestationRequested], wantPlaceholder: true},
		{name: "ownership exception grant", eventType: EventOwnershipExceptionGranted, version: 1,
			data:   completePrivacyFixture[OwnershipExceptionGranted](t, `{"reason":"approved for privacy-policy-subject","granted_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[OwnershipExceptionGranted], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "ownership exception revoke", eventType: EventOwnershipExceptionRevoked, version: 1,
			data:   completePrivacyFixture[OwnershipExceptionRevoked](t, `{"reason":"revoked for privacy-policy-subject","revoked_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[OwnershipExceptionRevoked], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "issuance request", eventType: EventIssuanceRequestOpened, version: 1,
			data:   completePrivacyFixture[IssuanceRequestOpened](t, `{"subject":"spiffe://tenant/privacy-policy-subject","requester":"privacy-policy-subject","justification":"requested by privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestOpened], wantPlaceholder: true,
			want: []string{`"justification":""`}},
		{name: "issuance decision", eventType: EventIssuanceRequestDecided, version: 1,
			data:   completePrivacyFixture[IssuanceRequestDecided](t, `{"decided_by":"privacy-policy-subject","reason":"reviewed by privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestDecided], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "issuance preparation", eventType: EventIssuanceRequestPrepared, version: 1,
			data:   completePrivacyFixture[IssuanceRequestPrepared](t, `{"prepared_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestPrepared], wantPlaceholder: true},
		{name: "issuance completion", eventType: EventIssuanceRequestIssued, version: 1,
			data:   completePrivacyFixture[IssuanceRequestIssued](t, `{"issued_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[IssuanceRequestIssued], wantPlaceholder: true},
		{name: "approval request", eventType: EventApprovalRequested, version: 1,
			data:   completePrivacyFixture[ApprovalRequested](t, `{"resource_name":"team/privacy-policy-subject","requester":"privacy-policy-subject","reason":"for privacy-policy-subject","evidence_refs":["ticket:privacy-policy-subject"]}`),
			decode: decodePrivacyFixture[ApprovalRequested], wantPlaceholder: true,
			want: []string{`"reason":""`, `"evidence_refs":[""]`}},
		{name: "approval decision", eventType: EventApprovalDecisionRecorded, version: 1,
			data:   completePrivacyFixture[ApprovalDecisionRecorded](t, `{"approver":"privacy-policy-subject","reason":"reviewed privacy-policy-subject"}`),
			decode: decodePrivacyFixture[ApprovalDecisionRecorded], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "identity created", eventType: EventIdentityCreated, version: 1,
			data:   completePrivacyFixture[IdentityCreated](t, `{"name":"team/privacy-policy-subject","attributes":{"owner":"privacy-policy-subject"}}`),
			decode: decodePrivacyFixture[IdentityCreated], wantPlaceholder: true,
			want: []string{`"attributes":{}`}},
		{name: "tenant member", eventType: EventTenantMemberUpserted, version: 1,
			data:   completePrivacyFixture[privacyTenantMemberUpsertedV1](t, `{"subject":"privacy-policy-subject","display_name":"team/privacy-policy-subject","email":"privacy-policy-subject","roles":["admin"]}`),
			decode: decodePrivacyFixture[privacyTenantMemberUpsertedV1], wantPlaceholder: true},
		{name: "tenant member offboard", eventType: EventTenantMemberOffboarded, version: 1,
			data:   completePrivacyFixture[privacyTenantMemberOffboardedV1](t, `{"subject":"privacy-policy-subject","reason":"offboard privacy-policy-subject","offboarded_by":"privacy-policy-subject"}`),
			decode: decodePrivacyFixture[privacyTenantMemberOffboardedV1], wantPlaceholder: true,
			want: []string{`"reason":""`}},
		{name: "SCIM member binding", eventType: EventTenantMemberUpserted, version: TenantMemberSCIMSchemaVersion,
			data:   completePrivacyFixture[TenantMemberUpserted](t, `{"subject":"privacy-policy-subject","scim":{"user_name":"different-personal-alias","external_id":"privacy-policy-subject","subject_attribute":"externalId"}}`),
			decode: decodePrivacyFixture[TenantMemberUpserted], wantPlaceholder: true, want: []string{`"scim":{}`}},
		{name: "SCIM inactive binding", eventType: EventTenantMemberOffboarded, version: TenantMemberSCIMSchemaVersion,
			data:   completePrivacyFixture[TenantMemberOffboarded](t, `{"subject":"privacy-policy-subject","scim":{"user_name":"privacy-policy-subject","external_id":"different-personal-external-id","subject_attribute":"userName"}}`),
			decode: decodePrivacyFixture[TenantMemberOffboarded], wantPlaceholder: true, want: []string{`"scim":{}`}},
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
			data:   completePrivacyFixture[NotificationRoutingPolicyUpserted](t, `{"scope_ref":"privacy-policy-subject","owner_ref":"privacy-policy-subject","owner_email":"privacy-policy-subject","channels_by_severity":{"critical":["pager"]}}`),
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
			case LifecycleOwnershipReadinessEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV6](t,
					`{"identity_id":"identity-a","from":"issued","to":"deployed","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key","ownership_readiness":{"mode":"owner","identity_id":"identity-a","owner_id":"owner-a","owner_model_digest":"sha256:model","attested_by":"privacy-policy-subject","verified_at":"2026-08-12T10:00:00Z","attestation_due_at":"2026-11-10T10:00:00Z","evaluated_at":"2026-08-12T10:01:00Z"}}`)
				wantPlaceholder = true
			case LifecycleCompletedSideEffectEventSchemaVersion:
				data = completePrivacyFixture[privacyIdentityTransitionV7](t,
					`{"identity_id":"identity-a","from":"issued","to":"deployed","reason":"requested by privacy-policy-subject","idempotency_key":"stable-key","side_effect":{"destination":"connector.deploy","idempotency_key":"transition:stable-key","completed":true},"ownership_readiness":{"mode":"owner","identity_id":"identity-a","owner_id":"owner-a","owner_model_digest":"sha256:model","attested_by":"privacy-policy-subject","verified_at":"2026-08-12T10:00:00Z","attestation_due_at":"2026-11-10T10:00:00Z","evaluated_at":"2026-08-12T10:01:00Z"}}`)
				wantPlaceholder = true
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

func TestMigrationPrivacyRewritePreservesExecutableRunAndActionBindingAUD40(t *testing.T) {
	const subject = "alice"
	run := migration.Run{
		ID: "40400000-0000-4000-8000-000000000040", PlanID: subject, Status: migration.RunRunning,
		Waves: []migration.RunWave{{
			ID: subject, Ordinal: 1, Phase: migration.PhaseVerifyingTrust, Started: true,
			Members: []migration.RunMember{{
				IdentityID: "40400000-0000-4000-8000-000000000041",
				Binding: migration.MemberBinding{
					IssuingAuthorityID: "40400000-0000-4000-8000-000000000042",
					TargetID:           "40400000-0000-4000-8000-000000000043", TargetRevision: "revision-a",
					Connector: "nginx", Target: subject,
					TargetConfig:    json.RawMessage(`{"owner":"alice"}`),
					RequiredAgentID: "40400000-0000-4000-8000-000000000044",
					TrustAnchorPath: "/etc/" + subject + "/root.pem", TrustAnchorPEM: []byte("public-ca"),
					TrustAnchorFingerprint: "aaaaaaaa", VerifyAddress: "127.0.0.1:443",
					VerifyServerName: subject, SubjectCommonName: subject,
					SubjectDNSNames:          []string{subject},
					PredecessorCertificateID: "40400000-0000-4000-8000-000000000045",
					PredecessorFingerprint:   "bbbbbbbb",
				},
			}},
		}},
	}
	payload, err := json.Marshal(MigrationRunRecorded{Run: run, Actions: []migration.Action{{
		Kind: migration.ActionDistributeTrust, WaveID: run.Waves[0].ID, IdentityID: run.Waves[0].Members[0].IdentityID,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(payload, "tenant-a", subject, EventMigrationRunRecorded, 1)
	if err != nil || !changed || bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("migration privacy rewrite changed=%t err=%v payload=%s", changed, err, rewritten)
	}
	var got MigrationRunRecorded
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	if err := migration.ValidateExecutableRun(got.Run); err != nil {
		t.Fatalf("rewritten migration run lost executable authority: %v", err)
	}
	if err := migration.ValidateActions(got.Run, got.Actions); err != nil {
		t.Fatalf("rewritten migration actions drifted from their wave: %v", err)
	}
}

func TestExplicitRejectPolicyDoesNotInferFieldsFromAnotherSchema(t *testing.T) {
	if _, _, err := events.PseudonymizeEventDataForSubject(
		[]byte(`{"name":"a"}`), "tenant-a", "a", EventTenantRegistered, 1,
	); err == nil || !strings.Contains(err.Error(), "rejects subject-bearing") {
		t.Fatalf("tenant.registered inherited another schema's name policy: %v", err)
	}
}
