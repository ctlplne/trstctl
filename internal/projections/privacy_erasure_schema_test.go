// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestPrivacySubjectErasedSchemaVersionsAreExplicit(t *testing.T) {
	for _, version := range []int{
		1,
		PrivacySubjectErasedOperationEventSchemaVersion,
		PrivacySubjectErasedEventSchemaVersion,
	} {
		if err := ValidateSchemaVersion(events.Event{
			Type: EventPrivacySubjectErased, SchemaVersion: version,
		}); err != nil {
			t.Fatalf("privacy.subject.erased v%d: %v", version, err)
		}
	}
	if err := ValidateSchemaVersion(events.Event{
		Type:          EventPrivacySubjectErased,
		SchemaVersion: PrivacySubjectErasedEventSchemaVersion + 1,
	}); !errors.Is(err, ErrUnknownSchemaVersion) {
		t.Fatalf("future privacy.subject.erased schema error = %v, want ErrUnknownSchemaVersion", err)
	}
}

func TestPrivacySubjectErasedV3PayloadRejectsPIICapableSelectorsAndOpenFenceEvidence(t *testing.T) {
	event := events.Event{
		Type: EventPrivacySubjectErased, SchemaVersion: PrivacySubjectErasedEventSchemaVersion,
	}
	valid := PrivacySubjectErased{
		OperationID: "operation", RequestBinding: "binding", SubjectRef: strings.Repeat("a", 64),
		Selectors: store.PrivacyErasureSelectors{ReadModels: []store.PrivacyReadModelSelector{{
			Table: "operation_approval_requests", ID: "77952000-0000-4000-8000-000000000001",
		}}},
		Counts: map[string]int{
			"owners": 0, "read_models": 1, "operation_approval_requests": 1,
			"secret_rotation_schedule_ticks":             0,
			"secret_rotation_schedule_tick_rows":         0,
			"secret_rotation_schedule_commands":          0,
			"secret_rotation_schedule_outer_resolutions": 0,
		},
		RecoveryFences:        []store.PrivacyRecoveryFenceDisposition{},
		SchedulerDispositions: []store.SecretRotationSchedulePrivacyDisposition{},
	}
	if err := ValidatePrivacySubjectErasedPayload(event, valid); err != nil {
		t.Fatalf("valid v3 payload: %v", err)
	}

	for name, mutate := range map[string]func(*PrivacySubjectErased){
		"raw subject reference": func(payload *PrivacySubjectErased) {
			payload.SubjectRef = "alice@example.com"
		},
		"non canonical subject reference": func(payload *PrivacySubjectErased) {
			payload.SubjectRef = strings.Repeat("A", 64)
		},
		"raw requester reference": func(payload *PrivacySubjectErased) {
			payload.RequestedByRef = "privacy-admin@example.com"
		},
		"missing recovery evidence": func(payload *PrivacySubjectErased) {
			payload.RecoveryFences = nil
		},
		"missing scheduler evidence": func(payload *PrivacySubjectErased) {
			payload.SchedulerDispositions = nil
		},
		"raw approval resource": func(payload *PrivacySubjectErased) {
			payload.Selectors.ApprovalRequests = []store.PrivacyApprovalSelector{{Resource: "alice@example.com", Action: "issue"}}
		},
		"raw certificate fingerprint": func(payload *PrivacySubjectErased) {
			payload.Selectors.CertificateFingerprints = []string{"alice@example.com"}
		},
		"open count key": func(payload *PrivacySubjectErased) {
			payload.Counts = map[string]int{"alice@example.com": 1}
		},
		"non uuid read model id": func(payload *PrivacySubjectErased) {
			payload.Selectors.ReadModels = []store.PrivacyReadModelSelector{{
				Table: "operation_approval_requests", ID: "alice@example.com",
			}}
		},
		"open read model table": func(payload *PrivacySubjectErased) {
			payload.Selectors.ReadModels = []store.PrivacyReadModelSelector{{
				Table: "subject_alice@example.com", ID: "77952000-0000-4000-8000-000000000001",
			}}
		},
		"open fence kind": func(payload *PrivacySubjectErased) {
			payload.RecoveryFences = []store.PrivacyRecoveryFenceDisposition{{
				Kind: "subject:alice@example.com", EventID: "77952000-0000-4000-8000-000000000003",
				Disposition: store.PrivacyRecoveryFenceDeleted,
			}}
		},
		"open fence disposition": func(payload *PrivacySubjectErased) {
			payload.RecoveryFences = []store.PrivacyRecoveryFenceDisposition{{
				Kind:    store.PrivacyRecoveryFenceApplicationSecret,
				EventID: "77952000-0000-4000-8000-000000000003", Disposition: "retained:alice@example.com",
			}}
		},
		"non uuid fence event": func(payload *PrivacySubjectErased) {
			payload.RecoveryFences = []store.PrivacyRecoveryFenceDisposition{{
				Kind:    store.PrivacyRecoveryFenceApplicationSecret,
				EventID: "alice@example.com", Disposition: store.PrivacyRecoveryFenceDeleted,
			}}
		},
		"duplicate fence evidence": func(payload *PrivacySubjectErased) {
			fence := store.PrivacyRecoveryFenceDisposition{
				Kind:    store.PrivacyRecoveryFenceApplicationSecret,
				EventID: "77952000-0000-4000-8000-000000000003", Disposition: store.PrivacyRecoveryFenceDeleted,
			}
			payload.RecoveryFences = []store.PrivacyRecoveryFenceDisposition{fence, fence}
		},
		"open scheduler kind": func(payload *PrivacySubjectErased) {
			payload.SchedulerDispositions = []store.SecretRotationSchedulePrivacyDisposition{{
				Kind: "subject:alice@example.com", AuthorityRef: strings.Repeat("b", 64),
				Disposition: store.SecretRotationSchedulePrivacyDispositionErased,
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			payload := valid
			mutate(&payload)
			if err := ValidatePrivacySubjectErasedPayload(event, payload); err == nil {
				t.Fatal("invalid v3 payload was accepted")
			}
		})
	}

	legacy := valid
	legacy.Selectors.ApprovalRequests = []store.PrivacyApprovalSelector{{
		Resource: "legacy arbitrary resource", Action: "legacy arbitrary action",
	}}
	legacy.Selectors.CertificateFingerprints = []string{"legacy-fingerprint"}
	legacy.RecoveryFences = nil
	if err := ValidatePrivacySubjectErasedPayload(events.Event{
		Type: EventPrivacySubjectErased, SchemaVersion: PrivacySubjectErasedOperationEventSchemaVersion,
	}, legacy); err != nil {
		t.Fatalf("legacy v2 payload must remain replayable: %v", err)
	}
}
