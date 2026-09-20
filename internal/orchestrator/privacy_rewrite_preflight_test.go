// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestErasePrivacySubjectFailsBeforeTouchingStoreOrLogWithoutProofSet proves the
// served command cannot emit privacy.subject.erased and only then discover that
// destructive history rewrite authority is missing. Nil dependencies are
// intentional: any store selection or event append would panic this test.
func TestErasePrivacySubjectFailsBeforeTouchingStoreOrLogWithoutProofSet(t *testing.T) {
	orch := NewOrchestrator(nil, nil, nil)
	_, err := orch.ErasePrivacySubject(
		context.Background(),
		"22bdcaa0-7286-4c85-a318-81871274ebd6",
		"erased@example.test",
		"request",
	)
	if err == nil || !strings.Contains(err.Error(), "signed continuity callback") {
		t.Fatalf("ErasePrivacySubject error = %v, want proof-set preflight failure", err)
	}
}

func TestErasePrivacySubjectFailsBeforeStoreTouchWhenLogVerifierWasNotWired(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open raw event log: %v", err)
	}
	defer func() { _ = log.Close() }()

	orch := NewOrchestrator(
		log,
		nil, // any store touch after preflight would panic
		nil,
		WithTenantDataRewriteOptions(
			events.WithTenantDataContinuity(func(context.Context, events.TenantDataRewriteReport) (events.Event, error) {
				return events.Event{}, nil
			}),
			events.WithTenantDataCutoverPreparation(func(
				ctx context.Context,
				_ events.TenantDataRewriteReport,
				proceed func(context.Context) error,
			) error {
				return proceed(ctx)
			}),
			events.WithTenantDataAuditContinuity(func(
				context.Context,
				events.TenantDataAuditView,
			) (events.TenantDataAuditCheckpoint, error) {
				return events.TenantDataAuditCheckpoint{IdentityDigest: "unused"}, nil
			}),
		),
	)
	_, err = orch.ErasePrivacySubject(
		ctx,
		"22bdcaa0-7286-4c85-a318-81871274ebd6",
		"erased@example.test",
		"request",
	)
	if err == nil || !strings.Contains(err.Error(), "continuity signature verifier") {
		t.Fatalf("ErasePrivacySubject error = %v, want raw-log verifier preflight failure", err)
	}
}
