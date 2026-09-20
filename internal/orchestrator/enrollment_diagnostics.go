// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var enrollmentDiagnosticVerificationNamespace = uuid.MustParse("3f3d561c-e05e-41ea-aea1-df8a9b8765ad")

// RecordEnrollmentDiagnosis appends and projects one protocol refusal under the
// request's tenant. The immutable event is authoritative; the bounded RLS read
// model is only its operator-facing projection.
func (o *Orchestrator) RecordEnrollmentDiagnosis(ctx context.Context, tenantID string, diagnostic enrollmentdiag.Diagnosis) error {
	if o == nil || o.log == nil || o.store == nil {
		return fmt.Errorf("orchestrator: enrollment diagnostics are not configured")
	}
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("orchestrator: enrollment diagnostic tenant id is required (AN-1)")
	}
	// The enrollment server knows what it refused, but not where the requested
	// certificate belongs. Resolve only an explicit identity-to-target binding;
	// never guess :443 from a SAN or probe the enrollment server itself.
	if diagnostic.VerificationKind == "" {
		route, err := o.store.ResolveEnrollmentDiagnosticVerificationRoute(ctx, tenantID, diagnostic.IdentityRef)
		if err == nil {
			diagnostic.VerificationKind = enrollmentdiag.VerificationEndpoint
			diagnostic.VerificationAddress = route.Address
			diagnostic.VerificationServerName = route.ServerName
		} else if !errors.Is(err, store.ErrEnrollmentDiagnosticNoVerificationRoute) {
			return err
		}
	}
	diagnosticID := "diagnostic:" + crypto.SHA256Hex([]byte(strings.Join([]string{
		tenantID, string(diagnostic.Protocol), diagnostic.OperationRef,
		diagnostic.IdentityRef, diagnostic.EndpointRef,
	}, "\x00")))
	payload, err := json.Marshal(projections.EnrollmentDiagnosticObserved{
		DiagnosticID: diagnosticID, Protocol: string(diagnostic.Protocol), Step: string(diagnostic.Step), Cause: string(diagnostic.Cause),
		Summary: diagnostic.Summary, Remediation: diagnostic.Remediation,
		OperationRef: diagnostic.OperationRef, IdentityRef: diagnostic.IdentityRef, EndpointRef: diagnostic.EndpointRef,
		VerificationKind: string(diagnostic.VerificationKind), VerificationAddress: diagnostic.VerificationAddress,
		VerificationServerName: diagnostic.VerificationServerName,
	})
	if err != nil {
		return err
	}
	_, err = o.emitVersioned(ctx, projections.EventEnrollmentDiagnosticObserved, tenantID, projections.EnrollmentDiagnosticEventSchemaVersion, payload)
	return err
}

// QueueEnrollmentDiagnosticVerification appends the action receipt, projects
// its link, and queues the exact D2 relay intent in one tenant transaction.
func (o *Orchestrator) QueueEnrollmentDiagnosticVerification(
	ctx context.Context,
	tenantID, diagnosticID, idempotencyKey string,
) (events.Event, projections.EnrollmentDiagnosticVerificationQueued, bool, error) {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false,
			fmt.Errorf("orchestrator: enrollment diagnostic verification is not configured")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(diagnosticID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false,
			fmt.Errorf("orchestrator: tenant, diagnostic, and idempotency key are required")
	}
	target, err := o.store.GetEnrollmentDiagnosticVerificationTarget(ctx, tenantID, diagnosticID)
	if err != nil {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false, err
	}
	if target.VerificationKind != string(enrollmentdiag.VerificationEndpoint) || target.VerificationAddress == "" ||
		target.ExpectedFingerprint == "" {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false,
			fmt.Errorf("orchestrator: enrollment diagnostic has no prove-fixed endpoint")
	}
	seed := []byte(tenantID + "\x00" + diagnosticID + "\x00" + idempotencyKey)
	eventID := uuid.NewSHA1(enrollmentDiagnosticVerificationNamespace, append([]byte("event\x00"), seed...)).String()
	endpointID := uuid.NewSHA1(enrollmentDiagnosticVerificationNamespace, append([]byte("endpoint\x00"), seed...)).String()
	payload := projections.EnrollmentDiagnosticVerificationQueued{
		DiagnosticID: diagnosticID, VerificationEndpointID: endpointID,
		Address: target.VerificationAddress, ServerName: target.VerificationServerName,
		ExpectedFingerprint: target.ExpectedFingerprint,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false, err
	}
	entry, err := enrollmentDiagnosticVerificationOutboxEntry(tenantID, eventID, payload)
	if err != nil {
		return events.Event{}, projections.EnrollmentDiagnosticVerificationQueued{}, false, err
	}
	var event events.Event
	inserted := false
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		event, err = o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventEnrollmentDiagnosticVerificationQueued,
			TenantID: tenantID, Data: raw,
		})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventEnrollmentDiagnosticVerificationQueued ||
			event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: canonical enrollment diagnostic verification differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
	return event, payload, inserted, err
}

func enrollmentDiagnosticVerificationOutboxEntry(
	tenantID, eventID string,
	payload projections.EnrollmentDiagnosticVerificationQueued,
) (Entry, error) {
	if tenantID == "" || eventID == "" || payload.DiagnosticID == "" ||
		payload.VerificationEndpointID == "" || payload.Address == "" || payload.ExpectedFingerprint == "" {
		return Entry{}, fmt.Errorf("orchestrator: invalid enrollment diagnostic verification intent")
	}
	intent, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{{
		EndpointID: payload.VerificationEndpointID, Address: payload.Address,
		ServerName: payload.ServerName, Fingerprint: payload.ExpectedFingerprint,
	}}})
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: tenantID, Destination: relay.KindEndpointVerify,
		IdempotencyKey: eventID, Payload: intent, RequiredAgentRole: "network",
	}, nil
}
