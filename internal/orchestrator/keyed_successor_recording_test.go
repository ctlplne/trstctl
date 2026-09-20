// SPDX-License-Identifier: BUSL-1.1
package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Real PostgreSQL and NATS when executed. These tests do not invoke a signer
// service, renewal dispatcher, broker endpoint, or browser.
func TestCertificateRecordingKeyedCrossPathConflict(t *testing.T) {
	for _, key := range []string{"issue:transition:cross-path", "renew:transition:cross-path", "agentcsr:17:2:0123456789abcdef"} {
		for _, successorFirst := range []bool{false, true} {
			name := key + "/plain-first"
			if successorFirst {
				name = key + "/successor-first"
			}
			t.Run(name, func(t *testing.T) {
				s, log, _ := recordingSpine(t)
				ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
				defer cancel()
				o := orchestrator.NewOrchestrator(log, s, nil)
				predecessor, _ := recordingCertificates(t)
				predecessor.IssuanceIdempotencyKey = ""
				old, err := o.RecordCertificate(ctx, tenantA, predecessor)
				if err != nil {
					t.Fatal(err)
				}
				issued, _ := recordingCertificates(t)
				issued.IssuanceIdempotencyKey = key
				record := func(in store.Certificate, successor bool) (store.Certificate, error) {
					if successor {
						return o.RecordSuccessorCertificate(ctx, tenantA, in, old.ID)
					}
					return o.RecordCertificate(ctx, tenantA, in)
				}
				first, err := record(issued, successorFirst)
				if err != nil {
					t.Fatal(err)
				}
				head, err := log.LastSequence(ctx)
				if err != nil {
					t.Fatal(err)
				}
				original, found, err := log.EventAtSequence(ctx, head)
				if err != nil || !found {
					t.Fatalf("missing recording envelope: %v", err)
				}
				var payload projections.CertificateRecorded
				if err := json.Unmarshal(original.Data, &payload); err != nil {
					t.Fatal(err)
				}
				if (payload.ReplacesID != nil) != successorFirst || (successorFirst && *payload.ReplacesID != old.ID) {
					t.Fatal("actual event has the wrong predecessor relation")
				}
				before := certificateOrderState(t, ctx, s, issued.Fingerprint)
				oldBefore := certificateOrderState(t, ctx, s, old.Fingerprint)
				// Both APIs must canonicalize public PEM before exact event comparison.
				retry := issued
				retry.CertificatePEM = append([]byte("\n"), issued.CertificatePEM...)
				replayed, err := record(retry, successorFirst)
				if err != nil || replayed.ID != first.ID {
					t.Fatalf("same normalized keyed result did not replay: %v", err)
				}
				if _, err := record(issued, !successorFirst); !errors.Is(err, store.ErrIdempotencyConflict) {
					t.Fatalf("changed predecessor presence: want store idempotency conflict, got %v", err)
				}
				if !bytes.Equal(before, certificateOrderState(t, ctx, s, issued.Fingerprint)) || !bytes.Equal(oldBefore, certificateOrderState(t, ctx, s, old.Fingerprint)) {
					t.Fatal("retry or conflicting API changed certificate state")
				}
				if after, err := log.LastSequence(ctx); err != nil || after != head {
					t.Fatalf("retry or conflicting API appended: %d %v", after, err)
				}
				exact, found, err := log.EventByID(ctx, original.ID)
				if err != nil || !found || exact.Sequence != original.Sequence || !exact.Time.Equal(original.Time) || !bytes.Equal(exact.Data, original.Data) {
					t.Fatalf("original recording changed: %v", err)
				}
			})
		}
	}
}

// These are recorder-level compatibility cases for real key families. Their
// HTTP authorization, signing, and external-CA producer identities are separate.
func TestCertificateRecordingKeyedMetadataConflict(t *testing.T) {
	for _, key := range []string{"broker-issue:request", "protocol-issue:request", "attested-issue:subject:request", "k8s-auto:run:discovered-fingerprint"} {
		t.Run(key, func(t *testing.T) {
			s, log, _ := recordingSpine(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			o := orchestrator.NewOrchestrator(log, s, nil)
			issued, _ := recordingCertificates(t)
			issued.IssuanceIdempotencyKey = key
			issued.IssuanceRequestBinding = "fixed-original-binding"
			if _, err := o.RecordCertificate(ctx, tenantA, issued); err != nil {
				t.Fatal(err)
			}
			head, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			before := certificateOrderState(t, ctx, s, issued.Fingerprint)
			changed := issued
			changed.DeploymentLocation = "different-observation"
			if _, err := o.RecordCertificate(ctx, tenantA, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("changed issuance metadata: want store idempotency conflict, got %v", err)
			}
			if _, err := o.RecordCertificate(ctx, tenantA, issued); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, certificateOrderState(t, ctx, s, issued.Fingerprint)) {
				t.Fatal("keyed retry or refused metadata changed the row")
			}
			if after, err := log.LastSequence(ctx); err != nil || after != head {
				t.Fatalf("keyed retry or refused metadata appended: %d %v", after, err)
			}
		})
	}
}

func TestCertificateRecordingUnkeyedObservationMetadata(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	observed, _ := recordingCertificates(t)
	observed.IssuanceIdempotencyKey = ""
	observed.Source = "import"
	observed.CertificateDER = nil
	observed.CertificatePEM = nil
	observed.KeyOrigin = ""
	first, err := o.RecordCertificate(ctx, tenantA, observed)
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observed.Source = "discovery:cloud:fixture"
	observed.DeploymentLocation = "observed-location"
	second, err := o.RecordCertificate(ctx, tenantA, observed)
	if err != nil || second.ID != first.ID || second.Source != observed.Source || second.DeploymentLocation != observed.DeploymentLocation {
		t.Fatalf("unkeyed observation no longer updates canonical inventory: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head+1 {
		t.Fatalf("unkeyed observation did not append its own event: %d %v", after, err)
	}
}
