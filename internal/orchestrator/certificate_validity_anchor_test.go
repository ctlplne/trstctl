// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func anchoredRecordingCertificate(t *testing.T) store.Certificate {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	ca, err := crypto.SelfSignedCACert(key, "anchor recording CA", 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "anchor.example.test", DNSNames: []string{"anchor.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := crypto.SignLeafFromCSRWithValidity(ca, key, csr, 47*24*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	return store.Certificate{Source: "issued", Subject: info.Subject, SANs: info.DNSNames,
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		ValidityAnchor: &issued.ValidityAnchor, CertificateDER: issued.DER,
		CertificatePEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.DER}),
		IssuanceIdempotencyKey: "issue:transition:validity-anchor"}
}

func TestCertificateValidityAnchorSurvivesReplayAndColdSnapshot(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in := anchoredRecordingCertificate(t)
	original, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	observation := in
	observation.Source, observation.IssuanceIdempotencyKey = "import", ""
	observation.CertificateDER, observation.CertificatePEM, observation.ValidityAnchor = nil, nil, nil
	if _, err := o.RecordCertificate(ctx, tenantA, observation); err != nil {
		t.Fatal(err)
	}
	assertAnchor := func(stage string) {
		t.Helper()
		got, err := s.GetCertificate(ctx, tenantA, original.ID)
		if err != nil || got.ValidityAnchor == nil || !got.ValidityAnchor.Equal(*in.ValidityAnchor) || got.Source != "import" {
			t.Fatalf("%s lost immutable anchor or current provenance: %+v %v", stage, got, err)
		}
		if _, err := s.GetCertificate(ctx, tenantB, original.ID); err == nil {
			t.Fatal("neighbor tenant read the anchored certificate")
		}
	}
	assertAnchor("rediscovery")
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if n, err := p.Snapshot(ctx); err != nil || n == 0 {
		t.Fatalf("snapshot absent: %d %v", n, err)
	}
	// Cold source fixture only: remove the row and checkpoint in this disposable
	// database, then require the ordinary snapshot restore to reconstruct it.
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := s.SetTenantGUCTx(ctx, tx, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetProjectionCheckpointTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if restored, err := projections.New(s).RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("cold snapshot restore did not run: %t %v", restored, err)
	}
	assertAnchor("cold snapshot")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertAnchor("event-only rebuild")
	if repeated, err := o.RecordCertificate(ctx, tenantA, in); err != nil || repeated.ID != original.ID {
		t.Fatalf("exact anchored retry changed identity: %v", err)
	}
}

func TestCertificateValidityAnchorConflictsBeforeAppend(t *testing.T) {
	s, log, _ := recordingSpine(t)
	o := orchestrator.NewOrchestrator(log, s, nil)
	in := anchoredRecordingCertificate(t)
	if _, err := o.RecordCertificate(t.Context(), tenantA, in); err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"anchor", "signed expiry", "missing bounds", "submicrosecond"} {
		t.Run(change, func(t *testing.T) {
			other := in
			other.IssuanceIdempotencyKey = ""
			switch change {
			case "anchor":
				a := in.ValidityAnchor.Add(time.Second)
				other.ValidityAnchor = &a
			case "signed expiry":
				end := in.NotAfter.Add(time.Hour)
				other.NotAfter, other.ValidityAnchor = &end, nil
			case "missing bounds":
				other.NotBefore = nil
			case "submicrosecond":
				a := in.ValidityAnchor.Add(time.Nanosecond)
				other.ValidityAnchor = &a
			}
			if _, err := o.RecordCertificate(t.Context(), tenantA, other); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("changed anchor accepted or wrong error: %v", err)
			}
			if after, err := log.LastSequence(t.Context()); err != nil || after != before {
				t.Fatalf("rejected anchor poisoned source history: %d -> %d: %v", before, after, err)
			}
		})
	}
}

func TestCertificateValidityAnchorBindsRenewedPublicMaterial(t *testing.T) {
	s, log, _ := recordingSpine(t)
	o := orchestrator.NewOrchestrator(log, s, nil)
	replacement := anchoredRecordingCertificate(t)
	for _, material := range []string{"DER", "DER and PEM", "PEM only at projection boundary"} {
		t.Run(material, func(t *testing.T) {
			// Independent fingerprints prevent an accepted attack in one
			// subtest from masking a later one with already-corrupted state.
			in := anchoredRecordingCertificate(t)
			in.IssuanceIdempotencyKey = "renew:validity-anchor"
			if _, err := o.RecordCertificate(t.Context(), tenantA, in); err != nil {
				t.Fatal(err)
			}
			before, err := log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			observation := in
			observation.Source, observation.IssuanceIdempotencyKey = "import", ""
			observation.ValidityAnchor, observation.NotBefore, observation.NotAfter = nil, nil, nil
			observation.CertificateDER, observation.CertificatePEM = replacement.CertificateDER, nil
			if material == "DER and PEM" {
				observation.CertificatePEM = replacement.CertificatePEM
			}
			if material == "PEM only at projection boundary" {
				observation.CertificateDER, observation.CertificatePEM = nil, replacement.CertificatePEM
				// The command parser already rejects PEM without DER. The shared
				// store boundary must also bind a replayed PEM-only observation.
				err = s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
					return s.ValidateCertificateIssuanceBindingTx(t.Context(), tx, tenantA, observation)
				})
			} else {
				_, err = o.RecordCertificate(t.Context(), tenantA, observation)
			}
			if !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("replacement public material accepted or wrong error: %v", err)
			}
			if after, err := log.LastSequence(t.Context()); err != nil || after != before {
				t.Fatalf("rejected public material changed source history: %d -> %d: %v", before, after, err)
			}
			observation = in
			observation.Source, observation.IssuanceIdempotencyKey, observation.ValidityAnchor = "import", "", nil
			if _, err := o.RecordCertificate(t.Context(), tenantA, observation); err != nil {
				t.Fatalf("same public leaf observation refused: %v", err)
			}
		})
	}
}
