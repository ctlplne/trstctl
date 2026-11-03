// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// CI-L37 (d′): every single-statement read an issuance makes is one round trip
// — its tenant transaction's BEGIN, setup, statement and COMMIT in one batch.
// Each used to be three: the setup, the statement, COMMIT.
func TestIssuanceReadsAreOneRoundTripEach(t *testing.T) {
	s, tracer := tracedStore(t)
	ctx := t.Context()
	const id = "6f1c2a7e-4b0d-4c55-9a3e-2d8f6b1e0c11"
	reads := []struct {
		name string
		read func() error
	}{
		{"RequireLiveTenantService", func() error { return s.RequireLiveTenantService(ctx, tenantA) }},
		{"GetIdentity", func() error { _, err := s.GetIdentity(ctx, tenantA, id); return err }},
		{"IdentityTerminalState", func() error { _, _, _, err := s.IdentityTerminalState(ctx, tenantA, id); return err }},
		{"ControlPlaneKeygenFor", func() error { _, _, err := s.ControlPlaneKeygenFor(ctx, tenantA); return err }},
		{"GetOwner", func() error { _, err := s.GetOwner(ctx, tenantA, id); return err }},
		{"IdentityApprovalTarget", func() error { _, _, err := s.IdentityApprovalTarget(ctx, tenantA, id); return err }},
		{"hasPrivacySubjectErasurePreparation", func() error {
			_, err := s.HasPrivacySubjectErasurePreparationForTest(ctx, tenantA)
			return err
		}},
		{"CRLDueForRegeneration", func() error { _, err := s.CRLDueForRegeneration(ctx, tenantA, id, time.Now(), time.Hour); return err }},
		{"LatestCRL", func() error { _, _, err := s.LatestCRL(ctx, tenantA, id); return err }},
		{"GetCertificateByFingerprint", func() error { _, err := s.GetCertificateByFingerprint(ctx, tenantA, "ab"); return err }},
		{"GetIssuer", func() error { _, err := s.GetIssuer(ctx, tenantA, id); return err }},
		{"CompromisedSubjectKey", func() error { _, _, err := s.CompromisedSubjectKey(ctx, tenantA, "cd"); return err }},
		{"IdentityInitialIssuance", func() error { _, _, err := s.IdentityInitialIssuance(ctx, tenantA, id); return err }},
		{"IdentityTransitions", func() error { _, err := s.IdentityTransitions(ctx, tenantA, id); return err }},
	}
	// A read of nothing is still a whole tenant transaction; its answer is
	// absence (or, for admission, a refusal of the unregistered tenant).
	answered := func(err error) bool {
		return err == nil || errors.Is(err, pgx.ErrNoRows) || store.IsNotFound(err) || errors.Is(err, tenancy.ErrServiceUnavailable)
	}
	for _, r := range reads {
		_ = r.read() // the session's first use prepares the batch's statements
		tracer.take()
		if err := r.read(); !answered(err) {
			t.Fatalf("%s: %v", r.name, err)
		}
		if sent := tracer.take(); len(sent) != 1 || sent[0] != "[batch]" {
			t.Errorf("%s sent %d messages %q; want one batch", r.name, len(sent), sent)
		}
	}
	noSessionInTransaction(t, s)
}
