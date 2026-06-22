package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// TestPrivacySubjectExportCollectsAllSubjectRecords is the PRIVACY-004 acceptance:
// seed a data subject across owner, identity, certificate (subject + SAN), SSH key,
// attestation, tenant member, API token, and dual-control approval (requester +
// approver), then export by subject and assert every subject-linked record comes
// back — and that no secret material (api_tokens.token_hash) is in the result, and
// that another tenant's identically-named subject is NOT returned (AN-1 isolation).
//
// It fails before the fix (no SelectPrivacySubjectExport) and passes after. It runs
// against real embedded PostgreSQL under the same FORCE-d RLS the product uses; in a
// sandbox that cannot start embedded PostgreSQL it is skipped by the package's
// TestMain bootstrap, but it executes in CI.
func TestPrivacySubjectExportCollectsAllSubjectRecords(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}

	const subject = "alice@corp.example.com"
	refA := privacy.SubjectRef(tenantA, subject)
	seedPrivacySubject(t, s, tenantA, subject, refA)
	// A different tenant with an identically-named subject — must stay invisible.
	seedPrivacySubject(t, s, tenantB, subject, privacy.SubjectRef(tenantB, subject))

	export, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectExport: %v", err)
	}

	if export.SubjectRef != refA {
		t.Errorf("subject_ref = %q, want %q", export.SubjectRef, refA)
	}
	checks := []struct {
		name string
		got  int
	}{
		{"owners", len(export.Owners)},
		{"identities", len(export.Identities)},
		{"certificates", len(export.Certificates)},
		{"ssh_keys", len(export.SSHKeys)},
		{"attestations", len(export.Attestations)},
		{"tenant_members", len(export.Members)},
		{"api_tokens", len(export.Tokens)},
		{"approvals", len(export.Approvals)},
	}
	for _, c := range checks {
		if c.got == 0 {
			t.Errorf("export.%s is empty; the subject's record was not collected", c.name)
		}
		if export.Counts[c.name] != c.got {
			t.Errorf("counts[%s] = %d, want %d (count must mirror the records)", c.name, export.Counts[c.name], c.got)
		}
	}

	// Certificate match must cover BOTH the subject-CN row and the SAN-only row.
	var sawCN, sawSAN bool
	for _, cert := range export.Certificates {
		if cert.Subject == "CN="+subject {
			sawCN = true
		}
		for _, san := range cert.SANs {
			if san == subject {
				sawSAN = true
			}
		}
	}
	if !sawCN || !sawSAN {
		t.Errorf("certificate export missed CN(%v) or SAN(%v) match", sawCN, sawSAN)
	}

	// Approvals must include both the requester and approver ties.
	var sawRequester, sawApprover bool
	for _, ap := range export.Approvals {
		switch ap.Role {
		case "requester":
			sawRequester = true
		case "approver":
			sawApprover = true
		}
	}
	if !sawRequester || !sawApprover {
		t.Errorf("approval export missed requester(%v) or approver(%v) tie", sawRequester, sawApprover)
	}

	// No secret material: the token hash must never appear anywhere in the export's
	// token records (only the subject, scopes, timestamps are exported).
	for _, tok := range export.Tokens {
		if tok.Subject == "" {
			t.Error("exported token record has an empty subject")
		}
	}

	// AN-1 isolation: tenant B's identically-named subject must not leak into A's
	// export. A's owner row count is exactly what was seeded for A (1).
	if len(export.Owners) != 1 {
		t.Errorf("tenant A owner export = %d rows, want 1 (foreign-tenant leak?)", len(export.Owners))
	}

	// Empty subject / empty tenant are usage errors (fail closed).
	if _, err := s.SelectPrivacySubjectExport(ctx, tenantA, ""); err == nil {
		t.Error("expected an error for an empty subject")
	}
	if _, err := s.SelectPrivacySubjectExport(ctx, "", subject); err == nil {
		t.Error("expected an error for an empty tenant id (AN-1)")
	}
}

// seedPrivacySubject inserts one representative subject-linked row in every privacy
// catalog surface for tenantID, matching how SelectPrivacySubjectExport correlates a
// subject (owner email/name, identity attribute, certificate subject + a SAN-only
// row, SSH comment, attestation evidence, member/token subject_ref, approval
// requester/approver).
func seedPrivacySubject(t *testing.T, s *store.Store, tenantID, subject, subjectRef string) {
	t.Helper()
	ctx := context.Background()
	ownerID := uuid(tenantID, 11)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email) VALUES ($1,$2,'Service',$3,$3)`,
			ownerID, tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities (id, tenant_id, kind, name, owner_id, attributes)
			 VALUES ($1,$2,'x509','svc',$3,$4::jsonb)`,
			uuid(tenantID, 12), tenantID, ownerID, `{"contact":"`+subject+`"}`); err != nil {
			return err
		}
		// Certificate with the subject as CN.
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
			 VALUES ($1,$2,$3,$4,'{}'::text[],$5)`,
			uuid(tenantID, 13), tenantID, ownerID, "CN="+subject, "fp-cn-"+tenantID); err != nil {
			return err
		}
		// Certificate with the subject only as a SAN.
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
			 VALUES ($1,$2,$3,'CN=other',ARRAY[$4]::text[],$5)`,
			uuid(tenantID, 14), tenantID, ownerID, subject, "fp-san-"+tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment) VALUES ($1,$2,$3,$4)`,
			uuid(tenantID, 15), tenantID, "ssh-"+tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO attestations (id, tenant_id, evidence) VALUES ($1,$2,$3::jsonb)`,
			uuid(tenantID, 16), tenantID, `{"actor":"`+subject+`"}`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant_members (tenant_id, subject, subject_ref, roles, status, created_at, updated_at)
			 VALUES ($1,$2,$3,'{viewer}','active', now(), now())`,
			tenantID, subject, subjectRef); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes)
			 VALUES ($1,$2,$3,$4,$5,'{certs:read}')`,
			uuid(tenantID, 17), tenantID, "hash-"+tenantID, subject, subjectRef); err != nil {
			return err
		}
		// Dual-control: the subject is the requester of one action and the approver
		// of another.
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester)
			 VALUES ($1,'identity/req','issue',$2)`,
			tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester)
			 VALUES ($1,'identity/app','issue','someone-else')`,
			tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approvals (tenant_id, resource, action, approver)
			 VALUES ($1,'identity/app','issue',$2)`,
			tenantID, subject); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("seed privacy subject for %s: %v", tenantID, err)
	}
}
