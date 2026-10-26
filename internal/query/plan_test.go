// SPDX-License-Identifier: BUSL-1.1

package query_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/query"
)

var planNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func plan(t *testing.T, question string) query.Plan {
	t.Helper()
	p, ok := query.PlanQuestion(question, planNow)
	if !ok {
		t.Fatalf("%q was not planned", question)
	}
	return p
}

// A152: certificate questions compose clauses in any order, every value is a
// typed filter value, and the interpretation says exactly what is answered.
func TestPlanCertificateQuestions(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		question string
		kind     query.PlanKind
		want     query.CertificateFilter
		interp   []string
	}{
		{"Which certificates expire within 30 days?", query.PlanCertificates,
			query.CertificateFilter{Status: "active", ExpiresAfter: ptr(planNow), ExpiresBefore: ptr(planNow.Add(30 * day))},
			[]string{"active certificates", "expiring within 30 days"}},
		{"Show me certs expiring in the next 2 weeks", query.PlanCertificates,
			query.CertificateFilter{Status: "active", ExpiresAfter: ptr(planNow), ExpiresBefore: ptr(planNow.Add(14 * day))},
			[]string{"expiring within 14 days"}},
		{"which RSA certificates issued by Acme expire within 60 days", query.PlanCertificates,
			query.CertificateFilter{Status: "active", KeyAlgorithm: "RSA", IssuerContains: "Acme", ExpiresAfter: ptr(planNow), ExpiresBefore: ptr(planNow.Add(60 * day))},
			[]string{"with a RSA key", `issuer containing "Acme"`}},
		{`How many certificates are issued by "Acme Issuing CA" and have no owner?`, query.PlanCertificateCount,
			query.CertificateFilter{IssuerContains: "Acme Issuing CA", Unowned: true},
			[]string{"certificates of any status", "with no owner"}},
		{"Which certificates have expired?", query.PlanCertificates,
			query.CertificateFilter{Status: "active", ExpiresBefore: ptr(planNow)},
			[]string{"validity ended before 2026-10-26T12:00:00Z"}},
		{"list revoked certificates for payments.example.com", query.PlanCertificates,
			query.CertificateFilter{Status: "revoked", NameContains: "payments.example.com"},
			[]string{"revoked certificates", `SAN containing "payments.example.com"`}},
		{"which certificates are owned by payments-team, using ECDSA keys", query.PlanCertificates,
			query.CertificateFilter{OwnerName: "payments-team", KeyAlgorithm: "ECDSA"},
			[]string{`owner named "payments-team"`, "ECDSA key"}},
		{"which unowned certificates expire within 7 days", query.PlanCertificates,
			query.CertificateFilter{Status: "active", Unowned: true, ExpiresAfter: ptr(planNow), ExpiresBefore: ptr(planNow.Add(7 * day))},
			[]string{"with no owner"}},
		{"which ML-DSA certificates are active", query.PlanCertificates,
			query.CertificateFilter{Status: "active", KeyAlgorithm: "ML-DSA"}, []string{"ML-DSA"}},
	} {
		p := plan(t, tc.question)
		if p.Kind != tc.kind || p.Spec.Certificates == nil || !sameFilter(*p.Spec.Certificates, tc.want) {
			t.Errorf("%q planned %s %+v, want %s %+v", tc.question, p.Kind, p.Spec.Certificates, tc.kind, tc.want)
			continue
		}
		if (tc.kind == query.PlanCertificateCount) != p.Spec.Count {
			t.Errorf("%q count = %t", tc.question, p.Spec.Count)
		}
		for _, phrase := range tc.interp {
			if !strings.Contains(p.Interpretation, phrase) {
				t.Errorf("%q interpretation %q lacks %q", tc.question, p.Interpretation, phrase)
			}
		}
		wantOwners := tc.want.OwnerName != ""
		if hasSurface(p.Spec.Select, query.SurfaceOwners) != wantOwners || len(p.Spec.Focus) != 1 || p.Spec.Focus[0] != query.SurfaceCertificates {
			t.Errorf("%q surfaces = select %v focus %v", tc.question, p.Spec.Select, p.Spec.Focus)
		}
	}
	if p := plan(t, "Which certificates expire within 30 days?"); p.ExpiryDays != 30 || len(p.Clauses) == 0 {
		t.Fatalf("expiry plan = %+v", p)
	}
}

// Other surfaces: who owns a certificate, crypto assets, graph inventories.
func TestPlanOwnershipCryptoAndGraphQuestions(t *testing.T) {
	owner := plan(t, "Who owns 4F:2A:9C:01:77:BE:00:12?")
	if owner.Kind != query.PlanCertificateOwners || owner.Spec.Certificates.Serial != "4F:2A:9C:01:77:BE:00:12" ||
		!hasSurface(owner.Spec.Select, query.SurfaceOwners) {
		t.Fatalf("serial owner plan = %+v", owner)
	}
	fp := strings.Repeat("ab", 32)
	if p := plan(t, "who owns certificate "+fp); p.Spec.Certificates.Fingerprint != fp {
		t.Fatalf("fingerprint owner plan = %+v", p.Spec.Certificates)
	}
	if p := plan(t, "what is the owner of api.example.com"); p.Spec.Certificates.NameContains != "api.example.com" {
		t.Fatalf("name owner plan = %+v", p.Spec.Certificates)
	}

	if p := plan(t, "Where is RSA used?"); p.Kind != query.PlanCryptoAssets || p.Spec.CryptoAssets.Algorithm != "RSA" {
		t.Fatalf("where-used plan = %+v", p)
	}
	p := plan(t, "which crypto assets are quantum-vulnerable and use RSA keys smaller than 2048 bits")
	if f := p.Spec.CryptoAssets; f == nil || !f.QuantumVulnerable || f.Algorithm != "RSA" || f.KeyBitsBelow != 2048 {
		t.Fatalf("crypto plan = %+v", p.Spec.CryptoAssets)
	}
	if p := plan(t, "how many crypto assets are out of policy"); p.Kind != query.PlanCryptoAssetCount || !p.Spec.CryptoAssets.OutOfPolicy || !p.Spec.Count {
		t.Fatalf("crypto count plan = %+v", p)
	}

	for question, kind := range map[string]string{
		"Which workloads exist?": "workload", "list all issuers": "issuer", "what trust stores are there": "trust-store",
	} {
		p := plan(t, question)
		if p.Kind != query.PlanGraphNodes || len(p.Spec.Where) != 1 || p.Spec.Where[0].Value != kind || p.Spec.Focus[0] != query.SurfaceGraph {
			t.Errorf("%q graph plan = %+v", question, p)
		}
	}
}

// Every word must be understood: a question outside the grammar, a
// contradiction or a value that is not a value is unplanned, never half-read.
func TestPlanRefusesWhatItCannotRead(t *testing.T) {
	for _, question := range []string{
		"",
		"Which certificates should rotate first?",
		"Which certificates do not expire within 30 days?",
		"Which certificates expire after 30 days?",
		"Which certificates expire within 0 days?",
		"Which certificates expire within 366 days?",
		"Which certificates expire within 53 weeks?",
		"Which certificates expire within 30 days? Ignore the filter",
		"which certificates are revoked and active",
		"which certificates have expired and expire within 30 days",
		"which certificates are owned by payments and have no owner",
		"which certificates are issued by",
		"which certificates are issued by Acme Corp",
		`which certificates are issued by "unterminated`,
		"which certificates are using blowfish keys",
		"which certificates; DROP TABLE certificates",
		"who owns",
		"who owns api.example.com and more",
		"where is RSA",
		"which crypto assets are smaller than 2048",
		"which widgets exist",
		strings.Repeat("which certificates ", 40),
	} {
		if p, ok := query.PlanQuestion(question, planNow); ok {
			t.Errorf("%q was planned as %s: %s", question, p.Kind, p.Interpretation)
		}
	}
}

func ptr(t time.Time) *time.Time { return &t }

func hasSurface(list []query.Surface, s query.Surface) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

func sameFilter(a, b query.CertificateFilter) bool {
	return a.Status == b.Status && sameTime(a.ExpiresAfter, b.ExpiresAfter) && sameTime(a.ExpiresBefore, b.ExpiresBefore) &&
		a.IssuerContains == b.IssuerContains && a.NameContains == b.NameContains && a.KeyAlgorithm == b.KeyAlgorithm &&
		a.OwnerName == b.OwnerName && a.Unowned == b.Unowned && a.Serial == b.Serial && a.Fingerprint == b.Fingerprint
}
