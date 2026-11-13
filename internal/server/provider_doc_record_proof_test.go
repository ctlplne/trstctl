// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// docProofRecord is one record a documentation stand-in holds.
type docProofRecord struct {
	ID         string
	Org        string
	Inventory  string
	Count      float64
	NextExpiry string
	Link       string
}

// docProofCase is one documentation connector under the shared served
// proof: its target (ID set, endpoint the stand-in, console URL
// https://trstctl.msp.example), the two organizations, and the stand-in's
// records.
type docProofCase struct {
	target     config.ProviderBillingTarget
	secret     string
	orgA, orgB string
	records    func() []docProofRecord
	remove     func(id string)
	failWrites func(n int)
	writes     func() int
}

// runDocRecordProof is the MSP-14 Done-when for one documentation
// connector, served against its stand-in: each customer's inventory in one
// record under its own organization only, with the count, next expiry and
// link; a lost answer to the first write makes no second record; an
// unchanged inventory writes nothing; a renewal updates the record in place;
// a record deleted there is written again; the credential never reaches the
// debug log or the outbox.
func runDocRecordProof(t *testing.T, c docProofCase) {
	t.Helper()
	logs := captureDebugLog(t)
	ctx := context.Background()
	target := c.target
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
	})
	const customerB = "4f5e6d7c-8b9a-4c0d-9e1f-2a3b4c5d6e7f"
	registerServedTenant(t, h, "Alpha Corp")
	registerServedTenantID(t, h, customerB, "Beta Corp")
	for tenant, org := range map[string]string{h.tenant: c.orgA, customerB: c.orgB} {
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, $2, $3, 'operator@example.test', now())`, tenant, target.ID, org); err != nil {
			t.Fatal(err)
		}
	}
	soon := time.Now().UTC().Add(20 * 24 * time.Hour).Truncate(time.Second)
	later := time.Now().UTC().Add(200 * 24 * time.Hour).Truncate(time.Second)
	soonID := addDocCertificate(t, h, h.tenant, "www.alpha.example", soon)
	addDocCertificate(t, h, h.tenant, "api.alpha.example", later)
	addDocCertificate(t, h, customerB, "portal.beta.example", soon)

	c.failWrites(1)
	bucket := time.Now().UTC().Truncate(10 * time.Minute)
	docSync(t, h, h.tenant, target.ID, bucket)
	docSync(t, h, customerB, target.ID, bucket)
	byOrg := map[string]docProofRecord{}
	for _, r := range c.records() {
		if _, dup := byOrg[r.Org]; dup {
			t.Fatalf("two records under organization %s: %+v", r.Org, c.records())
		}
		byOrg[r.Org] = r
	}
	a, b := byOrg[c.orgA], byOrg[c.orgB]
	if len(byOrg) != 2 || !strings.Contains(a.Inventory, "www.alpha.example") || !strings.Contains(a.Inventory, "api.alpha.example") ||
		strings.Contains(a.Inventory, "beta") || a.Count != 2 || a.NextExpiry != soon.Format("2006-01-02") ||
		a.Link != "https://trstctl.msp.example/certificates" || !strings.Contains(a.Inventory, "Alpha Corp") {
		t.Fatalf("A's record = %+v (all: %+v)", a, c.records())
	}
	if !strings.Contains(b.Inventory, "portal.beta.example") || strings.Contains(b.Inventory, "alpha") || b.Count != 1 {
		t.Fatalf("B's record = %+v", b)
	}
	if rec, found, err := h.store.DocRecordFor(ctx, h.tenant, target.ID); err != nil || !found || rec.Status != store.DocRecordSynced ||
		rec.OrgID != c.orgA || rec.RecordID != a.ID || rec.Certificates != 2 {
		t.Fatalf("A's recorded sync = %+v %v %v", rec, found, err)
	}

	writes := c.writes()
	docSync(t, h, h.tenant, target.ID, bucket.Add(10*time.Minute))
	if after := c.writes(); after != writes {
		t.Fatalf("an unchanged inventory wrote %d times", after-writes)
	}

	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'superseded' WHERE id = $1`, soonID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	renewed := time.Now().UTC().Add(110 * 24 * time.Hour).Truncate(time.Second)
	addDocCertificate(t, h, h.tenant, "www.alpha.example", renewed)
	docSync(t, h, h.tenant, target.ID, bucket.Add(20*time.Minute))
	for _, r := range c.records() {
		if r.Org == c.orgA && (r.ID != a.ID || r.NextExpiry != renewed.Format("2006-01-02")) {
			t.Fatalf("A's record after the renewal = %+v, want record %s with the new expiry", r, a.ID)
		}
	}

	c.remove(a.ID)
	addDocCertificate(t, h, h.tenant, "mail.alpha.example", later)
	docSync(t, h, h.tenant, target.ID, bucket.Add(30*time.Minute))
	recreated := false
	for _, r := range c.records() {
		recreated = recreated || (r.Org == c.orgA && r.ID != a.ID && strings.Contains(r.Inventory, "mail.alpha.example"))
	}
	if !recreated {
		t.Fatalf("a deleted record was not written again: %+v", c.records())
	}

	if strings.Contains(logs.String(), c.secret) {
		t.Fatal("the debug log carries the credential")
	}
	var leaked int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE position($1 in payload::text) > 0 OR position($1 in coalesce(last_error, '')) > 0`,
		c.secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the outbox carries the credential (%d, %v)", leaked, err)
	}
}
