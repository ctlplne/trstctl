// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/docsys/docsystest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// addDocCertificate inventories one active certificate for the customer.
func addDocCertificate(t *testing.T, h *servedHarness, tenant, subject string, notAfter time.Time) string {
	t.Helper()
	id := uuid.NewString()
	if err := h.store.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO certificates (id, tenant_id, subject, sans, issuer, serial, fingerprint, not_after,
			deployment_location, source, status) VALUES ($1, $2, $3, $4, 'CN=Issuing CA', $5, $6, $7, 'web01:443', 'import', 'active')`,
			id, tenant, "CN="+subject, []string{subject}, strings.ReplaceAll(id, "-", "")[:16], strings.ReplaceAll(id, "-", ""), notAfter)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func docSync(t *testing.T, h *servedHarness, tenant, target string, bucket time.Time) {
	t.Helper()
	if queued, err := h.srv.orch.QueueDocRecord(context.Background(), tenant, target, bucket); err != nil || !queued {
		t.Fatalf("queue documentation sync = %v %v", queued, err)
	}
	servedRMMDrain(t, h, tenant, orchestrator.DestinationDocRecord, "the documentation sync")
}

// MSP-14 Done-when (served, IT Glue stand-in written from the public API
// reference): each customer's certificate inventory and expiry dates are
// written to one flexible asset under its own IT Glue organization (B's
// certificates never reach A's record, nor A's B's), with the count, the
// next expiry and the link back to trstctl; an unchanged inventory writes
// nothing; a renewal (a new certificate replacing the soonest) updates the
// record in place; a record deleted in IT Glue is written again; a lost
// answer to the create reuses the record it made instead of making another;
// and the API key never reaches the debug log or the outbox.
func TestServedITGlueKeepsEachCustomersCertificateRecordMSP14(t *testing.T) {
	logs := captureDebugLog(t)
	ctx := context.Background()
	const key = "itglue-served-api-key" // #nosec G101 -- a test-only value (CWE-798)
	itg := docsystest.NewITGlue(key)
	t.Cleanup(itg.Close)
	itg.AddOrganization(11)
	itg.AddOrganization(22)
	itg.AddType(33, "name", "certificates", "next-expiry", "certificate-count", "trstctl-link")
	target := config.ProviderBillingTarget{ID: "itglue", Type: "itglue", Endpoint: itg.URL(), AllowInsecureLoopback: true,
		ITGlue: &config.ITGlueTarget{APIKeyRef: writeServedCredentialFile(t, "itglue-key", key), FlexibleAssetTypeID: 33,
			Traits:     config.ITGlueTraits{Title: "name", Inventory: "certificates", NextExpiry: "next-expiry", Count: "certificate-count", Link: "trstctl-link"},
			ConsoleURL: "https://trstctl.msp.example"}}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
	})
	const customerB = "8d1e2f3a-4b5c-4d6e-9f7a-0b1c2d3e4f5a"
	registerServedTenant(t, h, "Alpha Corp")
	registerServedTenantID(t, h, customerB, "Beta Corp")
	for tenant, org := range map[string]string{h.tenant: "11", customerB: "22"} {
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'itglue', $2, 'operator@example.test', now())`, tenant, org); err != nil {
			t.Fatal(err)
		}
	}
	soon := time.Now().UTC().Add(20 * 24 * time.Hour).Truncate(time.Second)
	later := time.Now().UTC().Add(200 * 24 * time.Hour).Truncate(time.Second)
	soonID := addDocCertificate(t, h, h.tenant, "www.alpha.example", soon)
	addDocCertificate(t, h, h.tenant, "api.alpha.example", later)
	addDocCertificate(t, h, customerB, "portal.beta.example", soon)

	// A lost answer to A's first create: the retry finds the asset it made.
	itg.FailWritesAfterApplying(1)
	bucket := time.Now().UTC().Truncate(10 * time.Minute)
	docSync(t, h, h.tenant, "itglue", bucket)
	docSync(t, h, customerB, "itglue", bucket)
	assets := itg.Assets()
	if len(assets) != 2 {
		t.Fatalf("assets = %+v, want one per customer", assets)
	}
	byOrg := map[int64]docsystest.ITGlueAsset{}
	for _, a := range assets {
		byOrg[a.OrgID] = a
	}
	a, b := byOrg[11], byOrg[22]
	aHTML, _ := a.Traits["certificates"].(string)
	bHTML, _ := b.Traits["certificates"].(string)
	if !strings.Contains(aHTML, "www.alpha.example") || !strings.Contains(aHTML, "api.alpha.example") || strings.Contains(aHTML, "beta") ||
		a.Traits["certificate-count"] != float64(2) || a.Traits["next-expiry"] != soon.Format("2006-01-02") ||
		a.Traits["trstctl-link"] != "https://trstctl.msp.example/certificates" || !strings.Contains(aHTML, "Alpha Corp") {
		t.Fatalf("A's record = %+v", a)
	}
	if !strings.Contains(bHTML, "portal.beta.example") || strings.Contains(bHTML, "alpha") || b.Traits["certificate-count"] != float64(1) {
		t.Fatalf("B's record = %+v", b)
	}
	rec, found, err := h.store.DocRecordFor(ctx, h.tenant, "itglue")
	if err != nil || !found || rec.Status != store.DocRecordSynced || rec.OrgID != "11" || rec.Certificates != 2 || rec.NextExpiry == nil ||
		!rec.NextExpiry.Equal(soon) {
		t.Fatalf("A's recorded sync = %+v %v %v", rec, found, err)
	}

	// Nothing changed: the next interval writes nothing.
	_, writes, _ := itg.Counts()
	docSync(t, h, h.tenant, "itglue", bucket.Add(10*time.Minute))
	if _, after, _ := itg.Counts(); after != writes {
		t.Fatalf("an unchanged inventory wrote %d times", after-writes)
	}

	// A renewal: the soonest certificate is superseded by one expiring later.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'superseded' WHERE id = $1`, soonID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	renewed := time.Now().UTC().Add(110 * 24 * time.Hour).Truncate(time.Second)
	addDocCertificate(t, h, h.tenant, "www.alpha.example", renewed)
	docSync(t, h, h.tenant, "itglue", bucket.Add(20*time.Minute))
	assets = itg.Assets()
	if len(assets) != 2 {
		t.Fatalf("a renewal made another asset: %+v", assets)
	}
	for _, x := range assets {
		if x.OrgID == 11 && (x.ID != a.ID || x.Traits["next-expiry"] != renewed.Format("2006-01-02")) {
			t.Fatalf("A's record after the renewal = %+v, want asset %d with the new expiry", x, a.ID)
		}
	}

	// Deleted in IT Glue: written again under the same organization.
	itg.DeleteAsset(a.ID)
	addDocCertificate(t, h, h.tenant, "mail.alpha.example", later)
	docSync(t, h, h.tenant, "itglue", bucket.Add(30*time.Minute))
	recreated := false
	for _, x := range itg.Assets() {
		if x.OrgID == 11 && x.ID != a.ID && strings.Contains(x.Traits["certificates"].(string), "mail.alpha.example") {
			recreated = true
		}
	}
	if !recreated {
		t.Fatalf("a deleted record was not written again: %+v", itg.Assets())
	}

	if strings.Contains(logs.String(), key) {
		t.Fatal("the debug log carries the API key")
	}
	var leaked int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE position($1 in payload::text) > 0 OR position($1 in coalesce(last_error, '')) > 0`,
		key).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the outbox carries the API key (%d, %v)", leaked, err)
	}
}
