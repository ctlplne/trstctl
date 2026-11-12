// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// MSP-3 Done-when (usage, served, ConnectWise stand-in written from the
// vendor's public REST descriptions): each customer's signed period lands as
// additions of its own company's active agreement — customer A's figures on
// A's agreement, B's on B's, never crossed; a write whose answer was lost is
// retried without doubling a line; one customer's periods are applied oldest
// first even when the newer one is queued first, and an older period queued
// after a newer one was delivered writes nothing; a period of a customer
// remapped to another company sends nothing; a held (unsignable) period
// never reaches ConnectWise; neither API key appears in any recorded error or
// in the debug log.
func TestServedConnectWiseUsageLandsAsAgreementAdditionsMSP3(t *testing.T) {
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx := context.Background()
	const login, clientID = "trstctl_msp", "6c1a3e1e-58e3-4d1b-9f0e-3b8f5a0c2d71"
	const publicKey, privateKey = "cw-served-public-key", "cw-served-private-key"
	cw := psatest.NewConnectWise(login, clientID, publicKey, privateKey)
	t.Cleanup(cw.Close)
	cw.AddCompany(psatest.CWCompany{ID: 101, Identifier: "ALPHA", Name: "Alpha Dental"})
	cw.AddCompany(psatest.CWCompany{ID: 202, Identifier: "BETA", Name: "Beta Logistics"})
	cw.AddAgreement(psatest.CWAgreement{ID: 11, CompanyID: 101, TypeName: "Managed PKI", Status: "Active"})
	cw.AddAgreement(psatest.CWAgreement{ID: 21, CompanyID: 202, TypeName: "Managed PKI", Status: "Active"})
	target := config.ProviderBillingTarget{ID: "cw", Type: "connectwise", Endpoint: cw.URL(), AllowInsecureLoopback: true,
		ConnectWise: &config.ConnectWiseBillingTarget{CompanyID: login, ClientID: clientID,
			PublicKeyRef:  writeServedCredentialFile(t, "cw-public", publicKey),
			PrivateKeyRef: writeServedCredentialFile(t, "cw-private", privateKey),
			AgreementType: "Managed PKI", Products: map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}}}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
	})
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b02"
	registerServedTenant(t, h, "connectwise customer A")
	registerServedTenantID(t, h, customerB, "connectwise customer B")
	mapCompany := func(tenant, company string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'cw', $2, 'operator@example.test', now())
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	mapCompany(h.tenant, "101")
	mapCompany(customerB, "BETA")
	push := func(month time.Month, company string, certs, agents int64) projections.BillingSyncPushEvent {
		start := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
		return projections.BillingSyncPushEvent{TargetID: "cw", PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0), ExternalCompanyID: company,
			EvidenceDigest: "sha256:" + strings.ToLower(month.String()), EvidenceJWS: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
			Lines: []projections.BillingUsageLine{{Meter: "agents", Kind: "gauge", Value: agents},
				{Meter: "certificates_current", Kind: "gauge", Value: certs}, {Meter: "secrets_stored", Kind: "gauge", Value: 99}}}
	}
	queue := func(tenant string, p projections.BillingSyncPushEvent) {
		t.Helper()
		if queued, err := h.srv.orch.QueueBillingSyncPush(ctx, tenant, p); err != nil || !queued {
			t.Fatalf("queue %s %s = %v %v", tenant, p.PeriodStart.Format("2006-01"), queued, err)
		}
	}
	record := func(tenant string, month time.Month) store.BillingSyncPush {
		t.Helper()
		p, found, err := h.store.BillingSyncPushFor(ctx, tenant, "cw", time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC))
		if err != nil || !found {
			t.Fatalf("push %s %s: found=%v err=%v", tenant, month, found, err)
		}
		return p
	}
	drainUntil := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for !done() {
			if err := h.srv.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen", what)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// A's October is queued before its September; B's October alongside.
	// The first write takes effect but its answer is lost.
	queue(h.tenant, push(time.October, "101", 42, 3))
	queue(h.tenant, push(time.September, "101", 40, 2))
	queue(customerB, push(time.October, "BETA", 7, 1))
	cw.FailWritesAfterApplying(1)
	drainUntil("delivery of all three periods", func() bool {
		return record(h.tenant, time.September).Status == store.BillingSyncDelivered &&
			record(h.tenant, time.October).Status == store.BillingSyncDelivered &&
			record(customerB, time.October).Status == store.BillingSyncDelivered
	})
	alpha, beta := cw.Additions(11), cw.Additions(21)
	if len(alpha) != 2 || alpha[0].Product != "TRST-AGENT" || alpha[0].Quantity != 3 || alpha[1].Product != "TRST-CERT" || alpha[1].Quantity != 42 {
		t.Fatalf("A's agreement = %+v, want October's 3 agents and 42 certificates on two additions", alpha)
	}
	if len(beta) != 2 || beta[0].Quantity != 1 || beta[1].Quantity != 7 {
		t.Fatalf("B's agreement = %+v, want B's own 1 agent and 7 certificates", beta)
	}
	lastSeptember, firstOctober := -1, -1
	for i, seen := range cw.Seen() {
		if strings.HasPrefix(seen, "POST /finance/agreements/11/additions") {
			lastSeptember = i
		}
		if strings.HasPrefix(seen, "PATCH /finance/agreements/11/additions/") && firstOctober < 0 {
			firstOctober = i
		}
		if strings.Contains(seen, "/agreements/21/") && strings.Contains(seen, "101") {
			t.Fatalf("a request for B's agreement named A's company: %s", seen)
		}
	}
	if lastSeptember < 0 || firstOctober < lastSeptember {
		t.Fatalf("A's October was applied before its September (posts end at %d, patches start at %d): %v", lastSeptember, firstOctober, cw.Seen())
	}
	if p := record(h.tenant, time.October); p.ResponseStatus != http.StatusOK || p.ExternalCompanyID != "101" {
		t.Fatalf("A's October record = %+v", p)
	}

	// An older period queued after a newer one was delivered writes nothing.
	_, writesBefore, _ := cw.Counts()
	queue(h.tenant, push(time.August, "101", 1, 1))
	drainUntil("handling of A's August", func() bool { return record(h.tenant, time.August).Status == store.BillingSyncDelivered })
	if p := record(h.tenant, time.August); !strings.Contains(p.Reason, "already set") {
		t.Fatalf("A's August record = %+v, want it handled without writing", p)
	}
	if _, writes, _ := cw.Counts(); writes != writesBefore || cw.Additions(11)[1].Quantity != 42 {
		t.Fatalf("A's August wrote %d times or changed October's figure: %+v", writes-writesBefore, cw.Additions(11))
	}

	// B remapped to another company: B's November sends nothing.
	requestsBefore, _, _ := cw.Counts()
	queue(customerB, push(time.November, "BETA", 8, 1))
	mapCompany(customerB, "BETA-2")
	var attempts int
	var lastError string
	deadline := time.Now().Add(45 * time.Second)
	for attempts == 0 {
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT attempts, coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			customerB, orchestrator.BillingSyncPushKey("cw", time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC))).Scan(&attempts, &lastError)
		if time.Now().After(deadline) {
			t.Fatal("B's November was never attempted")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if requests, _, _ := cw.Counts(); requests != requestsBefore || record(customerB, time.November).Status != store.BillingSyncQueued {
		t.Fatalf("a remapped customer's period reached ConnectWise (%d→%d requests): %+v", requestsBefore, requests, record(customerB, time.November))
	}

	// A held (unsignable) period never reaches ConnectWise.
	held := push(time.December, "101", 5, 5)
	held.EvidenceJWS, held.Lines, held.Reason = "", nil, "metering coverage has a gap in this period"
	if ok, err := h.srv.orch.HoldBillingSyncPush(ctx, h.tenant, held); err != nil || !ok {
		t.Fatalf("hold December = %v %v", ok, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if requests, _, _ := cw.Counts(); requests != requestsBefore {
		t.Fatalf("a held period reached ConnectWise (%d→%d requests)", requestsBefore, requests)
	}

	// Neither key in any recorded error or reason, nor in the debug log.
	var leaked int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM outbox WHERE coalesce(last_error, '') LIKE '%' || $1 || '%' OR coalesce(last_error, '') LIKE '%' || $2 || '%') +
		(SELECT count(*) FROM provider_billing_sync_pushes WHERE reason LIKE '%' || $1 || '%' OR reason LIKE '%' || $2 || '%')`,
		publicKey, privateKey).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("a recorded error or reason carries an API key (%d rows, %v)", leaked, err)
	}
	if out := logs.String(); strings.Contains(out, publicKey) || strings.Contains(out, privateKey) || !strings.Contains(out, "outbox delivery") {
		t.Fatalf("the debug log carries an API key, or recorded no delivery at all:\n%s", out)
	}
	if _, _, refused := cw.Counts(); refused != 0 {
		t.Fatalf("ConnectWise refused %d requests' credentials", refused)
	}
}
