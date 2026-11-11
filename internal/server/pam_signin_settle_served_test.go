// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/pamsignin"
	"trstctl.com/trstctl/internal/store"
)

// A274-L1: trstctl records its own use of an account after the sign-in has
// happened (a credential health check is recorded when it finishes), so a
// collection that read the sign-in in between flagged trstctl's own sign-in
// as a bypass. A collection now judges a dated sign-in only once it is older
// than the settle time and reads back past its lookback by as much, so the
// next run judges what it left: an outside sign-in is still flagged, one run
// later, and a sign-in whose health-check record lands after the first read
// is explained.
func TestServedSignInCollectionWaitsForTrstctlsOwnRecordA274L1(t *testing.T) {
	ctx := context.Background()
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	const settle = 4 * time.Second
	h.srv.pam.signInSettle.Store(int64(settle))
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1-registrar", "access:read", "access:targets.write")
	watcher := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1-watcher", "discovery:read", "discovery:write")
	// The account's current DSN: an earlier test in this process may have
	// rotated its password, and the secret store holds what it is now.
	dsn := f.vaultDSN
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/"+twoUserRole, custodian, nil); status == http.StatusOK {
		var current struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(body, &current) != nil || current.Value == "" {
			t.Fatalf("read the account secret: %s", body)
		}
		dsn = current.Value
	} else if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a274l1-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a274l1-register",
		map[string]any{"id": "orders-settle", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", watcher, "a274l1-source", map[string]any{
		"name": "a274l1-orders-signins", "kind": "pam_signin", "config": map[string]any{"provider_id": "pam-pg-vault", "lookback_seconds": 900}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the pam_signin source: %d %s", status, body)
	}
	collect := func(key string) []a274Finding {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", watcher, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, watcher, nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"succeeded"`) {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?limit=100", watcher, nil)
		var listed struct {
			Items []a274Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("findings after %s: %d %s", key, status, body)
		}
		var out []a274Finding
		for _, finding := range listed.Items {
			if finding.SourceID == source.ID {
				out = append(out, finding)
			}
		}
		return out
	}
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1-reader", "access:read")
	type signInRecord struct {
		Fingerprint string `json:"fingerprint"`
		Ref         string `json:"ref"`
		ExplainedBy *struct {
			Kind string `json:"kind"`
		} `json:"explained_by"`
	}
	// recordOf is the recorded sign-in of a PostgreSQL backend, if any run
	// recorded it.
	recordOf := func(pid int32) (signInRecord, bool) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/signins?provider_id=pam-pg-vault&limit=200", reader, nil)
		var listed struct {
			Items []signInRecord `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("recorded sign-ins: %d %s", status, body)
		}
		for _, r := range listed.Items {
			if strings.HasPrefix(r.Ref, fmt.Sprintf("pid %d@", pid)) {
				return r, true
			}
		}
		return signInRecord{}, false
	}
	// connect signs in as the account and returns the backend's pid.
	connect := func() (int32, func()) {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		var pid int32
		if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatalf("query: %v", err)
		}
		return pid, func() { _ = conn.Close(context.Background()) }
	}
	// Earlier tests in this process may have used these accounts in this
	// tenant: their spans explain sign-ins for the skew allowance after they
	// end, so this test starts after that.
	src, err := h.srv.pam.signInSource(h.tenant, "pam-pg-vault")
	if err != nil {
		t.Fatal(err)
	}
	windows, err := h.srv.pam.signInWindows(ctx, h.tenant, src, src.DynamicSecretManagedAccounts(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var latest time.Time
	for _, w := range windows {
		if w.To.After(latest) {
			latest = w.To
		}
	}
	if wait := time.Until(latest.Add(pamsignin.DefaultSlack + time.Second)); wait > 0 {
		if wait > 5*time.Minute {
			t.Fatalf("an earlier span of these accounts lasts until %s", latest)
		}
		time.Sleep(wait)
	}
	// Served tests share a tenant: an earlier test's check-out ending in that
	// wait has this harness rotate the account. Set a password this test
	// knows on the fixture's own database.
	password := strings.ReplaceAll(uuid.NewString(), "-", "")
	target := &twoUserTarget{t: t, adminDSN: f.pgAdminDSN}
	target.exec(`ALTER ROLE ` + twoUserAccountA + ` PASSWORD '` + password + `'`)
	dsn = target.dsn(twoUserAccountA, password)

	// An outside sign-in is not judged while it is recent, and the next run
	// judges it once it is older than the settle time: nothing is lost.
	// Served tests share a tenant, so another test's span may explain it;
	// unexplained, it is flagged.
	outsidePID, closeOutside := connect()
	outsideAt := time.Now()
	collect("a274l1-outside-recent")
	if r, found := recordOf(outsidePID); found {
		t.Fatalf("a recent sign-in was judged before its window could land: %+v", r)
	}
	time.Sleep(time.Until(outsideAt.Add(settle + time.Second)))
	got := collect("a274l1-outside-settled")
	closeOutside()
	outside, found := recordOf(outsidePID)
	if !found {
		t.Fatal("the run after the settle time did not judge the sign-in the previous run left")
	}
	if outside.ExplainedBy == nil {
		flagged := false
		for _, f := range got {
			flagged = flagged || f.Fingerprint == outside.Fingerprint
		}
		if !flagged {
			t.Fatalf("the unexplained outside sign-in raised no finding: %+v", got)
		}
	}

	// trstctl's own health check signs in; a collection reads the sign-in
	// before the check's record lands, then the record lands, and the next
	// run explains it: no finding.
	checkPID, closeCheck := connect()
	checkAt := time.Now()
	collect("a274l1-check-recent")
	if r, found := recordOf(checkPID); found {
		t.Fatalf("the health check's sign-in was judged before its record landed: %+v", r)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyPAMAccountHealthCheckedTx(ctx, tx, h.tenant, store.PAMAccountHealth{
			TargetType: "postgres", TargetID: "orders-settle", ProviderID: "pam-pg-vault",
			Status: "healthy", Attempts: 1, CheckedAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(checkAt.Add(settle + time.Second)))
	got = collect("a274l1-check-settled")
	closeCheck()
	check, found := recordOf(checkPID)
	if !found || check.ExplainedBy == nil {
		t.Fatalf("after its record landed, the health check's sign-in reads %+v (recorded %v)", check, found)
	}
	for _, f := range got {
		if f.Fingerprint == check.Fingerprint {
			t.Fatalf("the health check's sign-in raised a finding: %+v", f)
		}
	}
}
