// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/pamsignin"
	"trstctl.com/trstctl/internal/store"
)

// TestServedEveryHealthCheckBetweenRunsExplainsItsSignInA274L1L1 (served, the
// gateway fixture's vaulted PostgreSQL account registered as a target): two
// credential health checks recorded nine minutes apart, both after the last
// sign-in collection, each explain the sign-in they made. Before, only the
// account's latest check opened a window, so the earlier check's sign-in read
// as one made outside trstctl. A sign-in near no check is still unexplained.
func TestServedEveryHealthCheckBetweenRunsExplainsItsSignInA274L1L1(t *testing.T) {
	ctx := context.Background()
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1l1-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a274l1l1-registrar", "access:read", "access:targets.write")
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/"+twoUserRole, custodian, nil); status != http.StatusOK {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a274l1l1-seed",
			map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed the account secret: %d %s", status, body)
		}
	}
	const targetID = "orders-health-history"
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a274l1l1-register",
		map[string]any{"id": targetID, "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}
	src, err := h.srv.pam.signInSource(h.tenant, "pam-pg-vault")
	if err != nil {
		t.Fatalf("sign-in source: %v", err)
	}
	roles := src.DynamicSecretManagedAccounts()
	accounts := roles[twoUserRole]
	if len(accounts) == 0 {
		t.Fatalf("the provider manages no account for %s: %v", twoUserRole, roles)
	}

	now := time.Now().UTC().Truncate(time.Second)
	first, second := now.Add(-10*time.Minute), now.Add(-time.Minute)
	for _, at := range []time.Time{first, second} {
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return h.store.ApplyPAMAccountHealthCheckedTx(ctx, tx, h.tenant, store.PAMAccountHealth{
				TargetType: "postgres", TargetID: targetID, ProviderID: "pam-pg-vault",
				Status: "healthy", Attempts: 1, CheckedAt: at,
			})
		}); err != nil {
			t.Fatalf("record the check at %s: %v", at, err)
		}
	}

	// One collection after both checks: each check's sign-in, made just
	// before its record, is trstctl's own; a sign-in near neither is not.
	windows, err := h.srv.pam.signInWindows(ctx, h.tenant, src, roles, now.Add(-15*time.Minute), now)
	if err != nil {
		t.Fatalf("windows: %v", err)
	}
	signIns := []pamsignin.SignIn{
		{Account: accounts[0], At: first.Add(-20 * time.Second), Ref: "a274l1l1-first-check"},
		{Account: accounts[0], At: second.Add(-20 * time.Second), Ref: "a274l1l1-second-check"},
		{Account: accounts[0], At: first.Add(-5 * time.Minute), Ref: "a274l1l1-outside"},
	}
	// Only this target's health-check windows: the shared served tenant's
	// other sessions and check-outs may use the same account.
	ref := "postgres/" + targetID
	var checks []pamsignin.Window
	for _, w := range windows {
		if w.Kind == pamsignin.WindowHealth && w.Ref == ref {
			checks = append(checks, w)
		}
	}
	for _, m := range pamsignin.Match(signIns, checks, pamsignin.DefaultSlack) {
		switch m.SignIn.Ref {
		case "a274l1l1-outside":
			if m.Window != nil {
				t.Fatalf("a sign-in five minutes before any check was explained by %+v", m.Window)
			}
		default:
			if m.Window == nil {
				t.Fatalf("the %s sign-in at %s is unexplained; the target's health-check windows are %+v", m.SignIn.Ref, m.SignIn.At, checks)
			}
		}
	}
	t.Logf("A274L1L1_OK checks=%s,%s windows=%d", first.Format(time.RFC3339), second.Format(time.RFC3339), len(checks))
}
