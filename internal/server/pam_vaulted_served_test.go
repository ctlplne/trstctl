// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestServedVaultedAccountRotatesThroughTheGatewayA261: a vaulted PostgreSQL
// target's sessions are delivered through its gateway signed in as the
// account an application secret holds — nobody receives the credential. A
// scheduled rotation (A240's two-user engine) moves the secret to the other
// account and retires the old one: a session opened afterwards still works
// through the gateway, now as the new account, and the old credential is
// refused by the database. A vaulted target allows only its secret's role
// and needs the secret readable.
func TestServedVaultedAccountRotatesThroughTheGatewayA261(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a261-registrar", "access:read", "access:targets.write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a261-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	register := func(key string, target map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, key, target)
	}
	vaulted := func(id string, roles []string, secret string) map[string]any {
		return map[string]any{"id": id, "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": roles,
			"gateway_agent_id": gatewayID, "gateway_address": f.gatewayAddr, "account_secret": secret}
	}
	if status, body := register("a261-wrong-role", vaulted("orders-vault-x", []string{"readonly"}, twoUserRole)); status == http.StatusCreated {
		t.Fatalf("a vaulted target allowing another role was registered: %s", body)
	}
	if status, body := register("a261-missing", vaulted("orders-vault-y", []string{"db/missing"}, "db/missing")); status == http.StatusCreated {
		t.Fatalf("a vaulted target naming an unreadable secret was registered: %s", body)
	}
	status, body := register("a261-register", vaulted("orders-vault", []string{twoUserRole}, twoUserRole))
	if status != http.StatusCreated || !strings.Contains(string(body), `"account_secret":"`+twoUserRole+`"`) {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}

	signedInAs := func(key string) string {
		t.Helper()
		session := f.open(key, map[string]any{"target_type": "postgres", "target_id": "orders-vault", "role": twoUserRole, "ttl_seconds": 120})
		if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil {
			t.Fatalf("a vaulted session was not delivered through its gateway alone: %+v", session)
		}
		local, stop := f.postgresTunnel(session)
		defer stop()
		conn, err := pgconn.Connect(f.ctx, "postgres://anyone@"+local+"/postgres?sslmode=disable")
		if err != nil {
			t.Fatalf("the vaulted session does not reach the database: %v (gateway: %s)", err, f.gatewayLog.String())
		}
		defer func() { _ = conn.Close(context.Background()) }()
		result := conn.ExecParams(f.ctx, "SELECT current_user", nil, nil, nil, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 {
			t.Fatalf("SELECT current_user through the gateway: %v", result.Err)
		}
		return string(result.Rows[0][0])
	}
	if got := signedInAs("a261-before"); got != twoUserAccountA {
		t.Fatalf("before the rotation the gateway signed in as %q, want %s", got, twoUserAccountA)
	}

	// A scheduled rotation, due now.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotation-schedules", custodian, "a261-schedule",
		map[string]any{"name": "orders-vault-weekly", "provider": "pam-pg-vault", "key": twoUserRole, "old_ref": twoUserAccountA,
			"interval_seconds": 7 * 24 * 3600, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create the rotation schedule: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", custodian, "a261-run-due", nil); status != http.StatusOK {
		t.Fatalf("run due rotations: %d %s", status, body)
	}
	a201Await(t, "the scheduled rotation completes", func() bool {
		ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
		defer cancel()
		_ = h.srv.Drain(ctx)
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/rotations", custodian, nil)
		var page struct {
			Items []struct {
				Key   string `json:"key"`
				Phase string `json:"phase"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, item := range page.Items {
			if item.Key == twoUserRole && item.Phase == "completed" {
				return true
			}
		}
		return false
	})

	if got := signedInAs("a261-after"); got != twoUserAccountB {
		t.Fatalf("after the rotation the gateway signed in as %q, want %s", got, twoUserAccountB)
	}
	if conn, err := pgconn.Connect(f.ctx, f.vaultDSN); err == nil {
		_ = conn.Close(context.Background())
		t.Fatal("the rotated-out credential still signs in")
	} else if !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("the old credential failed for another reason: %v", err)
	}
}
