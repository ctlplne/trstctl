// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
)

func TestCR260MySQLLeaseRevokeEndsVerifiedTLSSession(t *testing.T) {
	_, _, registry := startPAMMySQLWithVault(t, "cr260-live-session", false)
	providers := registry.ForTenant(servedTestTenant)
	if len(providers) != 1 {
		t.Fatalf("MySQL provider count = %d, want 1", len(providers))
	}
	provider, ok := providers[0].(*configuredDynamicProvider)
	if !ok {
		t.Fatal("fixture did not build the production MySQL provider")
	}
	credential, err := provider.Generate(t.Context(), dynsecret.GenerateRequest{Role: "mysql-reader", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(credential.Secret) })
	caRef := provider.cfg.TLSCARef
	if !strings.HasPrefix(caRef, "file:") {
		t.Fatal("fixture has no test-owned TLS CA")
	}
	caPEM, err := os.ReadFile(strings.TrimPrefix(caRef, "file:")) // #nosec G304 -- test-owned CA file path returned by the pinned MySQL fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport := &dynsecret.DatabaseTransport{
		Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true}),
		CAPEM:  caPEM, ServerName: "db.private.test",
	}
	client, err := dynsecret.OpenMySQLExecutorWithTransport(t.Context(), credential.Secret, transport)
	if err != nil {
		t.Fatalf("verified-TLS lease sign-in: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := client.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	var note string
	if err := conn.QueryRowContext(t.Context(), "SELECT note FROM notes WHERE id=1").Scan(&note); err != nil || note != "cr260-live-session" {
		t.Fatalf("lease read before revoke: match=%t err=%v", note == "cr260-live-session", err)
	}
	if err := provider.Revoke(t.Context(), credential.BackendRef); err != nil {
		t.Fatalf("revoke with an open lease session: %v", err)
	}
	if fresh, err := dynsecret.OpenMySQLExecutorWithTransport(t.Context(), credential.Secret, transport); err == nil {
		_ = fresh.Close()
		t.Fatal("a new login with the revoked lease still works")
	}
	if err := conn.QueryRowContext(t.Context(), "SELECT note FROM notes WHERE id=1").Scan(&note); err == nil {
		t.Fatal("an already-open lease session still reads after revoke completed")
	}
}
