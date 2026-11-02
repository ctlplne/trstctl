// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A240 two-user rotation against a real PostgreSQL: the owner provisioned two
// login roles in one group role holding the grants; each rotation sets a new
// password on the inactive account, both work while consumers move over, and
// retiring the predecessor scrambles its password without touching its grants.
func TestPostgresTwoUserRotationKeepsGrantsA240(t *testing.T) {
	adminDSN, stop := startDynsecretPostgres(t)
	defer stop()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	for _, stmt := range []string{
		"CREATE TABLE orders (id int PRIMARY KEY)",
		"INSERT INTO orders VALUES (1)",
		"CREATE ROLE orders_rw NOLOGIN",
		"GRANT SELECT, INSERT ON orders TO orders_rw",
		"CREATE ROLE orders_app_a LOGIN PASSWORD 'initial-a-password' IN ROLE orders_rw",
		"CREATE ROLE orders_app_b LOGIN IN ROLE orders_rw",
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	b, err := NewPostgresBackend(PostgresConfig{DSN: []byte(adminDSN), RotationAccounts: map[string][2]string{"orders-db": {"orders_app_a", "orders_app_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	works := func(dsn string, insert int) error {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close(ctx) }()
		var n int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM orders").Scan(&n); err != nil {
			return err
		}
		_, err = conn.Exec(ctx, "INSERT INTO orders VALUES ($1)", insert)
		return err
	}
	live := strings.Replace(adminDSN, "postgres:postgres@", "orders_app_a:initial-a-password@", 1)
	if err := works(live, 2); err != nil {
		t.Fatalf("the owner's account before rotation: %v", err)
	}
	predecessor, next := "orders_app_a", 10
	for cycle := 1; cycle <= 3; cycle++ {
		ref, dsn, err := b.CreateCredential(ctx, GenerateRequest{Role: "orders-db", LeaseID: "cmd-" + string(rune('0'+cycle)), Static: true, Predecessor: predecessor})
		if err != nil {
			t.Fatalf("cycle %d stage: %v", cycle, err)
		}
		if ref == predecessor || (ref != "orders_app_a" && ref != "orders_app_b") {
			t.Fatalf("cycle %d staged %q after %q", cycle, ref, predecessor)
		}
		// Both credentials work while consumers move over, with the same grants.
		if err := works(string(dsn), next); err != nil {
			t.Fatalf("cycle %d successor: %v", cycle, err)
		}
		if err := works(live, next+1); err != nil {
			t.Fatalf("cycle %d predecessor during the overlap: %v", cycle, err)
		}
		if err := b.Revoke(ctx, predecessor); err != nil {
			t.Fatalf("cycle %d retire: %v", cycle, err)
		}
		if err := works(live, next+2); err == nil {
			t.Fatalf("cycle %d: the retired predecessor still logs in", cycle)
		}
		var members int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
			WHERE g.rolname = 'orders_rw' AND u.rolname IN ('orders_app_a', 'orders_app_b')`).Scan(&members); err != nil || members != 2 {
			t.Fatalf("cycle %d: group membership %d (%v), want both accounts kept", cycle, members, err)
		}
		predecessor, live, next = ref, string(dsn), next+10
	}
	if predecessor != "orders_app_b" {
		t.Fatalf("three cycles from A ended on %q, want orders_app_b (A→B→A→B)", predecessor)
	}
	// A retry of an uncertain stage converges on the same account: the first
	// password stops working, the second works, no other role appears.
	ref1, dsn1, err := b.CreateCredential(ctx, GenerateRequest{Role: "orders-db", LeaseID: "cmd-retry", Static: true, Predecessor: predecessor})
	if err != nil {
		t.Fatal(err)
	}
	ref2, dsn2, err := b.CreateCredential(ctx, GenerateRequest{Role: "orders-db", LeaseID: "cmd-retry", Static: true, Predecessor: predecessor})
	if err != nil || ref1 != ref2 || works(string(dsn1), 100) == nil || works(string(dsn2), 101) != nil {
		t.Fatalf("retry: %q %q (%v)", ref1, ref2, err)
	}
	var roles int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname LIKE 'trstctl%'`).Scan(&roles); err != nil || roles != 0 {
		t.Fatalf("two-user rotation created %d roles (%v)", roles, err)
	}
	// An account the owner never provisioned is refused, naming the fix.
	missing, err := NewPostgresBackend(PostgresConfig{DSN: []byte(adminDSN), RotationAccounts: map[string][2]string{"orders-db": {"orders_app_a", "orders_app_c"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Close()
	if _, _, err := missing.CreateCredential(ctx, GenerateRequest{Role: "orders-db", LeaseID: "cmd-x", Static: true, Predecessor: "orders_app_a"}); err == nil ||
		!strings.Contains(err.Error(), "provision it with the role's grants first") {
		t.Fatalf("a missing account: %v", err)
	}
	if _, err := NewPostgresBackend(PostgresConfig{DSN: []byte(adminDSN), RotationAccounts: map[string][2]string{"r": {"same", "same"}}}); err == nil {
		t.Fatal("accepted a pair of one account")
	}
}
