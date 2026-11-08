// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dbaccess"
)

// A239-L1: a role's binding decides its class whatever the role is called, a
// bound map is the backend's own copy, and a default class covers only roles
// that are neither bound nor named as a class.
func TestDatabaseLeasesGrantTheClassTheirRoleIsBoundTo(t *testing.T) {
	ctx := context.Background()
	bound := map[string]dbaccess.Access{"analytics": dbaccess.Read, "etl": dbaccess.ReadWrite, "readonly": dbaccess.ReadWrite}
	mysqlGrant := func(t *testing.T, access DatabaseRoleAccess, role string) (string, error) {
		t.Helper()
		exec := &grantRecordingSQLExec{}
		b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "10.4.0.12", DatabaseRoleAccess: access})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: time.Hour})
		grant, _ := exec.grant()
		return grant, err
	}
	mongoGrant := func(t *testing.T, access DatabaseRoleAccess, role string) (string, error) {
		t.Helper()
		admin := &roleRecordingMongoAdmin{}
		b, err := NewMongoBackend(admin, MongoConfig{Database: "app", DatabaseRoleAccess: access})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: time.Hour})
		got, _ := admin.only(t)
		return got, err
	}
	explicit := DatabaseRoleAccess{RoleAccess: bound}
	for role, writes := range map[string]bool{"analytics": false, "etl": true, "readonly": true, "writer": true, "reader": false} {
		grant, err := mysqlGrant(t, explicit, role)
		if err != nil || strings.Contains(grant, "INSERT") != writes {
			t.Fatalf("bound MySQL role %q: grant %q, %v", role, grant, err)
		}
		want := "read"
		if writes {
			want = "readWrite"
		}
		if got, err := mongoGrant(t, explicit, role); err != nil || got != want {
			t.Fatalf("bound MongoDB role %q: %q, %v; want %q", role, got, err, want)
		}
	}
	if _, err := mysqlGrant(t, explicit, "viewer"); err == nil || !strings.Contains(err.Error(), "no access class") {
		t.Fatalf("an unbound, unnamed role was granted: %v", err)
	}

	// The backend keeps its own copy: a caller's later change grants nothing.
	shared := map[string]dbaccess.Access{"analytics": dbaccess.Read}
	exec := &grantRecordingSQLExec{}
	b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "10.4.0.12",
		DatabaseRoleAccess: DatabaseRoleAccess{RoleAccess: shared}})
	if err != nil {
		t.Fatal(err)
	}
	shared["analytics"] = dbaccess.ReadWrite
	if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "analytics", TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if grant, _ := exec.grant(); strings.Contains(grant, "INSERT") {
		t.Fatalf("a caller's later change reached the backend: %q", grant)
	}

	// A default class covers only the roles nothing else decides.
	fallback := DatabaseRoleAccess{RoleAccess: bound, DefaultAccess: dbaccess.Read}
	for role, writes := range map[string]bool{"db/reporting": false, "etl": true, "writer": true} {
		grant, err := mysqlGrant(t, fallback, role)
		if err != nil || strings.Contains(grant, "INSERT") != writes {
			t.Fatalf("defaulted MySQL role %q: grant %q, %v", role, grant, err)
		}
	}
}
