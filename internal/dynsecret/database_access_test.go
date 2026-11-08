// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"
)

// grantRecordingSQLExec keeps every statement a MySQL backend sends.
type grantRecordingSQLExec struct {
	mu      sync.Mutex
	queries []string
}

func (r *grantRecordingSQLExec) ExecContext(_ context.Context, q string, _ ...any) (sql.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, q)
	return nil, nil
}

func (r *grantRecordingSQLExec) grant() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	grant := ""
	for _, q := range r.queries {
		if strings.HasPrefix(q, "GRANT ") {
			grant = q
		}
	}
	return grant, len(r.queries)
}

// roleRecordingMongoAdmin keeps the roles each MongoDB user is created with.
type roleRecordingMongoAdmin struct {
	mu    sync.Mutex
	roles map[string][]MongoRole
}

func (m *roleRecordingMongoAdmin) CreateUser(_ context.Context, _, user string, _ []byte, roles []MongoRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.roles == nil {
		m.roles = map[string][]MongoRole{}
	}
	m.roles[user] = append([]MongoRole(nil), roles...)
	return nil
}

func (*roleRecordingMongoAdmin) DropUser(context.Context, string, string) error { return nil }

func (*roleRecordingMongoAdmin) SetUserPassword(context.Context, string, string, []byte) error {
	return nil
}

func (m *roleRecordingMongoAdmin) only(t *testing.T) (string, int) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, roles := range m.roles {
		if len(roles) != 1 {
			t.Fatalf("a MongoDB lease was created with roles %+v", roles)
		}
		return roles[0].Role, len(m.roles)
	}
	return "", 0
}

// A239-L1: a PostgreSQL, MySQL or MongoDB lease is granted the class its role
// names exactly, and a role that names no class is refused before any account
// exists. The class used to be guessed from the name: anything containing
// "read", "readwrite" and "read-write" included, became read-only, and anything
// else ("viewer", "reporting", "analyst") was granted INSERT, UPDATE and DELETE
// on every table.
func TestDatabaseLeasesNeverGuessAccessFromARoleName(t *testing.T) {
	ctx := context.Background()
	const writes = "SELECT, INSERT, UPDATE, DELETE"
	for _, tc := range []struct {
		role       string
		writes     bool
		refused    bool
		mongoGrant string
	}{
		{role: "readonly", mongoGrant: "read"},
		{role: "reader", mongoGrant: "read"},
		{role: "writer", writes: true, mongoGrant: "readWrite"},
		{role: "readwrite", writes: true, mongoGrant: "readWrite"},
		{role: "read-write", writes: true, mongoGrant: "readWrite"},
		{role: "viewer", refused: true},
		{role: "reporting", refused: true},
		{role: "analyst", refused: true},
		{role: "support-read", refused: true},
	} {
		t.Run(tc.role, func(t *testing.T) {
			exec := &grantRecordingSQLExec{}
			mysql, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "10.4.0.12"})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = mysql.CreateCredential(ctx, GenerateRequest{Role: tc.role, TTL: time.Hour})
			grant, sent := exec.grant()
			switch {
			case tc.refused:
				if err == nil || !strings.Contains(err.Error(), "no access class") {
					t.Fatalf("MySQL role %q was not refused: %v (grant %q)", tc.role, err, grant)
				}
				if sent != 0 {
					t.Fatalf("a refused MySQL role reached the server: %d statements", sent)
				}
			case err != nil:
				t.Fatalf("MySQL role %q: %v", tc.role, err)
			case tc.writes != strings.Contains(grant, writes):
				t.Fatalf("MySQL role %q was granted %q", tc.role, grant)
			}

			admin := &roleRecordingMongoAdmin{}
			mongo, err := NewMongoBackend(admin, MongoConfig{Database: "app"})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = mongo.CreateCredential(ctx, GenerateRequest{Role: tc.role, TTL: time.Hour})
			role, users := admin.only(t)
			switch {
			case tc.refused:
				if err == nil || !strings.Contains(err.Error(), "no access class") || users != 0 {
					t.Fatalf("MongoDB role %q was not refused before a user existed: %v (%d users, role %q)", tc.role, err, users, role)
				}
			case err != nil:
				t.Fatalf("MongoDB role %q: %v", tc.role, err)
			case role != tc.mongoGrant:
				t.Fatalf("MongoDB role %q was granted %q, want %q", tc.role, role, tc.mongoGrant)
			}

			// PostgreSQL decides before it connects: this DSN reaches nothing.
			if tc.refused {
				pg, err := NewPostgresBackend(PostgresConfig{DSN: []byte("postgres://trstctl@127.0.0.1:1/app?connect_timeout=1"), Database: "app", Schema: "public"})
				if err != nil {
					t.Fatal(err)
				}
				defer pg.Close()
				if _, _, err := pg.CreateCredential(ctx, GenerateRequest{Role: tc.role, TTL: time.Hour}); err == nil || !strings.Contains(err.Error(), "no access class") {
					t.Fatalf("PostgreSQL role %q was not refused before connecting: %v", tc.role, err)
				}
			}
		})
	}
}
