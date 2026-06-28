package postgresql_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/postgresql"
)

var (
	postgresCert = []byte("-----BEGIN CERTIFICATE-----\npostgresql-leaf\n-----END CERTIFICATE-----\n")
	postgresKey  = []byte("-----BEGIN PRIVATE KEY-----\npostgresql-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesTLSFilesAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := postgresql.New("/etc/postgresql/tls/server.crt", "/etc/postgresql/tls/server.key")
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("postgresql", postgresCert, postgresKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, ok := ops.File("/etc/postgresql/tls/server.crt"); !ok || !bytes.Equal(got, postgresCert) {
		t.Fatal("certificate was not written")
	}
	if got, ok := ops.File("/etc/postgresql/tls/server.key"); !ok || !bytes.Equal(got, postgresKey) {
		t.Fatal("key was not written")
	}
	if got := ops.Execs(); len(got) != 1 || got[0][0] != "pg_ctl" {
		t.Fatalf("reload not recorded: %+v", got)
	}
}

func TestPostgreSQLPassesConformance(t *testing.T) {
	rep := connector.Conformance(context.Background(), postgresql.New("/etc/postgresql/tls/server.crt", "/etc/postgresql/tls/server.key"))
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
