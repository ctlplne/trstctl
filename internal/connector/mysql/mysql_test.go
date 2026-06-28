package mysql_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/mysql"
)

var (
	mysqlCert = []byte("-----BEGIN CERTIFICATE-----\nmysql-leaf\n-----END CERTIFICATE-----\n")
	mysqlKey  = []byte("-----BEGIN PRIVATE KEY-----\nmysql-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesTLSFilesAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := mysql.New("/etc/mysql/tls/server-cert.pem", "/etc/mysql/tls/server-key.pem")
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("mysql", mysqlCert, mysqlKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, ok := ops.File("/etc/mysql/tls/server-cert.pem"); !ok || !bytes.Equal(got, mysqlCert) {
		t.Fatal("certificate was not written")
	}
	if got, ok := ops.File("/etc/mysql/tls/server-key.pem"); !ok || !bytes.Equal(got, mysqlKey) {
		t.Fatal("key was not written")
	}
	if got := ops.Execs(); len(got) != 1 || got[0][0] != "mysqladmin" {
		t.Fatalf("reload not recorded: %+v", got)
	}
}

func TestMySQLPassesConformance(t *testing.T) {
	rep := connector.Conformance(context.Background(), mysql.New("/etc/mysql/tls/server-cert.pem", "/etc/mysql/tls/server-key.pem"))
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
