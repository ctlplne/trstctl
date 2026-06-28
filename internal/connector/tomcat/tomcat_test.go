package tomcat_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/tomcat"
)

var (
	tomcatCert = []byte("-----BEGIN CERTIFICATE-----\ntomcat-leaf\n-----END CERTIFICATE-----\n")
	tomcatKey  = []byte("-----BEGIN PRIVATE KEY-----\ntomcat-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesTLSFilesAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := tomcat.New("/etc/tomcat/tls/server.crt", "/etc/tomcat/tls/server.key")
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("tomcat", tomcatCert, tomcatKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, ok := ops.File("/etc/tomcat/tls/server.crt"); !ok || !bytes.Equal(got, tomcatCert) {
		t.Fatal("certificate was not written")
	}
	if got, ok := ops.File("/etc/tomcat/tls/server.key"); !ok || !bytes.Equal(got, tomcatKey) {
		t.Fatal("key was not written")
	}
	if got := ops.Execs(); len(got) != 1 || got[0][0] != "catalina.sh" {
		t.Fatalf("reload not recorded: %+v", got)
	}
}

func TestTomcatPassesConformance(t *testing.T) {
	rep := connector.Conformance(context.Background(), tomcat.New("/etc/tomcat/tls/server.crt", "/etc/tomcat/tls/server.key"))
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
