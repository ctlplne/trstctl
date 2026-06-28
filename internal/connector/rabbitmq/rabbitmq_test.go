package rabbitmq_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
)

var (
	rabbitCert = []byte("-----BEGIN CERTIFICATE-----\nrabbitmq-leaf\n-----END CERTIFICATE-----\n")
	rabbitKey  = []byte("-----BEGIN PRIVATE KEY-----\nrabbitmq-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesTLSFilesAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := rabbitmq.New("/etc/rabbitmq/tls/server.crt", "/etc/rabbitmq/tls/server.key")
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("rabbitmq", rabbitCert, rabbitKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, ok := ops.File("/etc/rabbitmq/tls/server.crt"); !ok || !bytes.Equal(got, rabbitCert) {
		t.Fatal("certificate was not written")
	}
	if got, ok := ops.File("/etc/rabbitmq/tls/server.key"); !ok || !bytes.Equal(got, rabbitKey) {
		t.Fatal("key was not written")
	}
	if got := ops.Execs(); len(got) != 1 || got[0][0] != "rabbitmqctl" {
		t.Fatalf("reload not recorded: %+v", got)
	}
}

func TestRabbitMQPassesConformance(t *testing.T) {
	rep := connector.Conformance(context.Background(), rabbitmq.New("/etc/rabbitmq/tls/server.crt", "/etc/rabbitmq/tls/server.key"))
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
