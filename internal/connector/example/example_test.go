package example_test

import (
	"context"
	"testing"

	"certctl.io/certctl/internal/connector"
	"certctl.io/certctl/internal/connector/example"
)

var (
	cert = []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	key  = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")
)

// TestSampleDeploysViaSandboxWithOnlyGrantedCapabilities is the S5.5 acceptance:
// a connector built from the template deploys via the sandbox, performing only
// the operations its grant permits (write the cert files, reload the service).
func TestSampleDeploysViaSandboxWithOnlyGrantedCapabilities(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := example.New("/etc/certctl/tls", "reload-proxy", "--graceful")

	dep := connector.NewDeployment("proxy-node", cert, key)
	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, ok := ops.File("/etc/certctl/tls/tls.crt"); !ok || string(got) != string(cert) {
		t.Errorf("certificate not written to the granted path (ok=%v)", ok)
	}
	if _, ok := ops.File("/etc/certctl/tls/tls.key"); !ok {
		t.Error("key not written to the granted path")
	}
	if len(ops.Execs()) == 0 {
		t.Error("service reload was not run")
	}
}

// TestSamplePassesConformance is the other half of the acceptance: the sample
// connector passes the shared conformance suite (deploys, is idempotent, and is
// least-privilege — operations outside its grant are denied).
func TestSamplePassesConformance(t *testing.T) {
	report := connector.Conformance(context.Background(), example.New("/srv/tls", "reload"))
	if !report.OK() {
		t.Errorf("sample connector failed conformance: %+v", report.Checks)
	}
	if len(report.Checks) == 0 {
		t.Error("conformance produced no checks")
	}
}
