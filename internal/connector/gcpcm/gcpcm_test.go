package gcpcm_test

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	token    = "ya29.access-token"
	project  = "my-project"
	location = "global"
	certID   = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\ngcp-leaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ngcp-inter\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\ngcp-key\n-----END PRIVATE KEY-----\n")
)

func newConn(endpoint string) *gcpcm.Connector {
	return gcpcm.New(project, location, gcpcm.StaticToken(token),
		gcpcm.WithEndpoint(endpoint), gcpcm.WithPollInterval(0))
}

// Deploy updates the self-managed certificate resource with the renewed chain
// and key, authenticated with the bearer token.
func TestDeployUpdatesCertificate(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()

	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), newConn(srv.URL()), ops, connector.NewDeployment(certID, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got, ok := srv.Imported(certID)
	if !ok {
		t.Fatalf("nothing updated under %q", certID)
	}
	if got.PEMCertificate != string(sampleCert) {
		t.Errorf("pemCertificate = %q, want the full chain", got.PEMCertificate)
	}
	if got.PEMPrivateKey != string(sampleKey) {
		t.Errorf("pemPrivateKey mismatch")
	}
}

// The patch returns a long-running operation; the connector polls it to
// completion rather than assuming synchronous success.
func TestDeployPollsOperationToCompletion(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()

	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), newConn(srv.URL()), ops, connector.NewDeployment(certID, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if srv.Polls() < 1 {
		t.Errorf("expected the LRO to be polled at least once, got %d polls", srv.Polls())
	}
}

// A wrong bearer token is rejected; the deploy fails and nothing is updated.
func TestDeployFailsOnBadToken(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()

	c := gcpcm.New(project, location, gcpcm.StaticToken("wrong-token"), gcpcm.WithEndpoint(srv.URL()), gcpcm.WithPollInterval(0))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certID, sampleCert, sampleKey)); err == nil {
		t.Fatal("expected deploy to fail on a bad token, got nil")
	}
	if _, ok := srv.Imported(certID); ok {
		t.Error("nothing should be updated when the token is rejected")
	}
}

// Re-applying the same credential to the same resource converges to the same
// state.
func TestDeployIsIdempotent(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()

	ops := connector.NewHTTPOps(srv.Client())
	c := newConn(srv.URL())
	dep := connector.NewDeployment(certID, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	got, ok := srv.Imported(certID)
	if !ok || got.PEMCertificate != string(sampleCert) {
		t.Errorf("after redeploy: ok=%v", ok)
	}
}

// Least privilege: net.dial to the Certificate Manager host only — no fs, no
// exec, no other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := gcpcm.New(project, location, gcpcm.StaticToken(token)) // default GCP endpoint
	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("connector must request net.dial")
	}
	if !grant.Allows(pluginhost.CapNetDial, "certificatemanager.googleapis.com") {
		t.Error("net.dial must allow the Certificate Manager host")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the Certificate Manager host, not any host")
	}
}

// The connector satisfies the shared connector conformance suite.
func TestGCPCMPassesConformance(t *testing.T) {
	c := gcpcm.New(project, location, gcpcm.StaticToken(token))
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
