package connector_test

import (
	"context"
	"errors"
	"testing"

	"certctl.io/certctl/internal/connector"
	"certctl.io/certctl/internal/pluginhost"
)

// sampleCert/sampleKey are opaque PEM bytes; connectors never parse them.
var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\nMIIB-test-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\nMIIB-test-key\n-----END PRIVATE KEY-----\n")
)

// dialConnector deploys by sending the bundle to a network target; it needs only
// net.dial. It is a minimal in-line connector for SDK-mechanics tests.
type dialConnector struct{ name string }

func (c dialConnector) Name() string { return c.name }
func (c dialConnector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial)
}
func (c dialConnector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	bundle := append(append([]byte(nil), dep.CertPEM...), dep.KeyPEM...)
	return sb.Send(dep.Target, bundle)
}

// overreachConnector grants only net.dial but tries to write a file — it must be
// denied by the sandbox.
type overreachConnector struct{}

func (overreachConnector) Name() string { return "overreach" }
func (overreachConnector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial)
}
func (overreachConnector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	return sb.WriteFile("/etc/passwd", dep.CertPEM) // not granted
}

// TestRunDeploysThroughSandbox: Run drives the connector's Deploy through the
// capability-gated sandbox, and the credential lands at the target.
func TestRunDeploysThroughSandbox(t *testing.T) {
	ops := connector.NewMemoryOps()
	dep := connector.NewDeployment("edge-1:8443", sampleCert, sampleKey)
	if _, err := connector.Run(context.Background(), dialConnector{name: "edge"}, ops, dep); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, ok := ops.Sent("edge-1:8443")
	if !ok {
		t.Fatal("connector sent nothing to the target")
	}
	if len(got) != len(sampleCert)+len(sampleKey) {
		t.Errorf("delivered %d bytes, want cert+key bundle", len(got))
	}
}

// TestSandboxDeniesUngrantedCapability: a connector that attempts an operation
// outside its grant is denied — the core "only granted capabilities" guarantee.
func TestSandboxDeniesUngrantedCapability(t *testing.T) {
	ops := connector.NewMemoryOps()
	_, err := connector.Run(context.Background(), overreachConnector{}, ops, connector.NewDeployment("t", sampleCert, sampleKey))
	if !errors.Is(err, connector.ErrDenied) {
		t.Errorf("ungranted write err = %v, want ErrDenied", err)
	}
	if len(ops.Files()) != 0 {
		t.Error("a denied write still reached the target")
	}
}

// TestDeployIsIdempotent: deploying the same credential twice leaves the target
// with exactly the one credential (PUT semantics) — the basis for at-least-once
// outbox delivery.
func TestDeployIsIdempotent(t *testing.T) {
	ops := connector.NewMemoryOps()
	dep := connector.NewDeployment("edge-1:8443", sampleCert, sampleKey)
	c := dialConnector{name: "edge"}
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}
	if n := len(ops.Targets()); n != 1 {
		t.Errorf("after two deploys the target count = %d, want 1 (idempotent)", n)
	}
	got, _ := ops.Sent("edge-1:8443")
	if len(got) != len(sampleCert)+len(sampleKey) {
		t.Error("idempotent redeploy corrupted the target state")
	}
}

// TestRegistryHandleDecodesAndDeploys: the outbox handler body decodes a deploy
// payload and routes it to the named connector.
func TestRegistryHandleDecodesAndDeploys(t *testing.T) {
	ops := connector.NewMemoryOps()
	reg := connector.NewRegistry(func(string) connector.Ops { return ops })
	reg.Register(dialConnector{name: "edge"})

	payload, err := connector.EncodeDeploy("edge", connector.NewDeployment("edge-1:8443", sampleCert, sampleKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Handle(context.Background(), payload); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if _, ok := ops.Sent("edge-1:8443"); !ok {
		t.Error("registry did not route the deploy to the connector")
	}

	// Unknown connector is a clear error, not a silent drop.
	bad, _ := connector.EncodeDeploy("nope", connector.NewDeployment("t", sampleCert, sampleKey))
	if err := reg.Handle(context.Background(), bad); err == nil {
		t.Error("Handle for an unregistered connector should error")
	}
}

// erroringConnector always fails its deploy.
type erroringConnector struct{}

func (erroringConnector) Name() string { return "broken" }
func (erroringConnector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial)
}
func (erroringConnector) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	return errors.New("upstream exploded")
}

// noCapConnector requests no capabilities — not a valid least-privilege
// connector (it can do nothing).
type noCapConnector struct{}

func (noCapConnector) Name() string                   { return "nocap" }
func (noCapConnector) Capabilities() pluginhost.Grant { return pluginhost.NewGrant() }
func (noCapConnector) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	return nil
}

// TestConformanceFailsForBrokenOrPowerlessConnector: the suite catches a
// connector that errors on deploy and one that declares no capabilities.
func TestConformanceFailsForBrokenOrPowerlessConnector(t *testing.T) {
	if connector.Conformance(context.Background(), erroringConnector{}).OK() {
		t.Error("an erroring connector passed conformance")
	}
	if connector.Conformance(context.Background(), noCapConnector{}).OK() {
		t.Error("a connector with no declared capabilities passed conformance")
	}
}
