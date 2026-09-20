// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
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

type previewProbeConnector struct {
	previewed int
	deployed  int
}

func (*previewProbeConnector) Name() string { return "preview-probe" }
func (*previewProbeConnector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).WithPathPrefix(pluginhost.CapNetDial, "preview.example")
}
func (p *previewProbeConnector) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	p.deployed++
	return nil
}
func (p *previewProbeConnector) Preview(context.Context, connector.Sandbox, string) (connector.Preview, error) {
	p.previewed++
	return connector.Preview{
		Endpoint:    "https://preview.example",
		WouldMutate: []string{"replace the named certificate only after explicit deploy"},
		Detail:      "authenticated read-only target check passed",
	}, nil
}

func TestRegistryPreviewUsesExactFactoryContextWithoutDeploying(t *testing.T) {
	probe := &previewProbeConnector{}
	registry := connector.NewRegistry()
	var got connector.DeployPayload
	if err := registry.RegisterFactory("preview-probe", func(_ context.Context, payload connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
		got = payload
		return probe, connector.NewMemoryOps(), func() {}, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := connector.DeployPayload{
		TenantID: "tenant-a", TargetID: "target-a", TargetRevision: "revision-a",
		Connector: "preview-probe", Target: "payments edge",
		TargetConfig: []byte(`{"endpoint":"https://preview.example"}`),
	}
	plan, err := registry.Preview(context.Background(), request)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if probe.previewed != 1 || probe.deployed != 0 {
		t.Fatalf("preview calls=%d deploy calls=%d, want 1/0", probe.previewed, probe.deployed)
	}
	if got.TenantID != request.TenantID || got.TargetID != request.TargetID || got.TargetRevision != request.TargetRevision || string(got.TargetConfig) != string(request.TargetConfig) {
		t.Fatalf("factory context = %+v, want exact tenant/target/revision/config", got)
	}
	if plan.Endpoint == "" || len(plan.WouldMutate) == 0 || plan.Detail == "" {
		t.Fatalf("preview plan is not operator-usable: %+v", plan)
	}
}

func TestRegistryPreviewFailsClosedWhenConnectorHasNoZeroWriteContract(t *testing.T) {
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
	registry.Register(dialConnector{name: "edge"})
	_, err := registry.Preview(context.Background(), connector.DeployPayload{
		TenantID: "tenant-a", TargetID: "target-a", TargetRevision: "revision-a",
		Connector: "edge", Target: "edge-a",
	})
	if !errors.Is(err, connector.ErrPreviewUnsupported) {
		t.Fatalf("preview without contract error = %v, want ErrPreviewUnsupported", err)
	}
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

type postureProbeConnector struct {
	current   connector.TLSPosture
	mutations int
}

func (*postureProbeConnector) Name() string { return "posture-probe" }
func (*postureProbeConnector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial)
}
func (*postureProbeConnector) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	return nil
}
func (p *postureProbeConnector) ReadTLSPosture(context.Context, connector.Sandbox, string) (connector.TLSPosture, error) {
	return p.current, nil
}
func (p *postureProbeConnector) ApplyTLSPosture(_ context.Context, _ connector.Sandbox, _ string, desired connector.TLSPosture) error {
	p.current = desired
	p.mutations++
	return nil
}

func TestTLSPosturePreparedRetryPreservesOriginalAndRejectsDrift(t *testing.T) {
	legacy := connector.TLSPosture{
		MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
	desired := connector.TLSPosture{
		MinimumVersion: connector.TLSVersion13, CipherSuites: []string{"TLS_AES_256_GCM_SHA384"},
		KeyExchangeGroups: []string{"receiver-native-group", "X25519"},
	}
	probe := &postureProbeConnector{current: legacy}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
	registry.Register(probe)
	if err := registry.MarkTLSPostureCapable(probe.Name()); err != nil {
		t.Fatal(err)
	}
	mutation := connector.TLSPostureMutation{
		RunID: "run-a", FindingID: "finding-a", FindingKind: "protocol",
		TargetID: "target-a", TargetRevision: "revision-a", Connector: probe.Name(),
		Target: "listener-a", Desired: desired, ExpectedPrevious: &legacy, TenantID: "tenant-a",
	}
	first, err := registry.ApplyTLSPosture(context.Background(), mutation)
	if err != nil || !first.Applied || probe.mutations != 1 {
		t.Fatalf("first apply receipt=%+v mutations=%d err=%v", first, probe.mutations, err)
	}
	retry, err := registry.ApplyTLSPosture(context.Background(), mutation)
	if err != nil || retry.Applied || probe.mutations != 1 || !connector.EqualTLSPosture(retry.Previous, legacy) {
		t.Fatalf("ambiguous retry receipt=%+v mutations=%d err=%v", retry, probe.mutations, err)
	}
	probe.current = connector.TLSPosture{
		MinimumVersion: connector.TLSVersion12, CipherSuites: []string{"TLS_AES_128_GCM_SHA256"},
		KeyExchangeGroups: []string{"X25519"},
	}
	if _, err := registry.ApplyTLSPosture(context.Background(), mutation); err == nil {
		t.Fatal("prepared mutation overwrote receiver drift")
	}
	if probe.mutations != 1 {
		t.Fatalf("drift conflict still mutated receiver %d times", probe.mutations)
	}
}
