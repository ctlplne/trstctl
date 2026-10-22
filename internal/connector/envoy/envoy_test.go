// SPDX-License-Identifier: BUSL-1.1

package envoy_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/envoy/envoytest"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	envoyCert = []byte("-----BEGIN CERTIFICATE-----\nenvoy-leaf\n-----END CERTIFICATE-----\n")
	envoyKey  = []byte("-----BEGIN PRIVATE KEY-----\nenvoy-key\n-----END PRIVATE KEY-----\n")
	oldCert   = []byte("-----BEGIN CERTIFICATE-----\nold-envoy-leaf\n-----END CERTIFICATE-----\n")
	oldKey    = []byte("-----BEGIN PRIVATE KEY-----\nold-envoy-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployPushesSDSSecretIdempotentlyThroughRegistry(t *testing.T) {
	stub := envoytest.New()
	defer stub.Close()
	registry := observ.NewRegistry()
	conn := envoy.New(stub.URL(), "server_cert", envoy.WithMetrics(registry))
	ops := connector.NewHTTPOps(stub.Client())
	dep := connector.NewDeployment("edge/envoy", envoyCert, envoyKey)
	payload, err := connector.EncodeDeploy(conn.Name(), dep)
	if err != nil {
		t.Fatalf("encode deploy: %v", err)
	}
	r := connector.NewRegistry(func(string) connector.Ops { return ops })
	r.Register(conn)

	if err := r.Handle(context.Background(), payload); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	assertCurrent(t, stub, "server_cert", dep)
	if got := stub.Puts(); got != 1 {
		t.Fatalf("PUT count after first deploy = %d, want 1", got)
	}

	if err := r.Handle(context.Background(), payload); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	assertCurrent(t, stub, "server_cert", dep)
	if got := stub.Puts(); got != 1 {
		t.Fatalf("PUT count after idempotent deploy = %d, want 1", got)
	}
	if paths := stub.Paths(); hasWorkloadPath(paths) {
		t.Fatalf("Envoy connector must push SDS config, not call the SPIFFE Workload API: %v", paths)
	}

	var metrics bytes.Buffer
	if err := registry.WriteProm(&metrics); err != nil {
		t.Fatalf("render metrics: %v", err)
	}
	text := metrics.String()
	if !strings.Contains(text, `trstctl_envoy_deployments_total{target="edge/envoy",result="deployed"} 1`) {
		t.Fatalf("missing deployed counter in metrics:\n%s", text)
	}
	if !strings.Contains(text, `trstctl_envoy_deployments_total{target="edge/envoy",result="noop"} 1`) {
		t.Fatalf("missing noop counter in metrics:\n%s", text)
	}
}

func TestDeployRollsBackWhenSDSUpdateFailsAfterRemoteApply(t *testing.T) {
	stub := envoytest.New()
	defer stub.Close()
	stub.Seed("server_cert", connector.NewDeployment("edge/envoy", oldCert, oldKey))
	stub.FailNextPutAfterApply()
	conn := envoy.New(stub.URL(), "server_cert")
	dep := connector.NewDeployment("edge/envoy", envoyCert, envoyKey)

	_, err := connector.Run(context.Background(), conn, connector.NewHTTPOps(stub.Client()), dep)
	if err == nil {
		t.Fatal("expected failed SDS update, got nil")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("error = %q, want rollback context", err)
	}
	assertCurrent(t, stub, "server_cert", connector.NewDeployment("edge/envoy", oldCert, oldKey))
	if got := stub.Puts(); got != 2 {
		t.Fatalf("PUT count = %d, want failed update plus rollback", got)
	}
}

// An SDS management plane can echo the submitted secret on failure. The
// connector must drain that body without promoting the private key into an
// immutable error string.
func TestDeployRedactsSDSFailureBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.NotFound(w, r)
		case http.MethodPut:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(bytes.Join([][]byte{envoyCert, envoyKey}, []byte("|")))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	conn := envoy.New(srv.URL, "server_cert")
	_, err := connector.Run(context.Background(), conn, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("edge/envoy", envoyCert, envoyKey))
	if err == nil {
		t.Fatal("deploy succeeded despite SDS failure")
	}
	for _, forbidden := range []string{string(envoyCert), string(envoyKey)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error %q leaked the SDS secret", err)
		}
	}
}

func TestTLSPostureMutationReadsBackProtocolCipherAndGroup(t *testing.T) {
	legacy := connector.TLSPosture{
		MinimumVersion:    "TLSv1.0",
		CipherSuites:      []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
	emulator := envoytest.New()
	defer emulator.Close()
	emulator.SetPosture("edge-listener", legacy)
	conn := envoy.New(emulator.URL(), "server_cert")
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(emulator.Client()) })
	registry.Register(conn)
	if err := registry.MarkTLSPostureCapable("envoy"); err != nil {
		t.Fatal(err)
	}
	desired := connector.TLSPosture{
		MinimumVersion:    connector.TLSVersion13,
		CipherSuites:      []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		KeyExchangeGroups: []string{"receiver-native-group", "X25519"},
	}
	receipt, err := registry.ApplyTLSPosture(context.Background(), connector.TLSPostureMutation{
		RunID: "run-1", FindingID: "protocol-finding", FindingKind: "protocol",
		TargetID: "target-1", TargetRevision: "revision-1", Connector: "envoy",
		Target: "edge-listener", TenantID: "tenant-1", Desired: desired,
	})
	if err != nil {
		t.Fatalf("ApplyTLSPosture: %v", err)
	}
	if !receipt.Applied || !connector.EqualTLSPosture(receipt.Previous, legacy) || !connector.EqualTLSPosture(receipt.Observed, desired) {
		t.Fatalf("receipt = %#v, want exact prior and observed desired posture", receipt)
	}
	if got := emulator.Posture("edge-listener"); !connector.EqualTLSPosture(got, desired) {
		t.Fatalf("emulator posture = %#v, want %#v", got, desired)
	}
	if got := emulator.PosturePuts(); got != 1 {
		t.Fatalf("PUT count = %d, want one mutation", got)
	}
	noop, err := registry.ApplyTLSPosture(context.Background(), connector.TLSPostureMutation{
		RunID: "run-2", FindingID: "cipher-finding", FindingKind: "cipher",
		TargetID: "target-1", TargetRevision: "revision-1", Connector: "envoy",
		Target: "edge-listener", TenantID: "tenant-1", Desired: desired,
	})
	if err != nil {
		t.Fatalf("idempotent ApplyTLSPosture: %v", err)
	}
	if noop.Applied || emulator.PosturePuts() != 1 {
		t.Fatalf("idempotent receipt=%#v PUTs=%d, want no receiver mutation", noop, emulator.PosturePuts())
	}
}

func TestTLSPostureMutationRollsBackAndVerifiesReceiverMismatch(t *testing.T) {
	legacy := connector.TLSPosture{
		MinimumVersion:    "TLSv1.1",
		CipherSuites:      []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
	emulator := envoytest.New()
	defer emulator.Close()
	emulator.SetPosture("edge-listener", legacy)
	emulator.MismatchNextPostureApply()
	conn := envoy.New(emulator.URL(), "server_cert")
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(emulator.Client()) })
	registry.Register(conn)
	if err := registry.MarkTLSPostureCapable("envoy"); err != nil {
		t.Fatal(err)
	}
	_, err := registry.ApplyTLSPosture(context.Background(), connector.TLSPostureMutation{
		RunID: "run-rollback", FindingID: "cipher-finding", FindingKind: "cipher",
		TargetID: "target-1", TargetRevision: "revision-1", Connector: "envoy",
		Target: "edge-listener", TenantID: "tenant-1",
		Desired: connector.TLSPosture{
			MinimumVersion:    connector.TLSVersion13,
			CipherSuites:      []string{"TLS_AES_256_GCM_SHA384"},
			KeyExchangeGroups: []string{"receiver-native-group", "X25519"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "rollback verified") {
		t.Fatalf("error = %v, want verified rollback", err)
	}
	if got := emulator.Posture("edge-listener"); !connector.EqualTLSPosture(got, legacy) {
		t.Fatalf("post-failure posture = %#v, want exact legacy rollback %#v", got, legacy)
	}
	if got := emulator.PosturePuts(); got != 2 {
		t.Fatalf("PUT count = %d, want mismatched update plus rollback", got)
	}
}

func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	stub := envoytest.New()
	defer stub.Close()
	conn := envoy.New(stub.URL(), "server_cert")
	grant := conn.Capabilities()
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("Envoy SDS push connector must request net.dial")
	}
	if grant.Has(pluginhost.CapFSRead) || grant.Has(pluginhost.CapFSWrite) {
		t.Fatal("Envoy SDS push connector must not request file capabilities")
	}
	if grant.Has(connector.CapExec) {
		t.Fatal("Envoy SDS push connector must not request process.exec")
	}
	other, _ := http.NewRequest(http.MethodPut, "https://spiffe-workload.example/SPIFFEWorkloadAPI/FetchX509SVID", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Fatal("Envoy SDS push connector must scope net.dial to its configured SDS endpoint")
	}
}

// assertCurrent checks the double holds exactly the deployed material under
// name: the same fingerprint the control plane computed and the same PEM bytes.
func assertCurrent(t *testing.T, stub *envoytest.Server, name string, dep connector.Deployment) {
	t.Helper()
	got, ok := stub.Secret(name)
	if !ok {
		t.Fatalf("secret %q not stored", name)
	}
	if got.Name != name {
		t.Fatalf("secret name = %q, want %q", got.Name, name)
	}
	if got.Fingerprint != dep.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got.Fingerprint, dep.Fingerprint)
	}
	if !bytes.Equal(got.CertPEM, dep.CertPEM) {
		t.Fatal("stored certificate does not match deployed PEM")
	}
	if !bytes.Equal(got.KeyPEM, dep.KeyPEM) {
		t.Fatal("stored private key does not match deployed PEM")
	}
}

func hasWorkloadPath(paths []string) bool {
	for _, p := range paths {
		if strings.Contains(p, "SPIFFEWorkloadAPI") || strings.Contains(p, "FetchX509SVID") {
			return true
		}
	}
	return false
}
