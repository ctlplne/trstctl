// SPDX-License-Identifier: MPL-2.0

package envoy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/envoy"
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
	stub := newSDSStub(t)
	registry := observ.NewRegistry()
	conn := envoy.New(stub.URL(), "server_cert", envoy.WithMetrics(registry))
	ops := stub.Ops()
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
	stub.assertCurrent(t, "server_cert", dep)
	if got := stub.puts(); got != 1 {
		t.Fatalf("PUT count after first deploy = %d, want 1", got)
	}

	if err := r.Handle(context.Background(), payload); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	stub.assertCurrent(t, "server_cert", dep)
	if got := stub.puts(); got != 1 {
		t.Fatalf("PUT count after idempotent deploy = %d, want 1", got)
	}
	if paths := stub.paths(); hasWorkloadPath(paths) {
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
	stub := newSDSStub(t)
	stub.seed("server_cert", connector.NewDeployment("edge/envoy", oldCert, oldKey))
	stub.failNextPutAfterApply()
	conn := envoy.New(stub.URL(), "server_cert")
	dep := connector.NewDeployment("edge/envoy", envoyCert, envoyKey)

	_, err := connector.Run(context.Background(), conn, stub.Ops(), dep)
	if err == nil {
		t.Fatal("expected failed SDS update, got nil")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("error = %q, want rollback context", err)
	}
	stub.assertCurrent(t, "server_cert", connector.NewDeployment("edge/envoy", oldCert, oldKey))
	if got := stub.puts(); got != 2 {
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

func TestTLSPostureMutationReadsBackProtocolCipherAndHybridGroup(t *testing.T) {
	legacy := connector.TLSPosture{
		MinimumVersion:    "TLSv1.0",
		CipherSuites:      []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
	emulator := newPostureEmulator(t, legacy)
	conn := envoy.New(emulator.URL(), "server_cert")
	registry := connector.NewRegistry(func(string) connector.Ops { return emulator.Ops() })
	registry.Register(conn)
	if err := registry.MarkTLSPostureCapable("envoy"); err != nil {
		t.Fatal(err)
	}
	desired := connector.TLSPosture{
		MinimumVersion:    connector.TLSVersion13,
		CipherSuites:      []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"},
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
	if got := emulator.Current(); !connector.EqualTLSPosture(got, desired) {
		t.Fatalf("emulator posture = %#v, want %#v", got, desired)
	}
	if got := emulator.PutCount(); got != 1 {
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
	if noop.Applied || emulator.PutCount() != 1 {
		t.Fatalf("idempotent receipt=%#v PUTs=%d, want no receiver mutation", noop, emulator.PutCount())
	}
}

func TestTLSPostureMutationRollsBackAndVerifiesReceiverMismatch(t *testing.T) {
	legacy := connector.TLSPosture{
		MinimumVersion:    "TLSv1.1",
		CipherSuites:      []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
	emulator := newPostureEmulator(t, legacy)
	emulator.MismatchNextApply()
	conn := envoy.New(emulator.URL(), "server_cert")
	registry := connector.NewRegistry(func(string) connector.Ops { return emulator.Ops() })
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
			KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "rollback verified") {
		t.Fatalf("error = %v, want verified rollback", err)
	}
	if got := emulator.Current(); !connector.EqualTLSPosture(got, legacy) {
		t.Fatalf("post-failure posture = %#v, want exact legacy rollback %#v", got, legacy)
	}
	if got := emulator.PutCount(); got != 2 {
		t.Fatalf("PUT count = %d, want mismatched update plus rollback", got)
	}
}

func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	stub := newSDSStub(t)
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

type sdsStub struct {
	t              *testing.T
	mu             sync.Mutex
	secrets        map[string]sdsResource
	putCount       int
	seenPaths      []string
	failPutApplied bool
}

func newSDSStub(t *testing.T) *sdsStub {
	t.Helper()
	return &sdsStub{t: t, secrets: map[string]sdsResource{}}
}

func (s *sdsStub) URL() string { return "https://envoy-sds.test" }

func (s *sdsStub) Ops() connector.Ops { return sdsOps{stub: s} }

func (s *sdsStub) seed(name string, dep connector.Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[name] = resourceFromDeployment(name, dep)
}

func (s *sdsStub) failNextPutAfterApply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPutApplied = true
}

func (s *sdsStub) puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putCount
}

func (s *sdsStub) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seenPaths...)
}

func (s *sdsStub) assertCurrent(t *testing.T, name string, dep connector.Deployment) {
	t.Helper()
	s.mu.Lock()
	got, ok := s.secrets[name]
	s.mu.Unlock()
	if !ok {
		t.Fatalf("secret %q not stored", name)
	}
	want := resourceFromDeployment(name, dep)
	if got.Resources[0].Name != want.Resources[0].Name {
		t.Fatalf("secret name = %q, want %q", got.Resources[0].Name, want.Resources[0].Name)
	}
	if got.Resources[0].Fingerprint != want.Resources[0].Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got.Resources[0].Fingerprint, want.Resources[0].Fingerprint)
	}
	if !bytes.Equal(got.Resources[0].TLSCertificate.CertificateChain.InlineBytes, dep.CertPEM) {
		t.Fatal("stored certificate does not match deployed PEM")
	}
	if !bytes.Equal(got.Resources[0].TLSCertificate.PrivateKey.InlineBytes, dep.KeyPEM) {
		t.Fatal("stored private key does not match deployed PEM")
	}
}

func (s *sdsStub) handle(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/sds/secrets/")
	s.mu.Lock()
	s.seenPaths = append(s.seenPaths, r.URL.Path)
	s.mu.Unlock()
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "bad secret name", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		res, ok := s.secrets[name]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var res sdsResource
		if err := json.Unmarshal(body, &res); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.secrets[name] = res
		s.putCount++
		fail := s.failPutApplied
		s.failPutApplied = false
		s.mu.Unlock()
		if fail {
			http.Error(w, "applied but envoy rejected SDS ack", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type sdsOps struct {
	stub *sdsStub
}

var (
	_ connector.Ops       = sdsOps{}
	_ connector.Requester = sdsOps{}
)

func (o sdsOps) Request(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	o.stub.handle(rec, req)
	return rec.Result(), nil
}

func (o sdsOps) Send(string, []byte) error {
	return fmt.Errorf("envoy test SDS target does not support raw Send")
}

func (o sdsOps) WriteFile(string, []byte) error {
	return fmt.Errorf("envoy test SDS target does not support WriteFile")
}

func (o sdsOps) Exec(string, []string) error {
	return fmt.Errorf("envoy test SDS target does not support Exec")
}

func hasWorkloadPath(paths []string) bool {
	for _, p := range paths {
		if strings.Contains(strings.ToLower(p), "workload") || strings.Contains(strings.ToLower(p), "spiffe") {
			return true
		}
	}
	return false
}

func resourceFromDeployment(name string, dep connector.Deployment) sdsResource {
	return sdsResource{Resources: []sdsSecret{{
		Type:        "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		Name:        name,
		Fingerprint: dep.Fingerprint,
		TLSCertificate: tlsCertificate{
			CertificateChain: dataSource{InlineBytes: dep.CertPEM},
			PrivateKey:       dataSource{InlineBytes: dep.KeyPEM},
		},
	}}}
}

type sdsResource struct {
	Resources []sdsSecret `json:"resources"`
}

type sdsSecret struct {
	Type           string         `json:"@type"`
	Name           string         `json:"name"`
	Fingerprint    string         `json:"fingerprint"`
	TLSCertificate tlsCertificate `json:"tls_certificate"`
}

type tlsCertificate struct {
	CertificateChain dataSource `json:"certificate_chain"`
	PrivateKey       dataSource `json:"private_key"`
}

type dataSource struct {
	InlineBytes []byte `json:"inline_bytes"`
}

type postureEmulator struct {
	mu                sync.Mutex
	posture           connector.TLSPosture
	putCount          int
	mismatchNextApply bool
}

func newPostureEmulator(t *testing.T, initial connector.TLSPosture) *postureEmulator {
	t.Helper()
	return &postureEmulator{posture: initial}
}

func (e *postureEmulator) URL() string { return "https://envoy-posture.test" }

func (e *postureEmulator) Ops() connector.Ops { return postureOps{emulator: e} }

func (e *postureEmulator) Current() connector.TLSPosture {
	e.mu.Lock()
	defer e.mu.Unlock()
	return connector.TLSPosture{
		MinimumVersion:    e.posture.MinimumVersion,
		CipherSuites:      append([]string(nil), e.posture.CipherSuites...),
		KeyExchangeGroups: append([]string(nil), e.posture.KeyExchangeGroups...),
	}
}

func (e *postureEmulator) PutCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.putCount
}

func (e *postureEmulator) MismatchNextApply() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mismatchNextApply = true
}

func (e *postureEmulator) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/tls-posture/edge-listener" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(e.Current())
	case http.MethodPut:
		var desired connector.TLSPosture
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&desired); err != nil {
			http.Error(w, "bad posture", http.StatusBadRequest)
			return
		}
		e.mu.Lock()
		e.putCount++
		if e.mismatchNextApply {
			e.mismatchNextApply = false
			desired.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"}
		}
		e.posture = desired
		e.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type postureOps struct{ emulator *postureEmulator }

var (
	_ connector.Ops       = postureOps{}
	_ connector.Requester = postureOps{}
)

func (o postureOps) Request(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	o.emulator.handlePosture(rec, req)
	return rec.Result(), nil
}

func (postureOps) Send(string, []byte) error {
	return fmt.Errorf("posture emulator does not support Send")
}
func (postureOps) WriteFile(string, []byte) error {
	return fmt.Errorf("posture emulator does not support WriteFile")
}
func (postureOps) Exec(string, []string) error {
	return fmt.Errorf("posture emulator does not support Exec")
}
