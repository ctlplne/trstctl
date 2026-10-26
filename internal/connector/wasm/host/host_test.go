// SPDX-License-Identifier: BUSL-1.1

package host_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	"trstctl.com/trstctl/internal/connector/wasm/host"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	moduleOnce  sync.Once
	moduleBytes []byte
	moduleErr   error
)

// testModule builds the connector module from this tree once per test binary.
func testModule(t *testing.T) []byte {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the wasip1 connector module")
	}
	moduleOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
		out := filepath.Join(os.TempDir(), "trstctl-connector-module-test.wasm")
		cmd := exec.Command("go", "build", "-buildmode=c-shared", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", out, "./internal/connector/wasm/module") // #nosec G204 -- fixed toolchain and package; output confined to the temp dir (CWE-78).
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
		if msg, err := cmd.CombinedOutput(); err != nil {
			moduleErr = errors.New(string(msg))
			return
		}
		moduleBytes, moduleErr = os.ReadFile(out) // #nosec G304 -- the file this test just built (CWE-22).
		_ = os.Remove(out)
	})
	if moduleErr != nil {
		t.Fatalf("build connector module: %v", moduleErr)
	}
	return moduleBytes
}

func newRuntime(t *testing.T) *host.Runtime {
	t.Helper()
	rt, err := host.New(context.Background(), testModule(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

var familyTargets = map[string]string{
	"nginx": `{"profile":"p","cert_path":"/etc/nginx/tls.crt","key_path":"/etc/nginx/tls.key"}`, "apache": `{"profile":"p","cert_path":"/etc/apache/tls.crt","key_path":"/etc/apache/tls.key"}`,
	"caddy": `{"profile":"p","cert_path":"/etc/caddy/tls.crt","key_path":"/etc/caddy/tls.key"}`, "traefik": `{"profile":"p","cert_path":"/etc/traefik/tls.crt","key_path":"/etc/traefik/tls.key"}`,
	"postgresql": `{"profile":"p","cert_path":"/var/lib/pg/server.crt","key_path":"/var/lib/pg/server.key"}`, "mysql": `{"profile":"p","cert_path":"/etc/mysql/tls.crt","key_path":"/etc/mysql/tls.key"}`,
	"rabbitmq": `{"profile":"p","cert_path":"/etc/rabbitmq/tls.crt","key_path":"/etc/rabbitmq/tls.key"}`, "elasticsearch": `{"profile":"p","cert_path":"/etc/es/tls.crt","key_path":"/etc/es/tls.key"}`,
	"tomcat":                  `{"profile":"p","cert_path":"/opt/tomcat/tls.crt","key_path":"/opt/tomcat/tls.key"}`,
	"iis":                     `{"profile":"p","binding":"*:443:","import_dir":"C:/import"}`,
	"haproxy":                 `{"profile":"p","crt_path":"/etc/haproxy/tls.pem","config_path":"/etc/haproxy/haproxy.cfg"}`,
	"postfix":                 `{"profile":"p","postfix_cert_path":"/etc/postfix/c","postfix_key_path":"/etc/postfix/k","dovecot_cert_path":"/etc/dovecot/c","dovecot_key_path":"/etc/dovecot/k"}`,
	"java-keystore":           `{"profile":"p","keystore_path":"/opt/app/ks.p12","keystore_password_ref":"secret://ks","alias":"tls","format":"pkcs12"}`,
	"envoy":                   `{"endpoint":"https://sds.example.com","secret_name":"tls"}`,
	"a10":                     `{"endpoint":"https://a10.example.com","username":"admin","password_ref":"secret://a10"}`,
	"f5":                      `{"endpoint":"https://f5.example.com","client_ssl_profile":"cs","username":"admin","password_ref":"secret://f5"}`,
	"netscaler":               `{"endpoint":"https://ns.example.com","username":"admin","password_ref":"secret://ns"}`,
	"kemp":                    `{"endpoint":"https://kemp.example.com","token_ref":"secret://kemp"}`,
	"cisco":                   `{"endpoint":"https://cisco.example.com","username":"admin","password_ref":"secret://cisco"}`,
	"fortigate":               `{"endpoint":"https://fg.example.com","token_ref":"secret://fg"}`,
	"paloalto":                `{"endpoint":"https://pa.example.com","api_key_ref":"secret://pa"}`,
	"aws-acm":                 `{"endpoint":"https://acm.us-east-1.amazonaws.com","region":"us-east-1","access_key_id":"AKIDEXAMPLE","secret_access_key_ref":"secret://aws"}`,
	"azure-keyvault":          `{"endpoint":"https://vault.vault.azure.net","bearer_token_ref":"secret://az"}`,
	"gcp-certificate-manager": `{"endpoint":"https://certificatemanager.googleapis.com","project":"p","location":"global","bearer_token_ref":"secret://gcp"}`,
}

// build constructs family both ways: the host-built instance and its sandbox
// binding, with credentials recorded as native.Build resolved them.
func build(t *testing.T, rt *host.Runtime, family string) (connector.Connector, connector.Connector) {
	t.Helper()
	target, err := native.DecodeTarget(family, json.RawMessage(familyTargets[family]))
	if err != nil {
		t.Fatalf("%s: %v", family, err)
	}
	credentials := map[string][]byte{}
	built, _, err := native.Build(family, target, func(ref, _ string) ([]byte, error) {
		value := []byte("pw-" + strings.TrimPrefix(ref, "secret://"))
		credentials[ref] = value
		return value, nil
	})
	if err != nil {
		t.Fatalf("%s: build: %v", family, err)
	}
	bound, err := rt.Bind(built, family, target, credentials)
	if err != nil {
		t.Fatalf("%s: bind: %v", family, err)
	}
	return built, bound
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type effects struct {
	Files    map[string][]byte
	Execs    [][]string
	Targets  []string
	Requests map[string][]byte
}

func effectsOf(ops *connector.MemoryOps) effects {
	targets := ops.Targets()
	sort.Strings(targets)
	return effects{Files: ops.Files(), Execs: ops.Execs(), Targets: targets, Requests: ops.Requests()}
}

// A153: every shipped family deployed inside the sandbox has exactly the
// effects and the outcome it has in-process, against identical targets.
func TestEveryFamilyDeploysTheSameInsideTheSandbox(t *testing.T) {
	rt := newRuntime(t)
	cert, key := testCredential(t)
	dep := connector.NewDeployment("listener-1", cert, key)
	for family := range familyTargets {
		inProcess, sandboxed := build(t, rt, family)
		if sandboxed.Name() != inProcess.Name() || !reflect.DeepEqual(sandboxed.Capabilities().Capabilities(), inProcess.Capabilities().Capabilities()) {
			t.Fatalf("%s: the binding changed the name or grant", family)
		}
		directOps, boundOps := connector.NewMemoryOps(), connector.NewMemoryOps()
		directStats, directErr := connector.Run(context.Background(), inProcess, directOps, dep)
		boundStats, boundErr := connector.Run(context.Background(), sandboxed, boundOps, dep)
		if errText(directErr) != errText(boundErr) || directStats != boundStats {
			t.Fatalf("%s: in-process %v (%+v), sandboxed %v (%+v)", family, directErr, directStats, boundErr, boundStats)
		}
		if !reflect.DeepEqual(effectsOf(directOps), effectsOf(boundOps)) {
			t.Fatalf("%s: effects differ:\n in-process %+v\n sandboxed  %+v", family, effectsOf(directOps), effectsOf(boundOps))
		}
	}
}

// The binding exposes exactly the optional operations its family implements.
func TestBindingsExposeTheFamilysOperations(t *testing.T) {
	rt := newRuntime(t)
	type probe struct {
		name string
		has  func(connector.Connector) bool
	}
	probes := []probe{
		{"readback", func(c connector.Connector) bool { _, ok := c.(connector.Readbacker); return ok }},
		{"preview", func(c connector.Connector) bool { _, ok := c.(connector.Previewer); return ok }},
		{"rollback", func(c connector.Connector) bool { _, ok := c.(connector.Rollbacker); return ok }},
		{"legacy rollback", func(c connector.Connector) bool { _, ok := c.(connector.LegacyRollbacker); return ok }},
		{"takedown", func(c connector.Connector) bool { _, ok := c.(connector.Takedowner); return ok }},
		{"tls posture", func(c connector.Connector) bool { _, ok := c.(connector.TLSPostureConnector); return ok }},
		{"appliance key", func(c connector.Connector) bool { _, ok := c.(connector.ApplianceKeyGenerator); return ok }},
	}
	for family := range familyTargets {
		inProcess, sandboxed := build(t, rt, family)
		for _, p := range probes {
			if p.has(inProcess) != p.has(sandboxed) {
				t.Errorf("%s: %s in-process=%t sandboxed=%t", family, p.name, p.has(inProcess), p.has(sandboxed))
			}
		}
	}
}

// Optional operations cross too, with their results and sentinel errors.
func TestOptionalOperationsCrossTheBoundary(t *testing.T) {
	rt := newRuntime(t)
	for _, family := range []string{"f5", "kemp", "a10", "netscaler", "fortigate", "cisco", "paloalto", "gcp-certificate-manager"} {
		inProcess, sandboxed := build(t, rt, family)
		rb := connector.Rollback{Target: "listener-1", PredecessorFingerprint: strings.Repeat("ab", 32), Reason: "test"}
		_, directErr := connector.RunRollback(context.Background(), inProcess, connector.NewMemoryOps(), rb)
		_, boundErr := connector.RunRollback(context.Background(), sandboxed, connector.NewMemoryOps(), rb)
		if errText(directErr) != errText(boundErr) {
			t.Fatalf("%s rollback: in-process %v, sandboxed %v", family, directErr, boundErr)
		}
		for _, sentinel := range []error{connector.ErrNoPredecessorInstalled, connector.ErrRollbackNotConfigured, connector.ErrDenied} {
			if errors.Is(directErr, sentinel) != errors.Is(boundErr, sentinel) {
				t.Fatalf("%s rollback: sentinel %v lost across the boundary (%v)", family, sentinel, boundErr)
			}
		}
		installedA, errA := connector.RunReadback(context.Background(), inProcess, connector.NewMemoryOps(), "listener-1")
		installedB, errB := connector.RunReadback(context.Background(), sandboxed, connector.NewMemoryOps(), "listener-1")
		if errText(errA) != errText(errB) || installedA != installedB {
			t.Fatalf("%s readback: in-process %+v %v, sandboxed %+v %v", family, installedA, errA, installedB, errB)
		}
	}
}

// An operation outside the grant is refused by the host, and the refusal keeps
// its identity inside and outside the module.
func TestGrantIsEnforcedOnTheHostSide(t *testing.T) {
	rt := newRuntime(t)
	inProcess, sandboxed := build(t, rt, "nginx")
	cert, key := testCredential(t)
	dep := connector.NewDeployment("x", cert, key)
	ops := connector.NewMemoryOps()
	stats, err := connector.Run(context.Background(), narrowed{sandboxed, pluginhost.NewGrant(pluginhost.CapFSRead)}, ops, dep)
	if !errors.Is(err, connector.ErrDenied) || stats.Denied == 0 || len(ops.Files()) != 0 {
		t.Fatalf("a write outside the grant from inside the module = %v (%+v), want ErrDenied and no file", err, stats)
	}
	if _, direct := connector.Run(context.Background(), narrowed{inProcess, pluginhost.NewGrant(pluginhost.CapFSRead)}, connector.NewMemoryOps(), dep); errText(direct) != errText(err) {
		t.Fatalf("in-process %v, sandboxed %v", direct, err)
	}
}

// A cancelled operation ends the instance instead of letting it run on.
func TestCancelledOperationStops(t *testing.T) {
	rt := newRuntime(t)
	_, sandboxed := build(t, rt, "f5")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	cert, key := testCredential(t)
	start := time.Now()
	_, err := connector.Run(ctx, sandboxed, blockingOps{release: ctx.Done()}, connector.NewDeployment("listener-1", cert, key))
	if err == nil || time.Since(start) > 20*time.Second {
		t.Fatalf("cancelled deploy = %v after %s", err, time.Since(start))
	}
}

// narrowed is a connector whose grant is narrower than its family declares.
type narrowed struct {
	connector.Connector
	grant pluginhost.Grant
}

func (n narrowed) Capabilities() pluginhost.Grant { return n.grant }

// blockingOps holds every HTTP request until release closes.
type blockingOps struct{ release <-chan struct{} }

func (blockingOps) Send(string, []byte) error      { return nil }
func (blockingOps) WriteFile(string, []byte) error { return nil }
func (blockingOps) Exec(string, []string) error    { return nil }
func (b blockingOps) Request(*http.Request) (*http.Response, error) {
	<-b.release
	return nil, context.Canceled
}

// testCredential is a real certificate and key, for families that parse them.
func testCredential(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, "sandbox.example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return crypto.EncodeCertificatePEM(der), keyPEM
}

// os.IsNotExist and its siblings recognize only concrete filesystem error types,
// so an error rebuilt on the other side of the sandbox never satisfies them.
// Connector families test sandbox errors with errors.Is instead.
func TestConnectorFamiliesUseErrorsIsForFilesystemErrors(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	sources, err := filepath.Glob(filepath.Join(root, "*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		data, err := os.ReadFile(source) // #nosec G304 -- this repository's own connector sources (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		for _, predicate := range []string{"os.IsNotExist(", "os.IsExist(", "os.IsPermission(", "os.IsTimeout("} {
			if strings.Contains(string(data), predicate) {
				t.Errorf("%s uses %s, which an error crossing the connector sandbox never satisfies; use errors.Is", source, predicate)
			}
		}
	}
}

// The embedded module is the one this tree builds: a connector change without
// `make connector-wasm` would ship the previous connectors in the sandbox.
func TestEmbeddedModuleMatchesTheTree(t *testing.T) {
	if got, want := crypto.SHA256Hex(testModule(t)), host.BuiltinDigest(); got != want {
		t.Fatalf("embedded connector module is stale (tree builds %s, binary embeds %s); run `make connector-wasm` and commit", got, want)
	}
	rt, err := host.Builtin()
	if err != nil {
		t.Fatalf("load embedded module: %v", err)
	}
	if rt.Digest() != host.BuiltinDigest() {
		t.Fatalf("runtime digest %s, want %s", rt.Digest(), host.BuiltinDigest())
	}
}

// The module's only imports are the connector host functions and the WASI
// functions the Go runtime links — no socket; and since the host preopens no
// directory, no path a WASI file call names resolves.
func TestModuleImportsOnlyTheHostAndWASI(t *testing.T) {
	imports, err := host.ModuleImports(context.Background(), testModule(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) == 0 {
		t.Fatal("found no imports; the module cannot reach its host")
	}
	for _, imp := range imports {
		module, name, _ := strings.Cut(imp, ".")
		switch {
		case module == "trstctl_connector_host":
		case module == "wasi_snapshot_preview1" && !strings.HasPrefix(name, "sock_"):
		default:
			t.Errorf("the connector module imports %s", imp)
		}
	}
}
