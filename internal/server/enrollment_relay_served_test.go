// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/agent/enrollproxy"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/mtls"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

const relayHelperEnvironment = "TRSTCTL_TEST_ENROLLMENT_RELAY_HELPER"

// TestEnrollmentRelayHelperProcess turns this test binary into one real relay
// process. The parent passes an already-bound listener as fd 3, so readiness
// cannot race another process for the port. It runs the production proxy and
// pool; the only test-only part is process assembly around them.
func TestEnrollmentRelayHelperProcess(t *testing.T) {
	if os.Getenv(relayHelperEnvironment) != "1" {
		return
	}
	listenerFile := os.NewFile(3, "enrollment-relay-listener")
	if listenerFile == nil {
		t.Fatal("relay helper has no inherited listener")
	}
	listener, err := net.FileListener(listenerFile)
	if err != nil {
		t.Fatalf("relay helper listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	caPEM, err := os.ReadFile(os.Getenv("TRSTCTL_TEST_RELAY_CA")) // #nosec G703 -- the parent test supplies a freshly created public-CA fixture path to this helper process (CWE-22).
	if err != nil {
		t.Fatalf("relay helper control-plane CA: %v", err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatalf("relay helper TLS transport: %v", err)
	}
	pool, err := enrollproxy.NewPoolWithPublicURL(
		[]string{os.Getenv("TRSTCTL_TEST_RELAY_UPSTREAM")},
		os.Getenv("TRSTCTL_TEST_RELAY_PUBLIC_URL"),
		&http.Client{Transport: transport, Timeout: 10 * time.Second},
		time.Second,
	)
	if err != nil {
		t.Fatalf("relay helper pool: %v", err)
	}
	server := &http.Server{Handler: pool, ReadHeaderTimeout: 5 * time.Second}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("relay helper serve: %v", err)
	}
}

type enrollmentRelayProcess struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
	log  *bytes.Buffer
}

func startEnrollmentRelayProcess(t *testing.T, upstream, publicURL, caPath string) (*enrollmentRelayProcess, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve relay listener: %v", err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		t.Fatal("relay listener is not TCP")
	}
	file, err := tcpListener.File()
	if err != nil {
		_ = listener.Close()
		t.Fatalf("duplicate relay listener: %v", err)
	}
	address := listener.Addr().String()

	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	logs := &bytes.Buffer{}
	cmd := exec.Command(binary, "-test.run=^TestEnrollmentRelayHelperProcess$") // #nosec G204 -- fixed current test binary and fixed test selector (CWE-78)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(os.Environ(),
		relayHelperEnvironment+"=1",
		"TRSTCTL_TEST_RELAY_UPSTREAM="+upstream,
		"TRSTCTL_TEST_RELAY_PUBLIC_URL="+publicURL,
		"TRSTCTL_TEST_RELAY_CA="+caPath,
	)
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		_ = file.Close()
		_ = listener.Close()
		t.Fatalf("start relay process: %v", err)
	}
	_ = file.Close()
	_ = listener.Close()
	process := &enrollmentRelayProcess{cmd: cmd, done: make(chan error, 1), log: logs}
	go func() { process.done <- cmd.Wait() }()
	t.Cleanup(func() { process.stop(t) })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return process, "http://" + address
		}
		select {
		case waitErr := <-process.done:
			t.Fatalf("relay process exited before readiness: %v\n%s", waitErr, logs.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.stop(t)
	t.Fatalf("relay process did not become ready at %s\n%s", address, logs.String())
	return nil, ""
}

func (p *enrollmentRelayProcess) stop(t *testing.T) {
	t.Helper()
	if p == nil {
		return
	}
	p.once.Do(func() {
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Errorf("relay process did not exit after kill\n%s", p.log.String())
		}
	})
}

type relayVIP struct {
	active atomic.Value // string relay URL
	counts sync.Map     // relay URL -> *atomic.Int64
}

func (v *relayVIP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target, _ := v.active.Load().(string)
	if target == "" {
		http.Error(w, "no relay selected", http.StatusServiceUnavailable)
		return
	}
	base, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid relay target", http.StatusBadGateway)
		return
	}
	value, _ := v.counts.LoadOrStore(target, &atomic.Int64{})
	value.(*atomic.Int64).Add(1)
	out := r.Clone(r.Context())
	out.URL.Scheme = base.Scheme
	out.URL.Host = base.Host
	out.RequestURI = ""
	resp, err := http.DefaultClient.Do(out)
	if err != nil {
		http.Error(w, "selected relay unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyHTTPHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (v *relayVIP) count(target string) int64 {
	value, ok := v.counts.Load(target)
	if !ok {
		return 0
	}
	return value.(*atomic.Int64).Load()
}

func copyHTTPHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type noDirectControlPlaneTransport struct {
	base        http.RoundTripper
	blockedHost string
	attempts    atomic.Int64
}

func (t *noDirectControlPlaneTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.EqualFold(r.URL.Host, t.blockedHost) {
		t.attempts.Add(1)
		return nil, fmt.Errorf("dark segment has no route to control plane %s", t.blockedHost)
	}
	return t.base.RoundTrip(r)
}

// The literal A4 acceptance: a stock RFC 8555 client uses one stable segment
// URL, registers through a primary relay PROCESS, loses that process, and
// finishes a real signer-backed order through a secondary relay PROCESS. Its
// transport rejects every direct control-plane dial, so leaked directory,
// account, order, authorization, challenge, finalize, or certificate URLs fail
// the test at the exact request where the relay path was escaped. AUD-122 adds
// the common protected-url equality check, so completing this whole stock-client
// journey also proves every relay forwarded the exact public URL the client signed.
func TestStockACMEClientCompletesThroughPrimaryAndSecondaryRelayProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL, NATS, signer, and two relay processes")
	}
	var challengeAddr string
	validatorTransport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, challengeAddr)
	}}
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{Client: &http.Client{Transport: validatorTransport, Timeout: 5 * time.Second}},
		DNS01:  acmesrv.DNS01Validator{},
	}
	h := newOperatingServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	controlPlane := httptest.NewTLSServer(h.srv.Handler())
	defer controlPlane.Close()
	caPath := filepath.Join(t.TempDir(), "control-plane-ca.pem")
	servedWriteTLSCertPEM(t, caPath, controlPlane)

	vipHandler := &relayVIP{}
	vip := httptest.NewTLSServer(vipHandler)
	defer vip.Close()
	primary, primaryURL := startEnrollmentRelayProcess(t, controlPlane.URL, vip.URL, caPath)
	secondary, secondaryURL := startEnrollmentRelayProcess(t, controlPlane.URL, vip.URL, caPath)
	vipHandler.active.Store(primaryURL)

	blocker := &noDirectControlPlaneTransport{
		base: vip.Client().Transport, blockedHost: strings.TrimPrefix(controlPlane.URL, "https://"),
	}
	client, err := acmekey.NewClient(vip.URL + "/directory")
	if err != nil {
		t.Fatalf("stock ACME client: %v", err)
	}
	client.HTTPClient = &http.Client{Transport: blocker, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatalf("discover through primary relay process: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register through primary relay process: %v", err)
	}
	if vipHandler.count(primaryURL) == 0 {
		t.Fatal("primary relay process forwarded no stock-client requests")
	}

	primary.stop(t)
	vipHandler.active.Store(secondaryURL)

	const domain = "relay-failover.served.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("new order through secondary relay process: %v", err)
	}
	mux := http.NewServeMux()
	challenge := httptest.NewServer(mux)
	defer challenge.Close()
	challengeAddr = strings.TrimPrefix(challenge.URL, "http://")
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			t.Fatalf("get authorization through secondary relay: %v", err)
		}
		var selected *xacme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate.Type == "http-01" {
				selected = candidate
				break
			}
		}
		if selected == nil {
			t.Fatal("served ACME offered no HTTP-01 challenge")
		}
		response, err := client.HTTP01ChallengeResponse(selected.Token)
		if err != nil {
			t.Fatalf("HTTP-01 response: %v", err)
		}
		mux.HandleFunc(client.HTTP01ChallengePath(selected.Token), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, response)
		})
		if _, err := client.Accept(ctx, selected); err != nil {
			t.Fatalf("accept challenge through secondary relay: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authorizationURL); err != nil {
			t.Fatalf("wait authorization through secondary relay: %v", err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("wait order through secondary relay: %v", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
	if err != nil {
		t.Fatalf("finalize through secondary relay: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("stock client received no certificate through secondary relay")
	}
	if err := crypto.VerifyLeafSignedByCA(chain[0], caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("relay-issued leaf does not verify against served CA: %v", err)
	}
	if vipHandler.count(secondaryURL) == 0 {
		t.Fatal("secondary relay process forwarded no stock-client requests after primary death")
	}
	if blocker.attempts.Load() != 0 {
		t.Fatalf("stock client attempted %d direct control-plane routes from the dark segment", blocker.attempts.Load())
	}
	secondary.stop(t)
}
