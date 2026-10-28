// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// The SPIRE server build the plugin is proven against (CI's SPIRE e2e uses the
// same release).
const a205SPIREServerImage = "ghcr.io/spiffe/spire-server:1.15.1@sha256:abfb368f538557646d5eb138ab0854361b79fa5ae36243ca5efe378dcbe85d61"

const a205SPIRESocket = "/tmp/spire-server/private/api.sock"

// TestTwoSPIREServersVerifyEachOthersJWTSVIDsThroughTrstctl is A205: two SPIRE
// servers of one trust domain, in containers, run the trstctl upstream
// authority plugin against the served API. Each publishes its JWT signing key
// to POST /api/v1/spiffe/upstream-jwt-keys and adds every key trstctl returns
// to its bundle, so a JWT-SVID minted by one server verifies with the other's
// bundle, both ways. Each server's X.509 CA is signed by the served CA
// hierarchy: the served intermediate route requires a ceremony per CSR, so a
// test desk in front of it opens one for SPIRE's CSR and has two other
// custodians approve it, as operators would.
func TestTwoSPIREServersVerifyEachOthersJWTSVIDsThroughTrstctl(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a205SPIREServerImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned SPIRE server image is not present locally: %v\n%s", err, out)
	}
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	scopes := []string{"issuers:write", "issuers:read", "certs:issue"}
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "spire-upstream", scopes)
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "spire-custodian-one", scopes)
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "spire-custodian-two", scopes)
	rootSpec := map[string]any{
		"common_name":           "trstctl SPIRE upstream root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.org"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "a205-root-ceremony")
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "a205-root-approval")
	root := createRootCA(t, h, operator, ceremony.ID, rootSpec, "a205-root")

	desk := &spireCeremonyDesk{
		base: h.ts.URL, client: h.ts.Client(), next: h.ts.Config.Handler, rootID: root.ID,
		operator: operator, approvers: [2]string{approverOne, approverTwo},
	}
	endpoint, trustPEM := serveSPIREUpstreamForContainers(t, desk)
	plugin := buildSPIREPluginForContainers(t)

	a := startSPIREServerContainer(t, "a", endpoint, trustPEM, operator, root.ID, plugin)
	b := startSPIREServerContainer(t, "b", endpoint, trustPEM, operator, root.ID, plugin)

	// Each bundle carries both servers' JWT authorities once trstctl has
	// returned them (the subscription refreshes every second here).
	var jwksA, jwksB crypto.JWKS
	deadline := time.Now().Add(90 * time.Second)
	for {
		jwksA, jwksB = spireBundleJWKS(t, a), spireBundleJWKS(t, b)
		if len(jwtKeyIDs(jwksA)) >= 2 && sameKeyIDs(jwtKeyIDs(jwksA), jwtKeyIDs(jwksB)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the bundles did not converge on both JWT authorities: a=%v b=%v\nlogs a:\n%s\nlogs b:\n%s",
				jwtKeyIDs(jwksA), jwtKeyIDs(jwksB), dockerLogs(a), dockerLogs(b))
		}
		time.Sleep(time.Second)
	}

	tokenA := spireMintJWT(t, a, "spiffe://example.org/payments")
	tokenB := spireMintJWT(t, b, "spiffe://example.org/ledger")
	for _, c := range []struct {
		name, token, subject string
		jwks                 crypto.JWKS
	}{
		{"a's JWT-SVID with b's bundle", tokenA, "spiffe://example.org/payments", jwksB},
		{"b's JWT-SVID with a's bundle", tokenB, "spiffe://example.org/ledger", jwksA},
	} {
		claimsJSON, err := crypto.VerifyJWT(c.token, c.jwks)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var claims struct {
			Sub string `json:"sub"`
			Aud any    `json:"aud"`
		}
		if err := json.Unmarshal(claimsJSON, &claims); err != nil || claims.Sub != c.subject {
			t.Fatalf("%s claims = %s", c.name, claimsJSON)
		}
	}

	// trstctl holds both servers' keys, and each X.509 CA came from the served
	// hierarchy after its ceremony.
	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/spiffe/upstream-jwt-keys", operator, "", nil)
	var listed struct {
		Items []struct {
			KeyID       string `json:"key_id"`
			PublishedBy string `json:"published_by"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) < 2 {
		t.Fatalf("trstctl's published keys = %d %s", status, body)
	}
	for _, item := range listed.Items {
		if item.PublishedBy != "spire-upstream" {
			t.Fatalf("key %s published by %q", item.KeyID, item.PublishedBy)
		}
	}
	if signed := desk.signedCount(); signed < 2 {
		t.Fatalf("the served hierarchy signed %d SPIRE CAs, want one per server", signed)
	}
	t.Logf("A205_SPIRE_JWT_OK keys=%v intermediates=%d", jwtKeyIDs(jwksA), desk.signedCount())
}

// spireCeremonyDesk stands in for the custodians in front of the served
// intermediate route: for each SPIRE CSR it opens an issue_intermediate_csr
// ceremony through the API, two other custodians approve it, and the request
// goes on with the ceremony's ID. Everything else passes straight through.
type spireCeremonyDesk struct {
	base      string
	client    *http.Client
	next      http.Handler
	rootID    string
	operator  string
	approvers [2]string

	mu     sync.Mutex
	signed int
}

func (d *spireCeremonyDesk) signedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signed
}

func (d *spireCeremonyDesk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ca/authorities/"+d.rootID+"/intermediates/csr" {
		d.next.ServeHTTP(w, r)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]any
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ceremonyID, err := d.openCeremony(r.Context(), req)
	if err != nil {
		http.Error(w, "ceremony desk: "+err.Error(), http.StatusBadGateway)
		return
	}
	req["ceremony_id"] = ceremonyID
	forwarded, _ := json.Marshal(req)
	r.Body = io.NopCloser(bytes.NewReader(forwarded))
	r.ContentLength = int64(len(forwarded))
	rec := httptest.NewRecorder()
	d.next.ServeHTTP(rec, r)
	if rec.Code == http.StatusCreated {
		d.mu.Lock()
		d.signed++
		d.mu.Unlock()
	}
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (d *spireCeremonyDesk) openCeremony(ctx context.Context, req map[string]any) (string, error) {
	csrPEM, _ := req["csr_pem"].(string)
	digest := crypto.SHA256Hex([]byte(csrPEM))
	created, err := d.call(ctx, d.operator, "/api/v1/ca/ceremonies", "a205-desk-"+digest, map[string]any{
		"operation": "issue_intermediate_csr", "parent_id": d.rootID, "csr_pem": csrPEM,
		"threshold": 2, "spec": req["spec"],
	}, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var ceremony struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created, &ceremony); err != nil || ceremony.ID == "" {
		return "", fmt.Errorf("decode ceremony: %v %s", err, created)
	}
	for i, approver := range d.approvers {
		if _, err := d.call(ctx, approver, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals",
			fmt.Sprintf("a205-desk-approval-%d-%s", i, digest), nil, http.StatusOK); err != nil {
			return "", err
		}
	}
	return ceremony.ID, nil
}

func (d *spireCeremonyDesk) call(ctx context.Context, token, path, idem string, body any, want int) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", idem)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req) // #nosec G704 -- test calls its own served harness (CWE-918)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return nil, fmt.Errorf("%s = %d %s", path, resp.StatusCode, out)
	}
	return out, nil
}

// serveSPIREUpstreamForContainers serves handler over TLS on every interface
// with a certificate for host.docker.internal, the name the containers use.
func serveSPIREUpstreamForContainers(t *testing.T, handler http.Handler) (string, []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- the test's containers reach the served API through the Docker host gateway (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mtls.SelfSignedServerCert([]string{"host.docker.internal"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = cert.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "https://host.docker.internal:" + port, append([]byte(nil), cert.TrustPEM...)
}

func buildSPIREPluginForContainers(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "trstctl-spire-upstream-authority")
	arch := runtime.GOARCH
	if info, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output(); err == nil {
		switch strings.TrimSpace(string(info)) {
		case "x86_64", "amd64":
			arch = "amd64"
		case "aarch64", "arm64":
			arch = "arm64"
		}
	}
	cmd := exec.Command("go", "build", "-o", out, "trstctl.com/trstctl/cmd/trstctl-spire-upstream-authority") // #nosec G204 -- test builds the repository's own plugin (CWE-78)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if built, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the Linux SPIRE upstream authority plugin: %v\n%s", err, built)
	}
	return dir
}

// startSPIREServerContainer runs one SPIRE server with the trstctl upstream
// authority and returns its container name once it is healthy.
func startSPIREServerContainer(t *testing.T, name, endpoint string, trustPEM []byte, token, rootID, pluginDir string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "trstctl-a205-"+name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	confDir, dataDir := filepath.Join(dir, "conf"), filepath.Join(dir, "data")
	for _, d := range []string{confDir, dataDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for file, content := range map[string][]byte{
		"trstctl-token":  []byte(token + "\n"),
		"trstctl-ca.pem": trustPEM,
		"server.conf":    []byte(a205SPIREServerConfig(endpoint, rootID)),
	} {
		if err := os.WriteFile(filepath.Join(confDir, file), content, 0o600); err != nil { // #nosec G703 -- test writes into its own temp directory (CWE-22)
			t.Fatal(err)
		}
	}
	container := "trstctl-a205-" + name + "-" + strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano()))
	out, err := exec.Command("docker", "run", "-d", "--name", container, // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,mode=0700,uid=%d,gid=%d", os.Getuid(), os.Getgid()),
		"--add-host", "host.docker.internal:host-gateway",
		"-v", confDir+":/opt/spire/conf/server:ro",
		"-v", pluginDir+":/opt/spire/plugins:ro",
		"-v", dataDir+":/opt/spire/data/server",
		a205SPIREServerImage, "-config", "/opt/spire/conf/server/server.conf").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run SPIRE server %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() }) // #nosec G204 -- test removes the container it started (CWE-78)
	deadline := time.Now().Add(90 * time.Second)
	for {
		check := exec.Command("docker", "exec", container, "/opt/spire/bin/spire-server", "healthcheck", "-shallow", "-socketPath", a205SPIRESocket) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		if check.Run() == nil {
			return container
		}
		if time.Now().After(deadline) {
			t.Fatalf("SPIRE server %s did not become healthy:\n%s", name, dockerLogs(container))
		}
		time.Sleep(time.Second)
	}
}

func a205SPIREServerConfig(endpoint, rootID string) string {
	return fmt.Sprintf(`
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "/opt/spire/data/server"
    socket_path = %q
    ca_ttl = "1h"
    default_x509_svid_ttl = "5m"
    default_jwt_svid_ttl = "5m"
    log_level = "DEBUG"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/opt/spire/data/server/datastore.sqlite3"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "memory" {
        plugin_data = {}
    }
    UpstreamAuthority "trstctl" {
        plugin_cmd = "/opt/spire/plugins/trstctl-spire-upstream-authority"
        plugin_data {
            endpoint = %q
            ca_bundle_file = "/opt/spire/conf/server/trstctl-ca.pem"
            allow_private_cidrs = ["172.16.0.0/12", "192.168.0.0/16"]
            ca_authority_id = %q
            token_file = "/opt/spire/conf/server/trstctl-token"
            common_name = "SPIRE Server CA"
            ttl_seconds = 3600
            max_path_len = 0
            permitted_dns_domains = ["example.org"]
            jwt_key_refresh_seconds = 1
        }
    }
}
`, a205SPIRESocket, endpoint, rootID)
}

func spireBundleJWKS(t *testing.T, container string) crypto.JWKS {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "/opt/spire/bin/spire-server", "bundle", "show", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-format", "spiffe", "-socketPath", a205SPIRESocket).Output()
	if err != nil {
		t.Fatalf("bundle show on %s: %v", container, err)
	}
	jwks, err := crypto.ParseJWKS(out)
	if err != nil {
		t.Fatalf("parse %s's bundle: %v\n%s", container, err, out)
	}
	return jwks
}

// jwtKeyIDs are the bundle's JWT authorities (SPIFFE bundles mark them
// use=jwt-svid).
func jwtKeyIDs(jwks crypto.JWKS) []string {
	var ids []string
	for _, key := range jwks.Keys {
		if key.Use == "jwt-svid" {
			ids = append(ids, key.Kid)
		}
	}
	return ids
}

func sameKeyIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range a {
		seen[id] = true
	}
	for _, id := range b {
		if !seen[id] {
			return false
		}
	}
	return true
}

func spireMintJWT(t *testing.T, container, spiffeID string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "/opt/spire/bin/spire-server", "jwt", "mint", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-spiffeID", spiffeID, "-audience", "a205", "-socketPath", a205SPIRESocket).CombinedOutput()
	if err != nil {
		t.Fatalf("jwt mint on %s: %v\n%s", container, err, out)
	}
	return strings.TrimSpace(string(out))
}

func dockerLogs(container string) string {
	out, _ := exec.Command("docker", "logs", "--tail", "60", container).CombinedOutput() // #nosec G204 -- test reads its own container's logs (CWE-78)
	return string(out)
}
