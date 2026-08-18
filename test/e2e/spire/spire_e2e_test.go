// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package spire

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const spireServerSocket = "/tmp/spire-server/private/api.sock"

func TestSPIREServerMintsSVIDChainedToTrstctlUpstreamAuthority(t *testing.T) {
	if os.Getenv("TRSTCTL_RUN_SPIRE_E2E") != "1" {
		t.Skip("set TRSTCTL_RUN_SPIRE_E2E=1 to run the SPIRE server container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	rootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(rootKey, crypto.HierarchyCAProfile{
		CommonName:          "trstctl SPIRE e2e root",
		PermittedDNSDomains: []string{"example.org"},
		MaxPathLen:          1,
		TTL:                 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	trstctlHTTP, trstctlTrustPEM, closeHTTP := serveFakeTrstctlIntermediateCSR(t, rootKey, root)
	t.Cleanup(closeHTTP)

	dir := t.TempDir()
	confDir := mkdir(t, filepath.Join(dir, "conf"))
	pluginDir := mkdir(t, filepath.Join(dir, "plugins"))
	dataDir := mkdir(t, filepath.Join(dir, "data"))
	outDir := mkdir(t, filepath.Join(dir, "out"))
	pluginPath := filepath.Join(pluginDir, "trstctl-spire-upstream-authority")
	buildPluginForDocker(t, ctx, pluginPath)
	writeFile(t, filepath.Join(confDir, "trstctl-token"), []byte("e2e-token\n"), 0o600)
	writeFile(t, filepath.Join(confDir, "trstctl-ca.pem"), trstctlTrustPEM, 0o600)
	writeFile(t, filepath.Join(confDir, "server.conf"), []byte(spireServerConfig(trstctlHTTP)), 0o600)

	name := "trstctl-spire-e2e-" + strings.ToLower(randomSuffix())
	// Keep an early-exiting container long enough for waitForSPIREServer to
	// collect its logs. The cleanup below still removes the run-owned container.
	run(t, ctx, "docker", "run", "-d",
		"--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"-v", confDir+":/opt/spire/conf/server:ro",
		"-v", pluginDir+":/opt/spire/plugins:ro",
		"-v", dataDir+":/opt/spire/data/server",
		"-v", outDir+":/tmp/out",
		"ghcr.io/spiffe/spire-server:1.15.1",
		"-config", "/opt/spire/conf/server/server.conf")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		_ = exec.CommandContext(stopCtx, "docker", "rm", "-f", name).Run()
	})

	waitForSPIREServer(t, ctx, name)
	run(t, ctx, "docker", "exec", name,
		"/opt/spire/bin/spire-server", "x509", "mint",
		"-socketPath", spireServerSocket,
		"-spiffeID", "spiffe://example.org/workload",
		"-ttl", "60s",
		"-write", "/tmp/out")

	svidPEM := readFile(t, filepath.Join(outDir, "svid.pem"))
	bundlePEM := readFile(t, filepath.Join(outDir, "bundle.pem"))
	svidChain := pemCerts(t, svidPEM)
	bundle := pemCerts(t, bundlePEM)
	if len(svidChain) < 2 {
		t.Fatalf("SPIRE SVID chain has %d cert(s), want leaf + SPIRE intermediate signed by trstctl", len(svidChain))
	}
	if len(bundle) != 1 {
		t.Fatalf("SPIRE bundle has %d root(s), want the trstctl root", len(bundle))
	}
	id, err := crypto.SPIFFEIDFromCert(svidChain[0])
	if err != nil {
		t.Fatalf("SVID has no SPIFFE ID: %v", err)
	}
	if id != "spiffe://example.org/workload" {
		t.Fatalf("SVID ID = %q, want spiffe://example.org/workload", id)
	}
	if err := crypto.VerifyLeafSignedByCA(svidChain[0], svidChain[1]); err != nil {
		t.Fatalf("SPIRE SVID does not chain to SPIRE intermediate: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(svidChain[1], root.CertificateDER); err != nil {
		t.Fatalf("SPIRE intermediate does not chain to trstctl root: %v", err)
	}
	if string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bundle[0]})) != string(root.CertificatePEM) {
		t.Fatal("SPIRE upstream bundle is not the trstctl root returned by the upstream-authority plugin")
	}
}

func serveFakeTrstctlIntermediateCSR(t *testing.T, rootKey crypto.DigestSigner, root crypto.IssuedHierarchyCA) (string, []byte, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ca/authorities/root-1/intermediates/csr", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer e2e-token" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Idempotency-Key"); !strings.HasPrefix(got, "spire-upstream-root-1-") {
			http.Error(w, "missing idempotency key", http.StatusBadRequest)
			return
		}
		var body struct {
			CSRPem string `json:"csr_pem"`
			Spec   struct {
				CommonName string `json:"common_name"`
				TTLSeconds int64  `json:"ttl_seconds"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(body.CSRPem))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			http.Error(w, "missing CSR PEM", http.StatusBadRequest)
			return
		}
		issued, err := crypto.SignIntermediateHierarchyCAFromCSR(root.CertificateDER, rootKey, block.Bytes, crypto.HierarchyCAProfile{
			CommonName:          body.Spec.CommonName,
			PermittedDNSDomains: []string{"example.org"},
			MaxPathLen:          0,
			TTL:                 time.Duration(body.Spec.TTLSeconds) * time.Second,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		chain := append([]byte{}, issued.CertificatePEM...)
		chain = append(chain, root.CertificatePEM...)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate_pem": string(chain),
			"serial":          issued.Serial,
			"not_after":       issued.NotAfter.UTC().Format(time.RFC3339),
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serverCert, err := mtls.SelfSignedServerCert([]string{"host.docker.internal"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serverCert.ServeHTTPS(srv, ln) }()
	closeFn := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://host.docker.internal:" + port, append([]byte(nil), serverCert.TrustPEM...), closeFn
}

func buildPluginForDocker(t *testing.T, ctx context.Context, out string) {
	t.Helper()
	arch := dockerGoArch(t, ctx)
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "trstctl.com/trstctl/cmd/trstctl-spire-upstream-authority")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Linux SPIRE upstream-authority plugin: %v\n%s", err, out)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
}

func dockerGoArch(t *testing.T, ctx context.Context) string {
	t.Helper()
	out := run(t, ctx, "docker", "info", "--format", "{{.Architecture}}")
	switch strings.TrimSpace(string(out)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func spireServerConfig(endpoint string) string {
	return fmt.Sprintf(`
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "/opt/spire/data/server"
    socket_path = "`+spireServerSocket+`"
    ca_ttl = "1h"
    default_x509_svid_ttl = "5m"
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
            ca_authority_id = "root-1"
            token_file = "/opt/spire/conf/server/trstctl-token"
            common_name = "SPIRE Server CA"
            ttl_seconds = 3600
            max_path_len = 0
            permitted_dns_domains = ["example.org"]
        }
    }
}
`, endpoint)
}

func waitForSPIREServer(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, "docker", "exec", name, "/opt/spire/bin/spire-server", "healthcheck", "-shallow", "-socketPath", spireServerSocket)
		out, err := cmd.CombinedOutput()
		last = out
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	logs := run(t, ctx, "docker", "logs", name)
	t.Fatalf("SPIRE server did not become ready; last healthcheck output:\n%s\nlogs:\n%s", last, logs)
}

func run(t *testing.T, ctx context.Context, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func mkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pemCerts(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var certs [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, append([]byte(nil), block.Bytes...))
		}
	}
	if len(certs) == 0 {
		t.Fatal("no CERTIFICATE PEM blocks found")
	}
	return certs
}

func randomSuffix() string {
	return strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
}
