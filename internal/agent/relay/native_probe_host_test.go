// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
)

func nativeHostProbeFixture(t *testing.T) (executable, address string, certificate []byte) {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL unavailable")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, err := exec.Command(path, "list", "-signature-algorithms").Output() // #nosec G204 -- local stock test executable, fixed arguments.
	if err != nil || !strings.Contains(string(algorithms), "ML-DSA-65") {
		t.Skip("OpenSSL lacks ML-DSA-65")
	}
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "host readback test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pqc.GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	prepared, err := boundarycrypto.NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pqc.SignPQCLeafFromCSRWithPreparation(caDER, ca, key.CSRDER, 10*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	private, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(private)
	dir := t.TempDir()
	for name, data := range map[string][]byte{"leaf.pem": leafPEM, "ca.pem": caPEM, "key.pem": private} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address = listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	server := exec.CommandContext(ctx, path, "s_server", "-accept", address, "-cert", filepath.Join(dir, "leaf.pem"), "-cert_chain", filepath.Join(dir, "ca.pem"), "-key", filepath.Join(dir, "key.pem"), "-quiet", "-tls1_3", "-groups", "X25519") // #nosec G204 -- fixed stock command against owned loopback fixtures.
	server.Stdout, server.Stderr = io.Discard, io.Discard
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("native host test listener did not start")
	}
	return path, address, append(leafPEM, caPEM...)
}

func nativeHostProfileJSON(t *testing.T, root, executable string) string {
	t.Helper()
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command, err = filepath.EvalSymlinks(command)
	if err != nil {
		t.Fatal(err)
	}
	// This test performs only DryRunOnHost: the action is Lstatted, never run.
	profile := map[string]any{"allowed_roots": []string{root}, "actions": []map[string]any{{"logical_name": "nginx", "command": command, "pass_args": true}}}
	if executable != "" {
		profile["tls_probe_openssl"] = executable
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostProfileReadsPQCListenerDuringPreflight(t *testing.T) {
	executable, address, _ := nativeHostProbeFixture(t)
	root := t.TempDir()
	profile, err := LoadHostProfile(nativeHostProfileJSON(t, root, executable))
	if err != nil {
		t.Fatal(err)
	}
	target, err := json.Marshal(map[string]string{"cert_path": filepath.Join(root, "service.crt"), "key_path": filepath.Join(root, "service.key")})
	if err != nil {
		t.Fatal(err)
	}
	intent := DeployIntent{Connector: "nginx", Target: "host", TargetConfig: target, VerifyAddress: address, VerifyServerName: "api.example.test"}
	plan, err := DryRunOnHost(t.Context(), http.DefaultClient, profile, intent, nil)
	if err != nil || !plan.Ready {
		t.Fatalf("operator-authorized native preflight could not inspect the served certificate: %+v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(root, "service.crt")); !os.IsNotExist(err) {
		t.Fatal("read-only preflight changed the target")
	}
	// A remote target cannot turn on local process authority without the profile.
	without, err := LoadHostProfile(nativeHostProfileJSON(t, root, ""))
	if err != nil {
		t.Fatal(err)
	}
	target, err = json.Marshal(map[string]string{"cert_path": filepath.Join(root, "service.crt"), "key_path": filepath.Join(root, "service.key"), "tls_probe_openssl": executable})
	if err != nil {
		t.Fatal(err)
	}
	intent.TargetConfig = target
	plan, err = DryRunOnHost(t.Context(), http.DefaultClient, without, intent, nil)
	if err != nil || plan.Ready {
		t.Fatal("tenant target selected the native executable")
	}
}

func TestHostProfileRejectsInvalidNativeExecutable(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"openssl", filepath.Join(root, "missing"), root} {
		if _, err := LoadHostProfile(nativeHostProfileJSON(t, root, path)); err == nil {
			t.Fatalf("invalid native executable accepted: %q", path)
		}
	}
	file := filepath.Join(root, "not-executable")
	if err := os.WriteFile(file, []byte("public test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostProfile(nativeHostProfileJSON(t, root, file)); err == nil {
		t.Fatal("non-executable file accepted")
	}
}
