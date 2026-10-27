// SPDX-License-Identifier: BUSL-1.1

package wrapadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/kms/wrapadapter"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// localStackImage is the LocalStack build the demo stack pins.
const localStackImage = "localstack/localstack@sha256:b279c01f4cfb8f985a482e4014cabc1e2697b9d7a6c8c8db2e40f4d9f93687c7"

// A200 against LocalStack KMS: the signer key store seals the issuing CA key
// through the shipped adapter under a symmetric KMS key. Read back without the
// signer, LocalStack decrypts the wrapped data key under that key and the
// key store's encryption context; a restarted signer opens the CA key through
// the adapter and signs with the same public key; once the KMS key is
// disabled, the key store no longer opens, and nothing falls back to a file.
func TestLocalStackKMSSealsTheSignerCAKeyThroughTheAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", localStackImage).CombinedOutput(); err != nil {
		t.Skipf("the pinned LocalStack image is not present locally (docker pull %s): %v\n%s", localStackImage, err, out)
	}
	ctx := context.Background()
	endpoint := startLocalStack(t)
	kms := awskmssdk.NewFromConfig(awssdk.Config{
		Region: "us-east-1",
		Credentials: awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
			return awssdk.Credentials{AccessKeyID: "test", SecretAccessKey: "test", Source: "localstack"}, nil
		}),
	}, func(o *awskmssdk.Options) { o.BaseEndpoint = awssdk.String(endpoint) })
	created, err := kms.CreateKey(ctx, &awskmssdk.CreateKeyInput{
		KeySpec: types.KeySpecSymmetricDefault, KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		Description: awssdk.String("trstctl signer key store"),
	})
	if err != nil {
		t.Fatalf("create the KMS key: %v", err)
	}
	keyARN := awssdk.ToString(created.KeyMetadata.Arn)

	dir := t.TempDir()
	secretFile := filepath.Join(dir, "aws-secret")
	if err := os.WriteFile(secretFile, []byte("test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"aws": map[string]any{
		"endpoint": endpoint, "allow_insecure_loopback": true,
		"access_key_id": "test", "secret_access_key_file": secretFile,
	}})
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "kms-wrap.json")
	if err := os.WriteFile(configFile, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(wrapadapter.ConfigEnv, configFile)
	adapter := buildCommand(t, "./cmd/trstctl-kms-wrap", "trstctl-kms-wrap")
	wrapper, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
		Provider: "awskms", KeyRef: keyARN, WrapCommand: adapter, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	keystore := filepath.Join(dir, "keystore")
	first, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err != nil {
		t.Fatalf("a signer whose key store wraps through the adapter: %v", err)
	}
	gen, err := first.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "issuing-ca",
	})
	if err != nil {
		t.Fatalf("generate the issuing CA key: %v", err)
	}

	// Read back without the signer: the key file's data key is an adapter
	// frame around a KMS ciphertext that LocalStack decrypts under the key.
	sealed, err := os.ReadFile(filepath.Join(keystore, "issuing-ca.key")) // #nosec G304 -- the test's own key store (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _, err := seal.ContainerWrappedDEK(sealed)
	if err != nil || !bytes.HasPrefix(wrapped, []byte("TKW1A\x00\x00")) {
		t.Fatalf("the CA key's wrapped data key = %q, %v; want an AWS adapter frame", wrapped, err)
	}
	decrypted, err := kms.Decrypt(ctx, &awskmssdk.DecryptInput{
		KeyId: awssdk.String(keyARN), CiphertextBlob: wrapped[7:],
		EncryptionContext: map[string]string{"trstctl:purpose": wrapadapter.Purpose},
	})
	if err != nil || len(decrypted.Plaintext) != 32 || bytes.Contains(sealed, decrypted.Plaintext) {
		t.Fatalf("LocalStack's own decrypt of the wrapped data key: %v", err)
	}
	clear(decrypted.Plaintext)

	// A restarted signer opens the CA key through the adapter.
	signWith := func(server *signing.Server) ([]byte, error) {
		pub, err := server.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
		if err != nil {
			return nil, err
		}
		if _, err := server.Sign(ctx, &signerpb.SignRequest{
			Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
		}); err != nil {
			return nil, err
		}
		return pub.GetPublicKey(), nil
	}
	second, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err != nil {
		t.Fatalf("restart over the KMS-wrapped key store: %v", err)
	}
	if pub, err := signWith(second); err != nil || !bytes.Equal(pub, gen.GetPublicKey()) {
		t.Fatalf("the restarted signer's CA key = %v; same public key %v", err, bytes.Equal(pub, gen.GetPublicKey()))
	}

	// Disable the KMS key: the key store stops opening.
	if _, err := kms.DisableKey(ctx, &awskmssdk.DisableKeyInput{KeyId: awssdk.String(keyARN)}); err != nil {
		t.Fatal(err)
	}
	third, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err == nil {
		if _, err = signWith(third); err == nil {
			t.Fatal("the CA key opened with its KMS key disabled")
		}
	}
	refused := err
	// The signer binary refuses to start, naming KMS's reason: its custody
	// probe runs before the key store opens.
	socketDir, err := os.MkdirTemp("", "kw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	args := []string{"--socket", filepath.Join(socketDir, "s.sock"), "--keystore", keystore,
		"--kms-provider", "awskms", "--kms-key-ref", keyARN, "--kms-wrap-command", adapter}
	if runtime.GOOS != "linux" {
		args = append([]string{"--allow-insecure-dev-nonlinux"}, args...)
	}
	start := exec.Command(buildCommand(t, "./cmd/trstctl-signer", "trstctl-signer"), args...) // #nosec G204 -- the repository's own signer (CWE-78)
	refusal, startErr := start.CombinedOutput()
	if startErr == nil || !strings.Contains(string(refusal), "DisabledException") {
		t.Fatalf("the signer with its KMS key disabled = %v:\n%s", startErr, refusal)
	}
	t.Logf("LOCALSTACK_KMS_SIGNER_KEYSTORE_OK key=%s refused-after-disable=%q signer=%q", keyARN, refused, strings.TrimSpace(string(refusal)))
}

// startLocalStack runs LocalStack's KMS on a loopback port for this test.
func startLocalStack(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::4566", "-e", "SERVICES=kms", localStackImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start LocalStack: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() }) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	port, err := exec.Command("docker", "port", id, "4566/tcp").Output()   // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("LocalStack port: %v", err)
	}
	address := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	endpoint := "http://" + address
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(endpoint + "/_localstack/health")
		if err == nil {
			var health struct{ Services map[string]string }
			decodeErr := json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if decodeErr == nil && (health.Services["kms"] == "available" || health.Services["kms"] == "running") {
				return endpoint
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", id).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	t.Fatalf("LocalStack KMS did not become ready:\n%s", logs)
	return ""
}

// buildCommand compiles one of the repository's commands and returns its path.
func buildCommand(t *testing.T, pkg, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the repository")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, pkg) // #nosec G204 -- builds the repository's own command (CWE-78)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	return bin
}
