package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
)

func TestServedManagedKeysUseConfiguredAWSKMSLocalStack(t *testing.T) {
	runServedManagedKeysAWSKMSLifecycle(t, awsKMSAcceptanceConfig{
		name:            "localstack",
		region:          "us-east-1",
		endpoint:        localStackKMSEndpoint(t),
		accessKeyID:     "test",
		secretAccessKey: []byte("test"),
	})

	if live, ok := liveAWSKMSAcceptanceConfig(); ok {
		t.Run("real-aws-when-credentials-present", func(t *testing.T) {
			runServedManagedKeysAWSKMSLifecycle(t, live)
		})
	}
}

type awsKMSAcceptanceConfig struct {
	name            string
	region          string
	endpoint        string
	accessKeyID     string
	secretAccessKey []byte
	sessionToken    []byte
}

func runServedManagedKeysAWSKMSLifecycle(t *testing.T, awsCfg awsKMSAcceptanceConfig) {
	t.Helper()
	cfg := config.Default()
	cfg.ManagedKeys.Enabled = true
	cfg.ManagedKeys.Provider = config.ManagedKeyProviderAWS
	cfg.ManagedKeys.AWS.Region = awsCfg.region
	cfg.ManagedKeys.AWS.Endpoint = awsCfg.endpoint
	cfg.ManagedKeys.AWS.AccessKeyID = awsCfg.accessKeyID
	cfg.ManagedKeys.AWS.SecretAccessKey = awsCfg.secretAccessKey
	cfg.ManagedKeys.AWS.SessionToken = awsCfg.sessionToken

	custody, err := managedKeyCustodyFromConfig(context.Background(), cfg.ManagedKeys, nil)
	if err != nil {
		t.Fatalf("build managed-key custody from config: %v", err)
	}

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ManagedKeyCustody = custody
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cloud-kms-operator-"+awsCfg.name, []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})

	generated := servedManagedKeyAction(t, h, token, http.MethodPost, "/api/v1/managed-keys", "kms-04-generate", map[string]string{
		"algorithm": string(crypto.RSA2048),
	}, http.StatusCreated)
	if generated.KeyID == "" || generated.Algorithm != string(crypto.RSA2048) || generated.Version != 1 || generated.State != string(byok.StateActive) || len(generated.PublicDER) == 0 {
		t.Fatalf("unexpected generated managed key: %+v", generated)
	}

	rotated := servedManagedKeyAction(t, h, token, http.MethodPost, "/api/v1/managed-keys/rotate", "kms-04-rotate", map[string]string{
		"key_id": generated.KeyID,
	}, http.StatusOK)
	if rotated.KeyID == "" || rotated.KeyID == generated.KeyID || rotated.Version != 2 || rotated.State != string(byok.StateActive) || len(rotated.PublicDER) == 0 {
		t.Fatalf("unexpected rotated managed key: before=%+v after=%+v", generated, rotated)
	}

	zeroized := servedManagedKeyAction(t, h, token, http.MethodPost, "/api/v1/managed-keys/zeroize", "kms-04-zeroize", map[string]string{
		"key_id": rotated.KeyID,
	}, http.StatusOK)
	if zeroized.KeyID != rotated.KeyID || zeroized.Version != rotated.Version || zeroized.State != string(byok.StateZeroized) {
		t.Fatalf("unexpected zeroized managed key: before=%+v after=%+v", rotated, zeroized)
	}

	toRevoke := servedManagedKeyAction(t, h, token, http.MethodPost, "/api/v1/managed-keys", "kms-04-generate-for-revoke", map[string]string{
		"algorithm": string(crypto.RSA2048),
	}, http.StatusCreated)
	revoked := servedManagedKeyAction(t, h, token, http.MethodPost, "/api/v1/managed-keys/revoke", "kms-04-revoke", map[string]string{
		"key_id": toRevoke.KeyID,
	}, http.StatusOK)
	if revoked.KeyID != toRevoke.KeyID || revoked.State != string(byok.StateRevoked) {
		t.Fatalf("unexpected revoked managed key: before=%+v after=%+v", toRevoke, revoked)
	}

	for _, eventType := range []string{byok.EventKeyGenerated, byok.EventKeyRotated, byok.EventKeyZeroized, byok.EventKeyRevoked} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing managed-key event %s", eventType)
		}
	}
}

func liveAWSKMSAcceptanceConfig() (awsKMSAcceptanceConfig, bool) {
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if accessKeyID == "" || secretAccessKey == "" || region == "" {
		return awsKMSAcceptanceConfig{}, false
	}
	return awsKMSAcceptanceConfig{
		name:            "live",
		region:          region,
		accessKeyID:     accessKeyID,
		secretAccessKey: []byte(secretAccessKey),
		sessionToken:    []byte(os.Getenv("AWS_SESSION_TOKEN")),
	}, true
}

type servedManagedKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version"`
	State     string `json:"state"`
	PublicDER []byte `json:"public_der"`
}

func servedManagedKeyAction(t *testing.T, h *servedHarness, token, method, path, idem string, body any, want int) servedManagedKeyResponse {
	t.Helper()
	code, raw := doBearer(t, h.ts, method, path, token, idem, body)
	if code != want {
		t.Fatalf("%s %s = %d, want %d; body=%s", method, path, code, want, raw)
	}
	var got servedManagedKeyResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode managed-key response: %v body=%s", err, raw)
	}
	return got
}

func localStackKMSEndpoint(t *testing.T) string {
	t.Helper()
	if endpoint := os.Getenv("TRSTCTL_LOCALSTACK_KMS_ENDPOINT"); endpoint != "" {
		waitForLocalStackKMS(t, endpoint)
		return strings.TrimRight(endpoint, "/")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the LocalStack AWS KMS acceptance test: %v", err)
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon is required for the LocalStack AWS KMS acceptance test: %v\n%s", err, out)
	}

	image := "localstack/localstack:3.8.1"
	if out, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil {
		pull := exec.Command("docker", "pull", image)
		if pullOut, pullErr := pull.CombinedOutput(); pullErr != nil {
			t.Skipf("pull LocalStack image after inspect failed (%v, %s): %v\n%s", err, out, pullErr, pullOut)
		}
	}

	name := fmt.Sprintf("trstctl-kms04-%d", time.Now().UnixNano())
	args := []string{
		"run", "-d", "--rm",
		"--name", name,
		"-e", "SERVICES=kms",
		"-e", "LS_LOG=warn",
		"-p", "127.0.0.1::4566",
		image,
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("start LocalStack KMS: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var portOut []byte
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		portOut, err = exec.Command("docker", "port", name, "4566/tcp").CombinedOutput()
		if err == nil && strings.TrimSpace(string(portOut)) != "" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if strings.TrimSpace(string(portOut)) == "" {
		t.Fatalf("LocalStack did not publish port: %v\n%s", err, portOut)
	}
	endpoint := "http://" + localPortAddress(string(portOut))
	waitForLocalStackKMS(t, endpoint)
	return endpoint
}

func localPortAddress(raw string) string {
	line := strings.TrimSpace(strings.Split(raw, "\n")[0])
	line = strings.TrimPrefix(line, "0.0.0.0:")
	line = strings.TrimPrefix(line, "[::]:")
	if strings.Contains(line, "127.0.0.1:") {
		return line
	}
	if !strings.Contains(line, ":") {
		return "127.0.0.1:" + line
	}
	parts := strings.Split(line, ":")
	return "127.0.0.1:" + parts[len(parts)-1]
}

func waitForLocalStackKMS(t *testing.T, endpoint string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(strings.TrimRight(endpoint, "/") + "/_localstack/health")
		if err == nil {
			var health map[string]any
			err = json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if err == nil {
				if services, ok := health["services"].(map[string]any); ok {
					if state, ok := services["kms"].(string); ok && (state == "available" || state == "running") {
						return
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("LocalStack KMS at %s did not become healthy", endpoint)
}
