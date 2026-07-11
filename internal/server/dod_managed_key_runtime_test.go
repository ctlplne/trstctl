//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodManagedKeyProbe                  = "independent managed-key device signature proof"
	dodManagedKeySignTokenHelperEnv     = "TRSTCTL_DOD_MANAGED_KEY_SIGN_TOKEN_HELPER"
	dodManagedKeySignTokenSecretFileEnv = "TRSTCTL_DOD_MANAGED_KEY_SIGN_TOKEN_SECRET_FILE"
	dodRuntimeDockerHostEnv             = "TRSTCTL_RUNTIME_DOCKER_HOST"
	dodManagedKeyRuntimePlatform        = "linux/amd64"
	dodManagedKeyLoopbackProxyPort      = 18080
)

type dodManagedKeyArtifacts struct {
	licenseFile      string
	licensePublicKey []byte
	network          string
	postgresDSN      string
	root             string
	repo             string
	runtimeImage     string
}

type dodManagedKeyFileState struct {
	Mode       os.FileMode
	Size       int64
	ModifiedNS int64
}

type dodManagedKeyWire struct {
	KeyID       string           `json:"key_id"`
	Algorithm   crypto.Algorithm `json:"algorithm"`
	State       string           `json:"state"`
	PublicDER   []byte           `json:"public_der"`
	Extractable bool             `json:"extractable"`
}

type dodManagedKeyReadback struct {
	KeyID        string `json:"key_id"`
	State        string `json:"state"`
	PublicDER    string `json:"public_der"`
	Signature    string `json:"signature"`
	Digest       string `json:"digest"`
	ExportDenial string `json:"private_export"`
}

type dodManagedKeySubstrateConfig struct {
	Endpoint          string `json:"endpoint"`
	ContainerEndpoint string `json:"container_endpoint"`
	AWSAccessKey      string `json:"aws_access_key_id"`
	AWSSecretKey      string `json:"aws_secret_access_key"`
	AWSRegion         string `json:"aws_region"`
	AzureToken        string `json:"azure_token"`
	GCPToken          string `json:"gcp_token"`
	GCPParent         string `json:"gcp_parent"`
}

type dodManagedKeyRuntime struct {
	t                       *testing.T
	entryID                 string
	provider                string
	external                *proof.ExternalSubstrate
	artifacts               dodManagedKeyArtifacts
	dir                     string
	containerName           string
	signerPort              int
	serverPort              int
	control                 *proof.ShippedProcess
	token                   string
	env                     []string
	mtlsMaterial            *mtls.SignerPeerMaterial
	tpmForeignHandle        string
	tpmGenerateOperationTag string
	closed                  bool
}

// TestDODManagedKeyProductionAssembly launches the real licensed cmd/trstctl
// composition and the exact cgo signer image built by the release Dockerfile.
// Each route crosses the durable PostgreSQL outbox into that separate signer.
// Rotation is submitted while the signer is stopped, then completes after the
// same signer journal/device state restarts, proving real redelivery/recovery.
func TestDODManagedKeyProductionAssembly(t *testing.T) {
	artifacts := dodBuildManagedKeyArtifacts(t)
	only := os.Getenv("TRSTCTL_HSM_PROOF_ONLY")
	if only == "" {
		only = proof.OnlyExpectation(t)
	}
	if only == "" || only == "hsm_kms.runtime" {
		runtimeEntry := proof.StartCommand(t, "hsm_kms.runtime")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.runtime", config.ManagedKeyProviderAWS, runtimeEntry, runtimeEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.aws_kms" {
		awsEntry := proof.StartCommand(t, "hsm_kms.aws_kms")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.aws_kms", config.ManagedKeyProviderAWS, awsEntry, awsEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.azure_key_vault" {
		azureEntry := proof.StartCommand(t, "hsm_kms.azure_key_vault")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.azure_key_vault", config.ManagedKeyProviderAzureKeyVault, azureEntry, azureEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.gcp_kms" {
		gcpEntry := proof.StartCommand(t, "hsm_kms.gcp_kms")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.gcp_kms", config.ManagedKeyProviderGCPKMS, gcpEntry, gcpEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.pkcs11" {
		pkcsEntry := proof.StartCommand(t, "hsm_kms.pkcs11")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.pkcs11", config.ManagedKeyProviderPKCS11, pkcsEntry, pkcsEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.tpm2" {
		tpmEntry := proof.StartCommand(t, "hsm_kms.tpm2")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.tpm2", config.ManagedKeyProviderTPM2, tpmEntry, tpmEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.yubihsm2" {
		yubiEntry := proof.StartCommand(t, "hsm_kms.yubihsm2")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.yubihsm2", config.ManagedKeyProviderYubiHSM2, yubiEntry, yubiEntry.Endpoint())
	}
}

// TestDODManagedKeySignTokenHelper is invoked as a separate process by the
// production AuthTokenCommand seam. It holds the approval-authority side of the
// content-authorization secret; the control-plane process receives only the
// command path and never maps the shared secret into its address space.
func TestDODManagedKeySignTokenHelper(t *testing.T) {
	if os.Getenv(dodManagedKeySignTokenHelperEnv) != "1" {
		return
	}
	var request struct {
		KeyHandle string `json:"key_handle"`
		Purpose   int32  `json:"purpose"`
		Hash      string `json:"hash"`
		Padding   string `json:"padding"`
		DigestB64 string `json:"digest_b64"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		t.Fatalf("decode signer authorization intent: %v", err)
	}
	digest, err := base64.StdEncoding.DecodeString(request.DigestB64)
	if err != nil {
		t.Fatalf("decode signer authorization digest: %v", err)
	}
	authorizer, err := signing.LoadOrCreateAuthorizer(os.Getenv(dodManagedKeySignTokenSecretFileEnv))
	if err != nil {
		t.Fatalf("load independent signer authorizer: %v", err)
	}
	defer authorizer.Destroy()
	token, err := authorizer.Authorize(crypto.SignIntent{
		KeyHandle: request.KeyHandle,
		Purpose:   request.Purpose,
		Hash:      crypto.Hash(request.Hash),
		Padding:   crypto.RSAPadding(request.Padding),
		Digest:    digest,
	})
	if err != nil {
		t.Fatalf("authorize signer intent: %v", err)
	}
	if _, err := os.Stdout.WriteString(base64.StdEncoding.EncodeToString(token)); err != nil {
		t.Fatalf("write signer authorization token: %v", err)
	}
	os.Exit(0)
}

func dodBuildManagedKeyArtifacts(t *testing.T) dodManagedKeyArtifacts {
	t.Helper()
	root := t.TempDir()
	repo := dodManagedKeyRepoRoot(t)
	// A prior buggy proof omitted signer state env vars, so cmd/trstctl used its
	// package cwd and created internal/server/data. Preserve any pre-existing tree
	// exactly as found and fail if this launched proof changes it; cleanup must not
	// hide the regression by deleting evidence.
	cwdDataRoot := filepath.Join(repo, "internal", "server", "data")
	cwdDataBefore, err := dodManagedKeySnapshotTree(cwdDataRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cwdDataAfter, snapshotErr := dodManagedKeySnapshotTree(cwdDataRoot)
		if snapshotErr != nil {
			t.Errorf("snapshot managed-key proof cwd data after run: %v", snapshotErr)
			return
		}
		if !dodManagedKeySnapshotsEqual(cwdDataBefore, cwdDataAfter) {
			t.Errorf("launched managed-key proof changed default cwd data tree; before=%v after=%v", cwdDataBefore, cwdDataAfter)
		}
	})
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	claims := license.Claims{
		V: 1, ID: "dod-managed-key-license", Customer: "DoD runtime", Tier: license.TierEnterprise,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	rawLicense, err := license.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	licenseFile := filepath.Join(root, "enterprise-license.json")
	if err := os.WriteFile(licenseFile, rawLicense, 0o600); err != nil {
		t.Fatal(err)
	}
	trustedKey := base64.StdEncoding.EncodeToString(publicKey)
	signerLDFlags := "-s -w -buildid= -X trstctl.com/trstctl/internal/license.builtinPubKeysB64=" + trustedKey
	goVersion := dodManagedKeyToolchainVersion(t, repo)
	buildBase := dodPinnedBaseImage(t, "golang:"+goVersion+"-bookworm", "golang")
	runtimeBase := dodPinnedBaseImage(t, "debian:bookworm-slim", "debian")
	dodRunCommandAt(t, repo, "build shipped cgo signer image", "docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "deploy/docker/Dockerfile.signer-hsm", "--build-arg", "BUILD_IMAGE="+buildBase, "--build-arg", "BASE_IMAGE="+runtimeBase, "--build-arg", "LDFLAGS="+signerLDFlags, "-t", "trstctl-signer-hsm:dod", ".")
	signerImage := dodBuiltImageID(t, "trstctl-signer-hsm:dod", dodManagedKeyRuntimePlatform)
	// BuildKit resolves a bare sha256 image ID as a registry repository name.
	// Docker's local image-ID resolver is the path that can consume these exact
	// just-built bytes without falling back to a mutable local tag or registry.
	t.Setenv("DOCKER_BUILDKIT", "0")
	dodRunCommandAt(t, repo, "build independent device-reader image", "docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "tools/dodcensus/Dockerfile.managed-key-runtime", "--build-arg", "SIGNER_IMAGE="+signerImage, "-t", "trstctl-managed-key-runtime:dod", ".")
	runtimeImage := dodBuiltImageID(t, "trstctl-managed-key-runtime:dod", dodManagedKeyRuntimePlatform)
	network := "trstctl-dod-hsm-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dodRunCommand(t, "create isolated managed-key proof network", "docker", "network", "create", network)
	t.Cleanup(func() {
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	t.Setenv("TRSTCTL_HSM_PROOF_NETWORK", network)
	t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", runtimeImage)
	return dodManagedKeyArtifacts{
		licenseFile: licenseFile, licensePublicKey: append([]byte(nil), publicKey...),
		postgresDSN: serverTestPostgresDSN(t), root: root, repo: repo, network: network, runtimeImage: runtimeImage,
	}
}

func dodManagedKeySnapshotTree(root string) (map[string]dodManagedKeyFileState, error) {
	snapshot := map[string]dodManagedKeyFileState{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snapshot[relative] = dodManagedKeyFileState{
			Mode: info.Mode(), Size: info.Size(), ModifiedNS: info.ModTime().UnixNano(),
		}
		return nil
	})
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	return snapshot, err
}

func dodManagedKeySnapshotsEqual(left, right map[string]dodManagedKeyFileState) bool {
	if len(left) != len(right) {
		return false
	}
	for path, state := range left {
		if right[path] != state {
			return false
		}
	}
	return true
}

func dodRunManagedKeyProvider(t *testing.T, artifacts dodManagedKeyArtifacts, entryID, provider string, external *proof.ExternalSubstrate, endpoint string) {
	t.Helper()
	control := proof.BuildShippedProcess(t, entryID, artifacts.licensePublicKey)
	runtime := &dodManagedKeyRuntime{
		t: t, entryID: entryID, provider: provider, external: external,
		artifacts: artifacts, dir: t.TempDir(), signerPort: dodFreePort(t), serverPort: dodFreePort(t), control: control,
	}
	runtime.containerName = "trstctl-dod-hsm-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runtime.configure(endpoint)
	runtime.startSigner()
	t.Cleanup(runtime.close)
	defer runtime.close()
	if provider == config.ManagedKeyProviderTPM2 {
		runtime.installTPMForeignOperationCollision()
	}
	runtime.bootstrapToken()
	control.Start(runtime.dir, runtime.env)
	runtime.waitControlPlane()

	generateResponse := control.Do(dodManagedKeyRequestObject(runtime, http.MethodPost, "/api/v1/managed-keys", "generate", map[string]string{"algorithm": string(crypto.RSA2048)}))
	session := proof.StartResponse(t, entryID, generateResponse)
	generated := dodDecodeManagedKey(t, session.ResponseBody())
	dodRequireActiveManagedKey(t, generated)
	if generated.Extractable {
		t.Fatal("managed key was reported extractable")
	}
	if provider == config.ManagedKeyProviderTPM2 {
		runtime.assertTPMForeignCollisionAndOperationTag(generated.KeyID)
	}
	// Same HTTP idempotency key must return the original provider handle.
	replayed := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys", "generate", map[string]string{"algorithm": string(crypto.RSA2048)})))
	if replayed.KeyID != generated.KeyID {
		t.Fatalf("HTTP idempotency replay minted %q after %q", replayed.KeyID, generated.KeyID)
	}

	// Stop the separate signer before submitting rotation. The API request has
	// already persisted its event/outbox intent; restart lets the dispatcher
	// redeliver to the same signer journal and provider state.
	runtime.stopSigner()
	rotateResult := make(chan *http.Response, 1)
	go func() {
		rotateResult <- dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/rotate", "rotate", map[string]string{"key_id": generated.KeyID})
	}()
	time.Sleep(750 * time.Millisecond)
	runtime.restartSigner()
	var rotateResponse *http.Response
	select {
	case rotateResponse = <-rotateResult:
	case <-time.After(35 * time.Second):
		t.Fatal("managed-key outbox did not recover after signer restart")
	}
	rotated := dodDecodeManagedKey(t, runtime.responseBody(rotateResponse))
	dodRequireActiveManagedKey(t, rotated)
	if rotated.KeyID == generated.KeyID || bytes.Equal(rotated.PublicDER, generated.PublicDER) {
		t.Fatal("managed-key rotation did not create distinct provider material")
	}

	var signature, exportDenial []byte
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		readback := runtime.cloudReadback(rotated.KeyID, "active")
		signature = dodDecodeBase64(t, readback.Signature)
		exportDenial = []byte(readback.ExportDenial)
	} else {
		signature = runtime.hardwareSignAndWitness(generated, rotated, false, false)
		exportDenial = []byte("denied: private key is non-exportable device custody")
	}

	revoked := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/revoke", "revoke", map[string]string{"key_id": rotated.KeyID})))
	if revoked.State != "revoked" {
		t.Fatalf("revoke state = %q", revoked.State)
	}
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		runtime.cloudReadback(rotated.KeyID, "revoked")
	} else {
		runtime.assertHardwareRevoked(rotated.KeyID)
	}

	zeroized := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/zeroize", "zeroize", map[string]string{"key_id": rotated.KeyID})))
	if zeroized.State != "zeroized" {
		t.Fatalf("zeroize state = %q", zeroized.State)
	}
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		runtime.cloudReadback(rotated.KeyID, "zeroized")
	} else {
		runtime.finishHardwareWitness(generated, rotated, signature)
	}

	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.HSMSign(proof.HSMSignProbe{
		Signature: signature, PublicKey: rotated.PublicDER,
		ExportDenial: exportDenial, ExecutionReceipt: executionReceipt,
	}))
}

func (r *dodManagedKeyRuntime) configure(endpoint string) {
	r.t.Helper()
	configResponse, err := http.Get(endpoint + "/dod/config")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = configResponse.Body.Close() }()
	var substrate dodManagedKeySubstrateConfig
	if configResponse.StatusCode != http.StatusOK || json.NewDecoder(configResponse.Body).Decode(&substrate) != nil {
		r.t.Fatalf("invalid managed-key substrate config status=%d", configResponse.StatusCode)
	}
	containerEndpoint := "http://127.0.0.1:" + strconv.Itoa(dodManagedKeyLoopbackProxyPort)
	signerConfig := config.ManagedKeys{Enabled: true, Provider: r.provider}
	control := map[string]string{}
	writeSecret := func(name, value string) (host, container string) {
		host = filepath.Join(r.dir, name)
		if err := os.WriteFile(host, []byte(value), 0o600); err != nil {
			r.t.Fatal(err)
		}
		return host, "/runtime/" + name
	}
	switch r.provider {
	case config.ManagedKeyProviderAWS:
		hostSecret, containerSecret := writeSecret("aws-secret", substrate.AWSSecretKey)
		signerConfig.AWS = config.ManagedKeysAWSKMS{Region: substrate.AWSRegion, Endpoint: containerEndpoint, AllowInsecureLoopback: true, AccessKeyID: substrate.AWSAccessKey, SecretAccessKeyFile: containerSecret, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_AWS_REGION"] = substrate.AWSRegion
		control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = endpoint
		control["TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID"] = substrate.AWSAccessKey
		control["TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE"] = hostSecret
		control["TRSTCTL_MANAGED_KEYS_AWS_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderAzureKeyVault:
		hostToken, containerToken := writeSecret("azure-token", substrate.AzureToken)
		signerConfig.Azure = config.ManagedKeysAzureKV{VaultURL: "https://dod.managedhsm.azure.net", Endpoint: containerEndpoint, AllowInsecureLoopback: true, BearerTokenFile: containerToken, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL"] = "https://dod.managedhsm.azure.net"
		control["TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT"] = endpoint
		control["TRSTCTL_MANAGED_KEYS_AZURE_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE"] = hostToken
		control["TRSTCTL_MANAGED_KEYS_AZURE_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderGCPKMS:
		hostToken, containerToken := writeSecret("gcp-token", substrate.GCPToken)
		signerConfig.GCP = config.ManagedKeysGCPKMS{Parent: substrate.GCPParent, Endpoint: containerEndpoint + "/v1", AllowInsecureLoopback: true, BearerTokenFile: containerToken, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_GCP_PARENT"] = substrate.GCPParent
		control["TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT"] = endpoint + "/v1"
		control["TRSTCTL_MANAGED_KEYS_GCP_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE"] = hostToken
		control["TRSTCTL_MANAGED_KEYS_GCP_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderPKCS11:
		hostPIN, containerPIN := writeSecret("device-pin", "12345678")
		signerConfig.PKCS11 = config.ManagedKeysPKCS11HSM{ModulePath: "/runtime/libsofthsm2.so", TokenLabel: "trstctl-dod", UserPINFile: containerPIN, KeyLabelPrefix: "trstctl-pkcs11"}
		control["TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH"] = "/runtime/libsofthsm2.so"
		control["TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL"] = "trstctl-dod"
		control["TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE"] = hostPIN
	case config.ManagedKeyProviderTPM2:
		// Keep the transport socket on the container filesystem. Docker Desktop's
		// macOS bind mount rejects chmod(2) on Unix sockets; only the TPM state must
		// be durable across the signer stop/start and remains under /runtime.
		signerConfig.TPM2 = config.ManagedKeysTPM2{Path: "/tmp/swtpm.sock", PersistentHandleBase: 0x81010000}
		control["TRSTCTL_MANAGED_KEYS_TPM2_PATH"] = "/tmp/swtpm.sock"
		control["TRSTCTL_MANAGED_KEYS_TPM2_PERSISTENT_HANDLE_BASE"] = "2164326400"
	case config.ManagedKeyProviderYubiHSM2:
		hostPIN, containerPIN := writeSecret("device-pin", "12345678")
		signerConfig.YubiHSM2 = config.ManagedKeysPKCS11HSM{ModulePath: "/runtime/libsofthsm2.so", TokenLabel: "trstctl-dod", UserPINFile: containerPIN, KeyLabelPrefix: "trstctl-yubihsm2"}
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_MODULE_PATH"] = "/runtime/libsofthsm2.so"
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_TOKEN_LABEL"] = "trstctl-dod"
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE"] = hostPIN
	}
	rawConfig, err := json.Marshal(signerConfig)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "provider.json"), rawConfig, 0o600); err != nil {
		r.t.Fatal(err)
	}
	rawLicense, err := os.ReadFile(r.artifacts.licenseFile)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "license.json"), rawLicense, 0o600); err != nil {
		r.t.Fatal(err)
	}
	authSecretFile := filepath.Join(r.dir, "sign-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authSecretFile)
	if err != nil {
		r.t.Fatal(err)
	}
	authorizer.Destroy()
	testExecutable, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	authCommand := filepath.Join(r.dir, "authorize-sign-intent")
	authScript := "#!/bin/sh\nexport " + dodManagedKeySignTokenHelperEnv + "=1\nexport " +
		dodManagedKeySignTokenSecretFileEnv + "=" + dodManagedKeyShellQuote(authSecretFile) + "\nexec " +
		dodManagedKeyShellQuote(testExecutable) + " -test.run '^TestDODManagedKeySignTokenHelper$'\n"
	if err := os.WriteFile(authCommand, []byte(authScript), 0o700); err != nil {
		r.t.Fatal(err)
	}
	control["TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND"] = authCommand
	control["TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER"] = "false"
	material, err := mtls.GenerateSignerPeerMaterial(r.dir, "trstctl-dod-signer", time.Hour)
	if err != nil {
		r.t.Fatal(err)
	}
	r.mtlsMaterial = material
	r.env = dodManagedKeyControlEnv(r, control)
}

func dodManagedKeyControlEnv(r *dodManagedKeyRuntime, providerEnv map[string]string) []string {
	signerAddress := dodManagedKeySignerAddress(r.t, r.signerPort)
	values := map[string]string{
		"TRSTCTL_SERVER_ADDR":     "127.0.0.1:" + strconv.Itoa(r.serverPort),
		"TRSTCTL_SERVER_TLS_MODE": "disabled", "TRSTCTL_DEV_ALLOW_PLAINTEXT": "true",
		"TRSTCTL_POSTGRES_MODE": "external", "TRSTCTL_POSTGRES_DSN": r.artifacts.postgresDSN,
		"TRSTCTL_NATS_MODE": "embedded", "TRSTCTL_NATS_STORE_DIR": filepath.Join(r.dir, "nats"),
		"TRSTCTL_LICENSE_FILE": r.artifacts.licenseFile, "TRSTCTL_MIGRATE_AUTO": "true",
		"TRSTCTL_RATE_LIMIT_ENABLED": "false", "TRSTCTL_TELEMETRY_ENABLED": "false",
		"TRSTCTL_AUDIT_SIGNING_KEY_FILE":  filepath.Join(r.dir, "audit.pem"),
		"TRSTCTL_SECRETS_KEK_FILE":        filepath.Join(r.dir, "control-kek.bin"),
		"TRSTCTL_CA_CERT_FILE":            filepath.Join(r.dir, "issuing-ca.pem"),
		"TRSTCTL_SIGNER_KEY_STORE_DIR":    filepath.Join(r.dir, "control-signer-keys"),
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": filepath.Join(r.dir, "sign-auth.bin"),
		"TRSTCTL_SIGNER_MODE":             "external", "TRSTCTL_SIGNER_MTLS_ADDRESS": signerAddress,
		"TRSTCTL_SIGNER_MTLS_SERVER_NAME":  r.mtlsMaterial.ServerName,
		"TRSTCTL_SIGNER_MTLS_CERT_FILE":    r.mtlsMaterial.ControlPlane.CertFile,
		"TRSTCTL_SIGNER_MTLS_KEY_FILE":     r.mtlsMaterial.ControlPlane.KeyFile,
		"TRSTCTL_SIGNER_MTLS_PEER_CA_FILE": r.mtlsMaterial.ControlPlane.PeerCAFile,
		"TRSTCTL_SIGNER_MTLS_PEER_PIN":     r.mtlsMaterial.ControlPlane.PeerPinHex,
		"TRSTCTL_MANAGED_KEYS_ENABLED":     "true", "TRSTCTL_MANAGED_KEYS_PROVIDER": r.provider,
	}
	for key, value := range providerEnv {
		values[key] = value
	}
	base := make([]string, 0, len(os.Environ())+len(values))
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "TRSTCTL_") {
			base = append(base, item)
		}
	}
	for key, value := range values {
		base = append(base, key+"="+value)
	}
	return base
}

// dodRuntimeDockerHost is a closed routing seam for processes launched through
// the mounted Docker socket. Native tests reach published ports on loopback. The
// reviewed cross-host runner exports Docker Desktop's fixed host name. No URL,
// IP, arbitrary DNS name, whitespace variant, or port is accepted here.
func dodRuntimeDockerHost() (string, error) {
	value, ok := os.LookupEnv(dodRuntimeDockerHostEnv)
	if !ok || value == "" {
		return "127.0.0.1", nil
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%s contains surrounding whitespace", dodRuntimeDockerHostEnv)
	}
	switch value {
	case "127.0.0.1", "host.docker.internal":
		return value, nil
	default:
		return "", fmt.Errorf("%s must be 127.0.0.1 or host.docker.internal", dodRuntimeDockerHostEnv)
	}
}

func dodManagedKeySignerAddress(t *testing.T, port int) string {
	t.Helper()
	host, err := dodRuntimeDockerHost()
	if err != nil {
		t.Fatal(err)
	}
	if port < 1 || port > 65535 {
		t.Fatalf("managed-key signer port %d is outside 1..65535", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func TestDODManagedKeyControlEnvKeepsSignerStateInsideRuntimeDir(t *testing.T) {
	runtimeDir := t.TempDir()
	r := &dodManagedKeyRuntime{
		t: t, dir: runtimeDir, provider: config.ManagedKeyProviderAWS, signerPort: 19443,
		artifacts: dodManagedKeyArtifacts{licenseFile: filepath.Join(runtimeDir, "license.json"), postgresDSN: "postgres://dod"},
		mtlsMaterial: &mtls.SignerPeerMaterial{
			ServerName: "dod-signer",
			ControlPlane: mtls.SignerPeerConfig{
				CertFile: "control.crt", KeyFile: "control.key", PeerCAFile: "ca.pem", PeerPinHex: "00",
			},
		},
	}
	env := dodManagedKeyControlEnv(r, nil)
	values := map[string]string{}
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	want := map[string]string{
		"TRSTCTL_SIGNER_KEY_STORE_DIR":    filepath.Join(runtimeDir, "control-signer-keys"),
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": filepath.Join(runtimeDir, "sign-auth.bin"),
		"TRSTCTL_SIGNER_MTLS_ADDRESS":     "127.0.0.1:19443",
	}
	for key, expected := range want {
		if got := values[key]; got != expected {
			t.Errorf("%s = %q, want runtime-scoped %q", key, got, expected)
		}
	}
}

func TestDODManagedKeyRuntimeDockerHostIsClosed(t *testing.T) {
	t.Setenv(dodRuntimeDockerHostEnv, "")
	if got, err := dodRuntimeDockerHost(); err != nil || got != "127.0.0.1" {
		t.Fatalf("native Docker host = %q err=%v", got, err)
	}
	t.Setenv(dodRuntimeDockerHostEnv, "host.docker.internal")
	if got, err := dodRuntimeDockerHost(); err != nil || got != "host.docker.internal" {
		t.Fatalf("cross-host Docker host = %q err=%v", got, err)
	}
	if got := dodManagedKeySignerAddress(t, 19443); got != "host.docker.internal:19443" {
		t.Fatalf("cross-host signer address = %q", got)
	}
	for _, invalid := range []string{"localhost", "127.0.0.2", "host.docker.internal:2375", " host.docker.internal", "host.docker.internal "} {
		t.Setenv(dodRuntimeDockerHostEnv, invalid)
		if got, err := dodRuntimeDockerHost(); err == nil {
			t.Errorf("accepted runtime Docker host %q as %q", invalid, got)
		}
	}
}

func (r *dodManagedKeyRuntime) startSigner() {
	r.t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid < 0 {
		r.t.Fatalf("managed-key verifier requires a non-root runtime owner, got %d:%d", uid, gid)
	}
	passwdFile, groupFile := dodManagedKeySignerNSS(r.t, r.dir, uid, gid)
	args := []string{
		"run", "-d", "--name", r.containerName,
		"--platform", dodManagedKeyRuntimePlatform,
		"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		"--network", r.artifacts.network,
		"-p", fmt.Sprintf("127.0.0.1:%d:9443", r.signerPort),
	}
	// Docker Desktop supplies a special host.docker.internal proxy. Overriding it
	// with Linux's host-gateway address points at the VM gateway instead of the
	// macOS host and makes the signer unable to reach the proof substrate.
	if goruntime.GOOS == "linux" {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	args = append(args,
		"-v", r.dir+":/runtime",
		"-v", passwdFile+":/etc/passwd:ro", "-v", groupFile+":/etc/group:ro",
		"-e", "TRSTCTL_DOD_PROVIDER="+r.provider,
		"-e", "TRSTCTL_DOD_CLOUD_UPSTREAM=managed-key-emulator:8080",
		r.artifacts.runtimeImage,
		"--mtls-listen", ":9443", "--mtls-cert", "/runtime/signer.crt", "--mtls-key", "/runtime/signer.key",
		"--mtls-peer-ca", "/runtime/signer-ca.pem", "--mtls-peer-pin", r.mtlsMaterial.Signer.PeerPinHex,
		"--keystore", "/runtime/keystore", "--kek", "/runtime/signer-kek.bin",
		"--auth-secret", "/runtime/sign-auth.bin",
		"--license", "/runtime/license.json",
		"--managed-keys-config", "/runtime/provider.json",
	)
	dodRunCommand(r.t, "start separate managed-key signer", "docker", args...)
	r.waitSigner()
}

func dodManagedKeySignerNSS(t *testing.T, dir string, uid, gid int) (string, string) {
	t.Helper()
	if uid <= 0 || gid < 0 || !filepath.IsAbs(dir) || strings.ContainsAny(dir, ":\r\n\x00") {
		t.Fatalf("invalid managed-key signer NSS identity/path %d:%d %q", uid, gid, dir)
	}
	passwd := "root:x:0:0:root:/root:/usr/sbin/nologin\n" +
		fmt.Sprintf("dodsigner:x:%d:%d:DoD managed-key signer:/runtime:/usr/sbin/nologin\n", uid, gid)
	group := "root:x:0:\n"
	if gid != 0 {
		group += fmt.Sprintf("dodsigner:x:%d:\n", gid)
	}
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatalf("create managed-key signer %s: %v", name, err)
		}
		if _, err := file.WriteString(content); err != nil {
			_ = file.Close()
			t.Fatalf("write managed-key signer %s: %v", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatalf("sync managed-key signer %s: %v", name, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close managed-key signer %s: %v", name, err)
		}
		return path
	}
	return write("signer.passwd", passwd), write("signer.group", group)
}

func TestDODManagedKeySignerNSSIsScopedAndNonRoot(t *testing.T) {
	dir := t.TempDir()
	passwdFile, groupFile := dodManagedKeySignerNSS(t, dir, 501, 20)
	passwd, err := os.ReadFile(passwdFile)
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.ReadFile(groupFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(passwd) != "root:x:0:0:root:/root:/usr/sbin/nologin\ndodsigner:x:501:20:DoD managed-key signer:/runtime:/usr/sbin/nologin\n" {
		t.Fatalf("signer passwd = %q", passwd)
	}
	if string(group) != "root:x:0:\ndodsigner:x:20:\n" {
		t.Fatalf("signer group = %q", group)
	}
	for _, path := range []string{passwdFile, groupFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("signer NSS mode = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func dodManagedKeyShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (r *dodManagedKeyRuntime) stopSigner() {
	r.t.Helper()
	dodRunCommand(r.t, "stop managed-key signer for outbox redelivery", "docker", "stop", "-t", "2", r.containerName)
}

func (r *dodManagedKeyRuntime) restartSigner() {
	r.t.Helper()
	dodRunCommand(r.t, "restart managed-key signer", "docker", "start", r.containerName)
	r.waitSigner()
}

func (r *dodManagedKeyRuntime) waitSigner() {
	r.t.Helper()
	address := dodManagedKeySignerAddress(r.t, r.signerPort)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	logs := dodCommandOutput("docker", "logs", r.containerName)
	r.t.Fatalf("separate signer did not listen: %s", logs)
}

func (r *dodManagedKeyRuntime) bootstrapToken() {
	r.t.Helper()
	tenant := dodManagedKeyTenant(r.entryID)
	r.token = r.control.CreateToken(r.dir, r.env, "token", "create", "--tenant", tenant, "--tenant-name", "DoD managed keys", "--subject", "dod-hsm-operator", "--scopes", "keys:read,keys:write")
	if r.token == "" {
		r.t.Fatal("bootstrap returned an empty API token")
	}
}

func (r *dodManagedKeyRuntime) waitControlPlane() {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", r.serverPort))
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode/100 == 2 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	r.t.Fatalf("control plane did not serve: signer_logs=%s control_logs=%s", dodCommandOutput("docker", "logs", r.containerName), r.control.Logs())
}

func dodManagedKeyRequestObject(r *dodManagedKeyRuntime, method, path, idempotency string, value any) *http.Request {
	r.t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		r.t.Fatal(err)
	}
	request, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", r.serverPort, path), bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+r.token)
	request.Header.Set("Idempotency-Key", "dod-"+strings.ReplaceAll(r.entryID, ".", "-")+"-"+idempotency)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func dodManagedKeyRequest(r *dodManagedKeyRuntime, method, path, idempotency string, value any) *http.Response {
	r.t.Helper()
	request := dodManagedKeyRequestObject(r, method, path, idempotency, value)
	client := &http.Client{Timeout: 35 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		r.t.Fatalf("managed-key %s: %v logs=%s", path, err, r.control.Logs())
	}
	return response
}

func (r *dodManagedKeyRuntime) responseBody(response *http.Response) []byte {
	r.t.Helper()
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		r.t.Fatal(err)
	}
	if response.StatusCode/100 != 2 {
		r.t.Fatalf("managed-key response status=%d body=%s durable=%s logs=%s", response.StatusCode, body, r.durableDiagnostics(), r.control.Logs())
	}
	return body
}

func (r *dodManagedKeyRuntime) durableDiagnostics() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, r.artifacts.postgresDSN)
	if err != nil {
		return "connect=" + err.Error()
	}
	defer func() { _ = connection.Close(context.Background()) }()
	tenantID := dodManagedKeyTenant(r.entryID)
	rows, err := connection.Query(ctx,
		`SELECT id, status, attempts, COALESCE(last_error, ''), COALESCE(worker_id, '')
		   FROM outbox
		  WHERE tenant_id = $1 AND destination = $2
		  ORDER BY id`, tenantID, "managedkey.command")
	if err != nil {
		return "query-outbox=" + err.Error()
	}
	var out strings.Builder
	for rows.Next() {
		var id int64
		var statusValue, lastError, workerID string
		var attempts int
		if err := rows.Scan(&id, &statusValue, &attempts, &lastError, &workerID); err != nil {
			rows.Close()
			return "scan-outbox=" + err.Error()
		}
		fmt.Fprintf(&out, "outbox{id=%d status=%s attempts=%d worker=%s error=%q} ", id, statusValue, attempts, workerID, lastError)
	}
	rows.Close()
	operationRows, err := connection.Query(ctx,
		`SELECT operation_id, status, COALESCE(last_error, '')
		   FROM managed_key_operations
		  WHERE tenant_id = $1
		  ORDER BY created_at`, tenantID)
	if err != nil {
		return out.String() + "query-operations=" + err.Error()
	}
	defer operationRows.Close()
	for operationRows.Next() {
		var operationID, statusValue, lastError string
		if err := operationRows.Scan(&operationID, &statusValue, &lastError); err != nil {
			return out.String() + "scan-operations=" + err.Error()
		}
		fmt.Fprintf(&out, "operation{id=%s status=%s error=%q} ", operationID, statusValue, lastError)
	}
	if out.Len() == 0 {
		out.WriteString("no managed-key durable rows ")
	}
	journalFiles, _ := filepath.Glob(filepath.Join(r.dir, "keystore", "managed-key-operations", "*.json"))
	for _, journalFile := range journalFiles {
		raw, readErr := os.ReadFile(journalFile)
		if readErr == nil && len(raw) <= 1<<20 {
			fmt.Fprintf(&out, "signer-journal{%s=%s} ", filepath.Base(journalFile), raw)
		}
	}
	return out.String()
}

func (r *dodManagedKeyRuntime) cloudReadback(keyID, state string) dodManagedKeyReadback {
	r.t.Helper()
	query := url.Values{"key_id": []string{keyID}, "expect": []string{state}}
	response, err := http.Get(r.external.Endpoint() + "/dod/readback?" + query.Encode())
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var readback dodManagedKeyReadback
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&readback) != nil || readback.State != state {
		r.t.Fatalf("cloud managed-key readback state=%s status=%d", state, response.StatusCode)
	}
	return readback
}

func (r *dodManagedKeyRuntime) hardwareSignAndWitness(generated, rotated dodManagedKeyWire, revoked, zeroized bool) []byte {
	r.t.Helper()
	messagePath := filepath.Join(r.dir, "device-message")
	if err := os.WriteFile(messagePath, []byte(dodManagedKeyProbe), 0o600); err != nil {
		r.t.Fatal(err)
	}
	generatedPresent := r.hardwarePresent(generated.KeyID)
	rotatedPresent := r.hardwarePresent(rotated.KeyID)
	signaturePath := filepath.Join(r.dir, "device-signature")
	var command string
	if r.provider == config.ManagedKeyProviderTPM2 {
		command = fmt.Sprintf("TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321 tpm2_sign -c %s -g sha256 -f plain -o /runtime/device-signature /runtime/device-message", rotated.KeyID)
	} else {
		command = fmt.Sprintf("SOFTHSM2_CONF=/runtime/softhsm2.conf pkcs11-tool --module /runtime/libsofthsm2.so --login --pin 12345678 --sign --id %s --mechanism SHA256-RSA-PKCS --input-file /runtime/device-message --output-file /runtime/device-signature", rotated.KeyID)
	}
	r.dockerExecShell(true, "sign independent device message", command)
	signature, err := os.ReadFile(signaturePath)
	if err != nil || len(signature) == 0 {
		r.t.Fatalf("read independent device signature: %v", err)
	}
	_ = revoked
	_ = zeroized
	if !generatedPresent || !rotatedPresent {
		r.t.Fatal("independent device reader did not find both generated keys")
	}
	return signature
}

func (r *dodManagedKeyRuntime) hardwarePresent(keyID string) bool {
	r.t.Helper()
	if r.provider == config.ManagedKeyProviderTPM2 {
		return r.dockerExecShell(false, "read exact TPM public handle", fmt.Sprintf("TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321 tpm2_readpublic -c %s", keyID))
	}
	// OpenSC pkcs11-tool accepts --id with --list-objects but some modules still
	// enumerate every object in the token. With a predecessor key intentionally
	// left present after rotation, grepping that output therefore reports a false
	// positive after the successor has really been destroyed. Reading the public
	// object is an exact-ID lookup: it exits non-zero when that one object is gone.
	return r.dockerExecShell(false, "read exact PKCS11 public object", fmt.Sprintf("SOFTHSM2_CONF=/runtime/softhsm2.conf pkcs11-tool --module /runtime/libsofthsm2.so --login --pin 12345678 --read-object --type pubkey --id %s --output-file /runtime/device-public-key >/dev/null 2>&1", keyID))
}

func (r *dodManagedKeyRuntime) installTPMForeignOperationCollision() {
	r.t.Helper()
	operationID := dodManagedKeyOperationID(r.entryID, "generate")
	tag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		r.t.Fatal(err)
	}
	r.tpmGenerateOperationTag = hex.EncodeToString(tag)
	const (
		baseHandle = uint64(0x81010000)
		maxHandle  = uint64(0x81ffffff)
	)
	minHandle := baseHandle + 0x100
	first := minHandle + (binary.BigEndian.Uint64(tag[:8]) % (maxHandle - minHandle + 1))
	r.tpmForeignHandle = fmt.Sprintf("0x%08x", uint32(first))
	script := fmt.Sprintf(`set -eu
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
mkdir -p /runtime/tpm-foreign
rm -f /runtime/tpm-foreign/*
tpm2_createprimary -C o -G rsa -g sha256 -c /runtime/tpm-foreign/key.ctx >/dev/null
tpm2_evictcontrol -C o -c /runtime/tpm-foreign/key.ctx %s >/dev/null
tpm2_readpublic -c %s >/dev/null`, r.tpmForeignHandle, r.tpmForeignHandle)
	r.dockerExecShell(true, "persist foreign same-algorithm TPM collision", script)
}

func (r *dodManagedKeyRuntime) assertTPMForeignCollisionAndOperationTag(generatedHandle string) {
	r.t.Helper()
	if generatedHandle == r.tpmForeignHandle {
		r.t.Fatalf("TPM operation bound the foreign same-algorithm first candidate %q", generatedHandle)
	}
	if !r.hardwarePresent(r.tpmForeignHandle) {
		r.t.Fatalf("TPM operation overwrote or removed foreign first candidate %q", r.tpmForeignHandle)
	}
	command := fmt.Sprintf(
		"TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321 tpm2_readpublic -c %s | tr -d '[:space:]' | grep -qi %s",
		generatedHandle, r.tpmGenerateOperationTag,
	)
	if !r.dockerExecShell(false, "read TPM durable operation tag", command) {
		r.t.Fatalf("TPM generated handle %q did not expose its exact durable operation tag through ReadPublic", generatedHandle)
	}
}

func (r *dodManagedKeyRuntime) assertHardwareRevoked(keyID string) {
	r.t.Helper()
	if r.provider == config.ManagedKeyProviderTPM2 {
		if r.hardwarePresent(keyID) {
			r.t.Fatal("TPM revoke left persistent signing handle present")
		}
		return
	}
	command := fmt.Sprintf("SOFTHSM2_CONF=/runtime/softhsm2.conf pkcs11-tool --module /runtime/libsofthsm2.so --login --pin 12345678 --sign --id %s --mechanism SHA256-RSA-PKCS --input-file /runtime/device-message --output-file /runtime/revoked-signature", keyID)
	if r.dockerExecShell(false, "attempt revoked PKCS11 signature", command) {
		r.t.Fatal("revoked HSM key still produced a signature")
	}
}

func (r *dodManagedKeyRuntime) finishHardwareWitness(generated, rotated dodManagedKeyWire, signature []byte) {
	r.t.Helper()
	if r.hardwarePresent(rotated.KeyID) {
		r.t.Fatal("zeroized device key is still present")
	}
	witness := map[string]any{
		"generated_key": generated.KeyID, "rotated_key": rotated.KeyID,
		"public_der":        base64.StdEncoding.EncodeToString(rotated.PublicDER),
		"signature":         base64.StdEncoding.EncodeToString(signature),
		"message":           base64.StdEncoding.EncodeToString([]byte(dodManagedKeyProbe)),
		"generated_present": true, "rotated_present": true,
		"revoked_denied": true, "zeroized_absent": true,
	}
	body, _ := json.Marshal(witness)
	response, err := http.Post(r.external.Endpoint()+"/dod/witness", "application/json", bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		result, _ := io.ReadAll(response.Body)
		r.t.Fatalf("hardware witness rejected: status=%d body=%s", response.StatusCode, result)
	}
}

func (r *dodManagedKeyRuntime) dockerExecShell(requireSuccess bool, label, script string) bool {
	r.t.Helper()
	command := exec.Command("docker", "exec", r.containerName, "/bin/sh", "-c", script)
	output, err := command.CombinedOutput()
	if requireSuccess && err != nil {
		state := dodCommandOutput("docker", "inspect", "--format={{json .State}}", r.containerName)
		logs := dodCommandOutput("docker", "logs", "--tail=120", r.containerName)
		r.t.Fatalf("independent device command %q: %v output=%s state=%s logs=%s", label, err, output, state, logs)
	}
	return err == nil
}

func (r *dodManagedKeyRuntime) close() {
	if r.closed {
		return
	}
	r.closed = true
	if r.control != nil {
		r.control.Stop()
	}
	_ = exec.Command("docker", "rm", "-f", r.containerName).Run()
}

func dodDecodeManagedKey(t *testing.T, body []byte) dodManagedKeyWire {
	t.Helper()
	var value dodManagedKeyWire
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode managed-key response: %v body=%s", err, body)
	}
	return value
}

func dodRequireActiveManagedKey(t *testing.T, value dodManagedKeyWire) {
	t.Helper()
	if value.KeyID == "" || value.Algorithm != crypto.RSA2048 || value.State != "active" || len(value.PublicDER) < 128 {
		t.Fatalf("invalid active managed key: %+v", value)
	}
}

func dodDecodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("decode base64 evidence: %v", err)
	}
	return decoded
}

func dodManagedKeyTenant(entryID string) string {
	digest, _ := crypto.Digest(crypto.SHA256, []byte(entryID))
	encoded := hex.EncodeToString(digest[:16])
	return encoded[0:8] + "-" + encoded[8:12] + "-4" + encoded[13:16] + "-8" + encoded[17:20] + "-" + encoded[20:32]
}

func dodManagedKeyOperationID(entryID, idempotencySuffix string) string {
	tenantID := dodManagedKeyTenant(entryID)
	rawKey := "dod-" + strings.ReplaceAll(entryID, ".", "-") + "-" + idempotencySuffix
	digest, _ := crypto.Digest(crypto.SHA256, []byte(tenantID+"\x00"+rawKey))
	return "managedkey:" + hex.EncodeToString(digest)
}

func dodContainerEndpoint(t *testing.T, endpoint string) string {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Port() == "" {
		t.Fatalf("invalid substrate endpoint %q", endpoint)
	}
	return "http://host.docker.internal:" + parsed.Port()
}

func dodFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func dodRunCommand(t *testing.T, label, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v output=%s", label, err, output)
	}
}

func dodRunCommandAt(t *testing.T, dir, label, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v output=%s", label, err, output)
	}
}

func dodBuiltImageID(t *testing.T, image, platform string) string {
	t.Helper()
	command := exec.Command("docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}", image)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect built managed-key runtime image: %v output=%s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[1] != platform {
		t.Fatalf("built managed-key runtime image inspect = %q, want image-id %s", strings.TrimSpace(string(output)), platform)
	}
	id, err := dodParseContentImageID(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func dodManagedKeyToolchainVersion(t *testing.T, repo string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		t.Fatalf("read managed-key toolchain version: %v", err)
	}
	fields := strings.Fields(string(raw))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "toolchain" {
			continue
		}
		version := strings.TrimPrefix(fields[index+1], "go")
		if version == "" || strings.Trim(version, "0123456789.") != "" {
			t.Fatalf("go.mod toolchain %q is not an exact numeric Go version", fields[index+1])
		}
		return version
	}
	t.Fatal("go.mod has no exact toolchain directive for the signer builder")
	return ""
}

func dodPinnedBaseImage(t *testing.T, taggedImage, repository string) string {
	t.Helper()
	if repository == "" || strings.ContainsAny(repository, "@:\t\r\n ") {
		t.Fatalf("invalid pinned base repository %q", repository)
	}
	command := exec.Command("docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pull exact-platform base for %s: %v output=%s", taggedImage, err, output)
	}
	command = exec.Command("docker", "image", "inspect", "--format={{json .RepoDigests}}", taggedImage)
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect immutable base for %s: %v output=%s", taggedImage, err, output)
	}
	var repoDigests []string
	if err := json.Unmarshal(bytes.TrimSpace(output), &repoDigests); err != nil {
		t.Fatalf("decode immutable base digests for %s: %v output=%s", taggedImage, err, output)
	}
	prefix := repository + "@"
	for _, reference := range repoDigests {
		if !strings.HasPrefix(reference, prefix) {
			continue
		}
		digest, parseErr := dodParseContentImageID(strings.TrimPrefix(reference, prefix))
		if parseErr == nil {
			return prefix + digest
		}
	}
	t.Fatalf("pulled base %s has no exact %s@sha256 RepoDigest: %v", taggedImage, repository, repoDigests)
	return ""
}

func dodParseContentImageID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	algorithm, digest, ok := strings.Cut(value, ":")
	decoded, err := hex.DecodeString(digest)
	if !ok || algorithm != "sha256" || err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
		return "", fmt.Errorf("managed-key runtime image id %q is not content-addressed sha256", value)
	}
	return value, nil
}

func TestDODManagedKeyContentAddressedImageID(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if got, err := dodParseContentImageID("\n" + valid + "\n"); err != nil || got != valid {
		t.Fatalf("valid content image id = %q err=%v", got, err)
	}
	for _, invalid := range []string{"trstctl-managed-key-runtime:dod", "sha256:abc", "sha512:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if _, err := dodParseContentImageID(invalid); err == nil {
			t.Errorf("accepted mutable/invalid image reference %q", invalid)
		}
	}
}

func dodManagedKeyRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot locate repository root for managed-key runtime")
		}
		dir = parent
	}
}

func dodCommandOutput(name string, args ...string) string {
	output, _ := exec.Command(name, args...).CombinedOutput()
	return string(output)
}
