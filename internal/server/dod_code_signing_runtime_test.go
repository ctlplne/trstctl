//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

// TestDODCodeSigningProductionAssembly proves the shipped code-signing route
// from buildRunDeps through the assembled handler. Persistent and ephemeral
// code-signing keys live in a separate signer process; the external Rekor
// emulator independently verifies each exact pre-hashed signature with OpenSSL
// and exposes its accepted log entry through authenticated process-bound
// readback before the proof can pass.
func TestDODCodeSigningProductionAssembly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rekorPublicKeyFile := dodConfigureRekorLogKey(t, dir)
	external := proof.StartCommand(t, "code_signing.default")
	productionRekorEndpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
	signer := dodStartAuthorizedSoftwareSignerProcess(t, dir)
	oidcToken, jwksJSON := dodGitHubOIDCIdentity(t)
	defer func() {
		for index := range oidcToken {
			oidcToken[index] = 0
		}
	}()

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(dir, "secrets-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(dir, "signer-keys")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	cfg.CodeSigning = config.CodeSigning{
		Enabled: true,
		Keys: []config.CodeSigningKey{{
			TenantID: servedTestTenant, ID: "release-key", Handle: "dod-release-key",
			Algorithm: "ecdsa-p256", CreateIfMissing: true,
		}},
		GitHubOIDCTenants: []config.CodeSigningGitHubOIDC{{
			TenantID: servedTestTenant, Issuer: githuboidc.DefaultIssuer,
			Audience: "sigstore", JWKSJSON: string(jwksJSON), AllowedOwners: []string{"acme"},
		}},
		EphemeralAlgorithm: "ecdsa-p256",
		Rekor: config.CodeSigningRekor{
			Endpoint: productionRekorEndpoint + "/api/v1/log/entries", Timeout: "5s",
			LogPublicKeyFile:  rekorPublicKeyFile,
			AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate production code-signing config: %v", err)
	}

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	defer runSecrets.Close()
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	defer func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	dispatcherCtx, stopDispatcher := context.WithCancel(ctx)
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		srv.RunDispatcher(dispatcherCtx)
	}()
	defer func() {
		stopDispatcher()
		<-dispatcherDone
	}()

	token := dodSeedAPIToken(t, ctx, st, servedTestTenant, "dod-release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	digest := crypto.SHA256Sum([]byte("sha256: immutable OCI manifest bytes for DoD code-signing proof"))
	keyedRequest := dodCodeSigningRequest(t, "/api/v1/code-signing/sign", token, "dod-code-sign-keyed", map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image", "digest": digest,
	})
	session := proof.Start(t, "code_signing.default", srv.Handler(), keyedRequest)
	keyed := dodDecodeCodeSigningResponse(t, session.StatusCode(), session.ResponseBody())
	if keyed.KeyID != "release-key" || keyed.TransparencyDestination != defaultRekorDestination {
		t.Fatalf("keyed response is not bound to the configured key/Rekor destination: %+v", keyed)
	}
	dodVerifyCodeSigningSignature(t, keyed, digest)

	keylessRequest := dodCodeSigningRequest(t, "/api/v1/code-signing/keyless", token, "dod-code-sign-keyless", map[string]any{
		"artifact_type": "oci-image", "digest": digest,
		"identity_method": "github_oidc", "identity_payload": oidcToken,
	})
	keylessRecorder := &dodHTTPRecorder{header: make(http.Header), status: http.StatusOK}
	srv.Handler().ServeHTTP(keylessRecorder, keylessRequest)
	keyless := dodDecodeCodeSigningResponse(t, keylessRecorder.status, keylessRecorder.body.Bytes())
	const wantSAN = "acme/payments/.github/workflows/release.yml@refs/heads/main"
	if keyless.FulcioSAN != wantSAN || keyless.FulcioIssuer != githuboidc.DefaultIssuer {
		t.Fatalf("keyless response is not bound to verified GitHub/Fulcio claims: %+v", keyless)
	}
	if bytes.Equal(keyed.PublicKeyDER, keyless.PublicKeyDER) {
		t.Fatal("keyless response reused the persistent signing key")
	}
	dodVerifyCodeSigningSignature(t, keyless, digest)

	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("publish queued HashedRekord entries: %v", err)
	}
	readback := dodNotificationReadback(t, external.Endpoint())
	contract, err := os.ReadFile("../../tools/dodcensus/contracts/rekor-hashedrekord-v1.json")
	if err != nil {
		t.Fatalf("read Rekor substrate contract: %v", err)
	}
	executionReceipt := external.StopAndReceipt()
	transcript := append(session.ResponseBody(), keylessRecorder.body.Bytes()...)
	transcript = append(transcript, contract...)
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity:      []byte(keyless.FulcioSAN + "|" + keyless.FulcioIssuer),
		Transcript:          transcript,
		IndependentVerifier: readback,
		ExecutionReceipt:    executionReceipt,
	}))
}

func dodConfigureRekorLogKey(t *testing.T, dir string) string {
	t.Helper()
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate external Rekor emulator log key: %v", err)
	}
	privatePEM, err := logKey.PrivateKeyPEM()
	if err != nil {
		logKey.Destroy()
		t.Fatalf("export emulator-only Rekor log key: %v", err)
	}
	defer secret.Wipe(privatePEM)
	publicPEM := crypto.MarshalPublicKeyPEM(logKey.Public().DER)
	logKey.Destroy()
	privateFile := filepath.Join(dir, "rekor-emulator-private.pem")
	publicFile := filepath.Join(dir, "rekor-emulator-public.pem")
	if err := os.WriteFile(privateFile, privatePEM, 0o600); err != nil {
		t.Fatalf("write emulator Rekor private key: %v", err)
	}
	if err := os.WriteFile(publicFile, publicPEM, 0o644); err != nil {
		t.Fatalf("write configured Rekor log public key: %v", err)
	}
	t.Setenv("TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", privateFile)
	return publicFile
}

// dodStartAuthorizedSoftwareSignerProcess starts the production persistent
// signer implementation in a separate address space and keeps the approval
// authority only in the parent process. Multiple DoD runtime slices reuse this
// AN-4/dual-control boundary instead of serving a signer goroutine in-process.
func dodStartAuthorizedSoftwareSignerProcess(t *testing.T, dir string) runSigner {
	t.Helper()
	authFile := filepath.Join(dir, "signer-auth.bin")
	parentAuthorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("load parent sign-token provider: %v", err)
	}
	t.Cleanup(parentAuthorizer.Destroy)
	return dodStartShippedSignerProcess(t, dir, "codesign", authFile, "", parentAuthorizer)
}

func dodGitHubOIDCIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate OIDC provider key: %v", err)
	}
	defer signer.Destroy()
	jwk, err := crypto.PublicJWK(signer.Public(), "dod-github-oidc-key")
	if err != nil {
		t.Fatalf("marshal OIDC public JWK: %v", err)
	}
	jwksJSON, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal OIDC JWKS: %v", err)
	}
	token, err := crypto.SignJWT(signer, "dod-github-oidc-key", map[string]any{
		"iss": githuboidc.DefaultIssuer, "aud": "sigstore", "exp": time.Now().Add(10 * time.Minute).Unix(),
		"sub": "repo:acme/payments:ref:refs/heads/main", "repository": "acme/payments", "repository_owner": "acme",
		"workflow": "release", "ref": "refs/heads/main", "sha": "0123456789abcdef0123456789abcdef01234567",
		"job_workflow_ref": "acme/payments/.github/workflows/release.yml@refs/heads/main", "runner_environment": "github-hosted",
	})
	if err != nil {
		t.Fatalf("sign GitHub OIDC identity: %v", err)
	}
	return []byte(token), jwksJSON
}

func dodCodeSigningRequest(t *testing.T, path, token, idempotencyKey string, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode code-signing request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("build code-signing request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func dodDecodeCodeSigningResponse(t *testing.T, status int, body []byte) api.CodeSigningResponse {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("code-signing status=%d body=%s", status, body)
	}
	var response api.CodeSigningResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode code-signing response: %v; body=%s", err, body)
	}
	if response.Algorithm == "" || response.ArtifactType == "" || len(response.Signature) == 0 || len(response.PublicKeyDER) == 0 {
		t.Fatalf("incomplete code-signing response: %+v", response)
	}
	return response
}

func dodVerifyCodeSigningSignature(t *testing.T, response api.CodeSigningResponse, digest []byte) {
	t.Helper()
	if err := crypto.VerifyDigest(
		crypto.PublicKey{Algorithm: crypto.Algorithm(response.Algorithm), DER: response.PublicKeyDER},
		digest, response.Signature,
		crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15},
	); err != nil {
		t.Fatalf("code-signing response does not verify over the exact supplied SHA-256 digest: %v", err)
	}
}

type dodHTTPRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *dodHTTPRecorder) Header() http.Header { return r.header }

func (r *dodHTTPRecorder) WriteHeader(status int) { r.status = status }

func (r *dodHTTPRecorder) Write(body []byte) (int, error) { return r.body.Write(body) }

func (r *dodHTTPRecorder) String() string {
	return fmt.Sprintf("status=%d body=%s", r.status, r.body.Bytes())
}
