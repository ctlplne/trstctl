// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type servedCAKeyImportOffer struct {
	CeremonyID string `json:"ceremony_id"`
	crypto.AuthenticatedKeyImportOffer
}

type servedCAImportSignerRoute struct {
	client atomic.Pointer[signing.Client]
}

func (r *servedCAImportSignerRoute) Client() *signing.Client { return r.client.Load() }

func startUnavailableImportTestSigner(t *testing.T, code codes.Code) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "trstctl-old-signer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, request any, call *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		switch call.FullMethod {
		case signerpb.SignerService_PrepareKeyImportV2_FullMethodName, signerpb.SignerService_ImportWrappedKeyV2_FullMethodName:
			return nil, status.Error(code, "CA import test peer response")
		default:
			return handler(ctx, request)
		}
	}))
	signerpb.RegisterSignerServiceServer(server, &signerpb.UnimplementedSignerServiceServer{})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		<-done
	})
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type servedImportSignerHost struct {
	cli        string
	binary     string
	storeArgs  []string
	authFile   string
	pin        string
	authorizer *crypto.SignAuthorizer
}

func newServedImportSignerHost(t *testing.T) servedImportSignerHost {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	store := filepath.Join(dir, "custody")
	for _, path := range []string{bin, store} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin+string(os.PathSeparator), "./cmd/trstctl-cli", "./cmd/trstctl-signer") // #nosec G204 -- fixed tool and package targets, output to this test's temporary directory (CWE-78)
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shipped trstctl-cli and trstctl-signer: %v\n%s", err, output)
	}
	kekPath := filepath.Join(dir, "custody-kek.bin")
	wrapper, err := kek.LoadOrCreate(kekPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapper.Destroy()
	authFile := filepath.Join(dir, "custody-authorization.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	host := servedImportSignerHost{
		cli: filepath.Join(bin, "trstctl-cli"), binary: filepath.Join(bin, "trstctl-signer"),
		storeArgs: []string{"--keystore", store, "--kek", kekPath}, authFile: authFile, authorizer: authorizer,
	}
	if runtime.GOOS != "linux" {
		host.storeArgs = append(host.storeArgs, "--allow-insecure-dev-nonlinux")
	}
	identity := func(flag string) (string, error) {
		args := append(append([]string{}, host.storeArgs...), flag)
		command := exec.CommandContext(t.Context(), host.binary, args...) // #nosec G204 -- this test executes a local signer it built in its private fixture (CWE-78)
		out, err := command.Output()
		return strings.TrimSpace(string(out)), err
	}
	if missing, err := identity("--import-offer-fingerprint"); err == nil || missing != "" {
		t.Fatal("fingerprint read must refuse a missing signer identity")
	}
	host.pin, err = identity("--init-import-offer-identity")
	if err != nil || len(host.pin) != 64 {
		t.Fatal("provision signer-host offer identity", err)
	}
	if repeated, err := identity("--init-import-offer-identity"); err != nil || repeated != host.pin {
		t.Fatal("provisioning changed the first signer-host identity", err)
	}
	if read, err := identity("--import-offer-fingerprint"); err != nil || read != host.pin {
		t.Fatal("read-only signer command did not return the durable pin", err)
	}
	return host
}

func (h servedImportSignerHost) start(t *testing.T) (*signing.Client, func()) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "trstctl-import-signer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	args := append(append([]string{}, h.storeArgs...), "--socket", socket, "--auth-secret", h.authFile)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, h.binary, args...) // #nosec G204 -- this test executes a local signer it built in its private fixture (CWE-78)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			if err := cmd.Wait(); err != nil && err != context.Canceled {
				t.Errorf("isolated signer shutdown: %v %s", err, stderr.String())
			}
		}
	}
	t.Cleanup(stop)
	client, err := signing.DialReady(t.Context(), socket, 25*time.Second)
	if err != nil {
		stop()
		t.Fatalf("dial isolated CA import signer: %v %s", err, stderr.String())
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, stop
}

func writeImportFixture(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A128 through the served binary: an operator's existing CA, with the private
// key it already has, becomes a signer-held authority. Two custodians approve
// the chain and profile; the signer offers a one-time import key; the operator
// seals the key to it off-box; the import opens it inside the signer, which
// must hold the certificate's key; and the imported authority issues leaves
// that chain to the operator's own certificate. The control plane only ever
// relays sealed bytes.
func TestServedCAKeyImportTakesAnOperatorsCAKeyIntoTheSigner(t *testing.T) {
	ctx := context.Background()
	host := newServedImportSignerHost(t)
	first, stopFirst := host.start(t)
	second, _ := host.start(t)
	signerRoute := &servedCAImportSignerRoute{}
	signerRoute.client.Store(first)
	h := newOperatingServedHarness(t, config.Protocols{}, func(deps *Deps) {
		deps.Signer = signerRoute
		deps.SignerMode = "external"
		deps.SignAuthorizer = nil
		deps.SignTokenProvider = host.authorizer
	})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-key-import-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-key-import-approver", []string{"issuers:write", "issuers:read", "certs:issue"})

	// The operator's existing root CA and its private key, outside trstctl.
	rootPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(rootPKCS8)
	rootKey, err := crypto.LockedKeyFromPKCS8(rootPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	profile := crypto.HierarchyCAProfile{
		CommonName: "operator existing root", MaxPathLen: 1, TTL: 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"keyimport.example.test"}, EKUs: []string{"serverAuth"},
	}
	root, err := crypto.SelfSignedHierarchyCA(rootKey, profile)
	if err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{
		"common_name": profile.CommonName, "max_path_len": profile.MaxPathLen,
		"ttl_seconds": int64(profile.TTL.Seconds()), "permitted_dns_domains": profile.PermittedDNSDomains,
		"extended_key_usages": profile.EKUs, "signature_algorithm": "ecdsa-p256",
	}
	certificatePEM := string(root.CertificatePEM)
	ceremony := createCACeremonyWithCertificate(t, h, operator, "import_ca_key", certificatePEM, spec, 1, "ca-key-import-ceremony")
	body := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key-offer", operator, "ca-key-import-offer-early", body); code != http.StatusConflict {
		t.Fatalf("key offer before quorum = %d body=%s; want 409", code, raw)
	}
	approveCACeremony(t, h, approver, ceremony.ID, 1, "ca-key-import-approval")

	// A mixed-version rollout and transient custody contention both return a
	// retry or upgrade instruction through the served HTTP problem response.
	for _, tc := range []struct {
		name string
		code codes.Code
		want string
	}{
		{"old", codes.Unimplemented, "upgrade the isolated signer"},
		{"busy", codes.Unavailable, "retry with the same Idempotency-Key"},
	} {
		signerRoute.client.Store(startUnavailableImportTestSigner(t, tc.code))
		ciphertext := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec, "sealed_key_v2": []byte("fixture ciphertext")}
		for action, request := range map[string]map[string]any{"key-offer": body, "key": ciphertext} {
			code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/"+action, operator, "ca-key-import-"+action+"-"+tc.name, request)
			if code != http.StatusServiceUnavailable || !strings.Contains(string(raw), tc.want) {
				t.Errorf("%s with %s signer status=%d response=%s, want 503 with %q", action, tc.name, code, raw, tc.want)
			}
		}
	}
	signerRoute.client.Store(first)
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key-offer", operator, "ca-key-import-offer", body)
	if code != http.StatusOK {
		t.Fatalf("key offer = %d body=%s; want 200", code, raw)
	}
	var offer servedCAKeyImportOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		t.Fatalf("decode offer: %v body=%s", err, raw)
	}
	if offer.Suite != crypto.AuthenticatedKeyImportSuite || len(offer.PublicKey) == 0 || offer.TenantID != h.tenant ||
		offer.OperationID != ceremony.ID || !bytes.Equal(offer.ExpectedPublicKey, rootKey.Public().DER) || offer.Handle == "" {
		t.Fatal("relayed offer does not match the approved ceremony")
	}
	offerJSON := bytes.Clone(raw)
	info, err := offer.Verify(host.pin, time.Now())
	if err != nil {
		t.Fatal("the relayed offer does not verify against the signer-host pin", err)
	}

	// A key that is not the certificate's is refused inside the signer.
	wrongPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(wrongPKCS8)
	wrongSealed, err := crypto.SealKeyImport(offer.PublicKey, info, wrongPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	wrong := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec, "sealed_key_v2": wrongSealed}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import-wrong", wrong); code != http.StatusUnprocessableEntity {
		t.Fatalf("import of a key that is not the certificate's = %d body=%s; want 422", code, raw)
	}

	// The shipped CLI authenticates the offer before touching the local key
	// path, then emits only the sealed key when given the genuine offer.
	wrapDir := t.TempDir()
	offerFile := filepath.Join(wrapDir, "offer.json")
	requestFile := filepath.Join(wrapDir, "request.json")
	privateFile := filepath.Join(wrapDir, "ca.pem")
	requestJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	writeImportFixture(t, requestFile, requestJSON)
	offer.Signature[0] ^= 1
	altered, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	writeImportFixture(t, offerFile, altered)
	wrap := func() ([]byte, string, error) {
		cmd := exec.CommandContext(t.Context(), host.cli, "ca", "authorities", "wrap-key", // #nosec G204 -- the test compiles and executes the local CLI in an isolated fixture (CWE-78)
			"--offer", offerFile, "--key", privateFile, "--request", requestFile, "--tenant-id", h.tenant, "--signer-fingerprint", host.pin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return out, stderr.String(), err
	}
	if output, stderr, err := wrap(); err == nil || len(output) != 0 ||
		!strings.Contains(stderr, "invalid key import offer signature") || strings.Contains(stderr, "read private key") {
		t.Fatalf("the CLI did not refuse the altered public offer before opening the absent key: %v %s", err, stderr)
	}
	writeImportFixture(t, offerFile, offerJSON)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootPKCS8})
	defer secret.Wipe(pemKey)
	writeImportFixture(t, privateFile, pemKey)
	encoded, stderr, err := wrap()
	if err != nil {
		t.Fatalf("wrap the genuine signed offer: %v %s", err, stderr)
	}
	if bytes.Contains(encoded, rootPKCS8) || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(rootPKCS8)) {
		t.Fatal("the import request carries the plaintext private key")
	}
	var request map[string]any
	if err := json.Unmarshal(encoded, &request); err != nil || request["sealed_key_v2"] == nil || request["sealed_key"] != nil {
		t.Fatal("the CLI did not produce the v2-only import request", err)
	}
	legacy := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec, "sealed_key": wrongSealed}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import-legacy", legacy); code != http.StatusUnprocessableEntity {
		t.Fatalf("legacy import status = %d, want 422", code)
	}
	code, raw = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import", request)
	if code != http.StatusCreated {
		t.Fatalf("import CA key = %d body=%s; want 201", code, raw)
	}
	if retryCode, retry := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import", request); retryCode != code || !bytes.Equal(retry, raw) {
		t.Fatalf("exact HTTP retry status = %d, want the original %d response", retryCode, code)
	}
	var imported servedCAAuthority
	if err := json.Unmarshal(raw, &imported); err != nil {
		t.Fatalf("decode imported authority: %v body=%s", err, raw)
	}
	if imported.Status != "active" || imported.Kind != "root" || imported.SignerHandle != offer.Handle ||
		imported.PossessionProof != "signer_challenge" {
		t.Fatalf("imported authority = %+v", imported)
	}

	// The signer holds the operator's key: it reports that public key, and
	// leaves it issues chain to the operator's own certificate.
	remote, err := second.SignerForHandle(ctx, offer.Handle)
	if err != nil || !bytes.Equal(remote.Public().DER, rootKey.Public().DER) {
		t.Fatalf("signer holds %v for the imported handle, %v; want the operator's key", remote, err)
	}
	leaf := issueHierarchyLeaf(t, h, operator, imported.ID, "leaf.keyimport.example.test", "ca-key-import-leaf")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(leaf.CertificatePEM)), root.CertificateDER); err != nil {
		t.Fatalf("a leaf of the imported authority does not chain to the operator's certificate: %v", err)
	}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import-again", request); code != http.StatusConflict {
		t.Fatalf("a second import under the used ceremony = %d body=%s; want 409", code, raw)
	}
	if _, err := second.GenerateKeyHandle(ctx, crypto.ECDSAP256, offer.Handle); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a different process attempted a generic create after import, status = %v", status.Code(err))
	}
	stopFirst()
	restarted, _ := host.start(t)
	ca, err := restarted.SignerForOwnedDualControlCAHandle(ctx, h.tenant, offer.Handle, host.authorizer)
	if err != nil || !ca.RequiresAuthorization() || !bytes.Equal(ca.Public().DER, rootKey.Public().DER) {
		t.Fatal("the restarted signer did not restore the tenant-owned dual-control CA key", err)
	}
	if _, err := restarted.SignerForOwnedDualControlCAHandle(ctx, "44444444-4444-4444-8444-444444444444", offer.Handle, host.authorizer); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("neighbor looked up the imported CA key after signer restart: %v; want PermissionDenied", err)
	}
	digest := crypto.SHA256Sum([]byte("served CA import restart proof"))
	if _, err := ca.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatal("the authorized CA purpose failed after restart", err)
	}
	unattested, err := restarted.SignerForHandleWithPurpose(ctx, offer.Handle, signing.PurposeCASign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unattested.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("the restarted signer accepted CA signing without authorization")
	}
	tls, err := restarted.SignerForHandleWithPurpose(ctx, offer.Handle, signing.PurposeLeafTLS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("imported key sign under a different purpose = %v, want FailedPrecondition", status.Code(err))
	}
}
