//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const dodExternalCATenant = "d0d00000-0000-4000-8000-000000000101"

const (
	dodExternalSignerAzureVault = "https://dod.managedhsm.azure.net"
	dodEntrustTLSServerName     = "entrust.dod.test"
	dodEntrustTLSServerCertEnv  = "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE"
	dodEntrustTLSServerKeyEnv   = "TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE"
	dodEntrustTLSClientCAEnv    = "TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"
)

// TestDODExternalCAUniversalProductionAssembly is shared by the registry and 14
// granular external-CA census rows. Every literal entry starts an independent,
// nonce/entry/PID-bound OpenSSL-backed process. One untouched production
// buildRunDeps result is passed directly to Build, then each user-visible issue
// route proves its provider-specific wire exchange and independently verifies
// the returned leaf against that process's root.
func TestDODExternalCAUniversalProductionAssembly(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dodAssertExternalCANoRepoStateMutation(t, repo)
	secretDir := t.TempDir()
	entrustTLS, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), dodEntrustTLSServerName, time.Hour)
	if err != nil {
		t.Fatalf("generate Entrust substrate mTLS material: %v", err)
	}
	t.Setenv(dodEntrustTLSServerCertEnv, entrustTLS.Signer.CertFile)
	t.Setenv(dodEntrustTLSServerKeyEnv, entrustTLS.Signer.KeyFile)
	t.Setenv(dodEntrustTLSClientCAEnv, entrustTLS.Signer.PeerCAFile)

	registryExternal := proof.StartCommand(t, "external_ca.registry")
	adcsExternal := proof.StartCommand(t, "external_ca.adcs")
	awsExternal := proof.StartCommand(t, "external_ca.awspca")
	azureExternal := proof.StartCommand(t, "external_ca.azurekv")
	digicertExternal := proof.StartCommand(t, "external_ca.digicert")
	ejbcaExternal := proof.StartCommand(t, "external_ca.ejbca")
	entrustExternal := proof.StartCommand(t, "external_ca.entrust")
	gcpExternal := proof.StartCommand(t, "external_ca.gcpcas")
	globalSignExternal := proof.StartCommand(t, "external_ca.globalsign")
	letsEncryptExternal := proof.StartCommand(t, "external_ca.letsencrypt")
	sectigoExternal := proof.StartCommand(t, "external_ca.sectigo")
	shellExternal := proof.StartCommand(t, "external_ca.shellca")
	smallstepExternal := proof.StartCommand(t, "external_ca.smallstep")
	vaultExternal := proof.StartCommand(t, "external_ca.vaultpki")
	venafiExternal := proof.StartCommand(t, "external_ca.venafi")
	productionEndpoints := map[*proof.ExternalSubstrate]string{}
	productionEndpoint := func(external *proof.ExternalSubstrate) string {
		if endpoint := productionEndpoints[external]; endpoint != "" {
			return endpoint
		}
		endpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
		productionEndpoints[external] = endpoint
		return endpoint
	}

	dodRejectExternalCAMTLSWithoutClient(t, entrustExternal.Endpoint(), entrustTLS.ControlPlane.PeerCAFile, entrustTLS.ServerName)
	dodRejectExternalCAMTLSWithUntrustedClient(t, entrustExternal.Endpoint(), entrustTLS.ControlPlane.PeerCAFile, entrustTLS.ServerName)
	entrustIssuanceRoot := dodExternalCARootWithClient(t, entrustExternal.Endpoint(), dodExternalCAMTLSClient(t, entrustTLS.ControlPlane, entrustTLS.ServerName))

	signer := dodStartExternalCASigner(t, secretDir, productionEndpoint(azureExternal))
	managedAzure, err := signer.signer.Client().ManageKey(context.Background(), signing.ManagedKeyCommand{
		TenantID: dodExternalCATenant, Provider: "azure-key-vault", OperationID: "dod-external-ca-azure-key",
		Action: signing.ManagedKeyGenerate, Algorithm: crypto.RSA2048,
	})
	if err != nil {
		t.Fatalf("provision signer-local Azure CA ref: %v", err)
	}
	secretRef := dodExternalCASecretFile(t, secretDir, "provider-token", []byte("dod-token"))
	provisionerRef := dodExternalCASecretFile(t, secretDir, "provisioner-key", []byte("0123456789abcdef0123456789abcdef"))
	azureCAFile := filepath.Join(secretDir, "azure-managed-hsm-ca.pem")
	if err := os.WriteFile(azureCAFile, dodExternalCARoot(t, azureExternal.Endpoint()), 0o644); err != nil {
		t.Fatal(err)
	}
	shellCommand := filepath.Join(repo, "tools", "dodcensus", "substrates", "external_ca.py")
	network := func(external *proof.ExternalSubstrate) config.ExternalCANetworkConfig {
		return dodExternalCANetwork(t, productionEndpoint(external))
	}
	entrustNetwork := dodExternalCANetwork(t, productionEndpoint(entrustExternal))
	entrustNetwork.AllowInsecureHTTP = false
	entrustNetwork.RootCAFile = entrustTLS.ControlPlane.PeerCAFile
	entrustNetwork.ClientCertFile = entrustTLS.ControlPlane.CertFile
	entrustNetwork.ClientKeyFile = entrustTLS.ControlPlane.KeyFile
	entrustNetwork.ServerName = entrustTLS.ServerName
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(secretDir, "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(secretDir, "control-plane-issuing-ca.pem")
	cfg.Secrets.KEKFile = filepath.Join(secretDir, "control-plane-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(secretDir, "control-plane-signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(secretDir, "control-plane-sign-auth.bin")
	cfg.PCAS.Delegation.SignerStoreDir = filepath.Join(secretDir, "control-plane-pcas")
	cfg.ExternalCAs = []config.ExternalCAConfig{
		{ID: "registry", Type: "digicert", Name: "Registry Proof CA", Endpoint: productionEndpoint(registryExternal), APIKeyRef: secretRef, Network: network(registryExternal)},
		{ID: "adcs", Type: "adcs", Name: "ADCS", Endpoint: productionEndpoint(adcsExternal), CAConfig: `HOST\CA`, Template: "WebServer", Username: "dod-user", PasswordRef: secretRef, PollInterval: "1ms", Network: network(adcsExternal)},
		{ID: "awspca", Type: "awspca", Name: "AWS PCA", Endpoint: productionEndpoint(awsExternal), Region: "us-east-1", CertificateAuthorityARN: "arn:aws:acm-pca:us-east-1:123:certificate-authority/dod", AccessKeyID: "AKIADOD", SecretAccessKeyRef: secretRef, PollInterval: "1ms", Network: network(awsExternal)},
		{ID: "azurekv", Type: "azurekv", Name: "Azure Managed HSM CA", TenantID: dodExternalCATenant, Endpoint: productionEndpoint(azureExternal), ManagedKeyRef: managedAzure.KeyID, CACertFile: azureCAFile, Network: network(azureExternal)},
		{ID: "digicert", Type: "digicert", Name: "DigiCert", Endpoint: productionEndpoint(digicertExternal), APIKeyRef: secretRef, Network: network(digicertExternal)},
		{ID: "ejbca", Type: "ejbca", Name: "EJBCA", Endpoint: productionEndpoint(ejbcaExternal), BearerTokenRef: secretRef, CAName: "DodCA", CertificateProfile: "TLS", EndEntityProfile: "TLS", Network: network(ejbcaExternal)},
		{ID: "entrust", Type: "entrust", Name: "Entrust", Endpoint: productionEndpoint(entrustExternal), CAID: "dod-ca", PollInterval: "1ms", Network: entrustNetwork},
		{ID: "gcpcas", Type: "gcpcas", Name: "GCP CAS", Endpoint: productionEndpoint(gcpExternal), CAPool: "projects/dod/locations/us/caPools/dod", BearerTokenRef: secretRef, Network: network(gcpExternal)},
		{ID: "globalsign", Type: "globalsign", Name: "GlobalSign", Endpoint: productionEndpoint(globalSignExternal), APIKeyRef: secretRef, APISecretRef: secretRef, PollInterval: "1ms", Network: network(globalSignExternal)},
		{ID: "letsencrypt", Type: "letsencrypt", Name: "Let's Encrypt", DirectoryURL: productionEndpoint(letsEncryptExternal) + "/directory", Network: network(letsEncryptExternal)},
		{ID: "sectigo", Type: "sectigo", Name: "Sectigo", Endpoint: productionEndpoint(sectigoExternal), Login: "dod-login", PasswordRef: secretRef, CustomerURI: "dod-customer", OrgID: 1, CertType: 2, PollInterval: "1ms", Network: network(sectigoExternal)},
		{ID: "shellca", Type: "shellca", Name: "Shell CA", Command: shellCommand, Args: []string{"sign", "--endpoint", productionEndpoint(shellExternal)}, Network: config.ExternalCANetworkConfig{Timeout: "10s"}},
		{ID: "smallstep", Type: "smallstep", Name: "Smallstep", Endpoint: productionEndpoint(smallstepExternal), ProvisionerName: "dod-provisioner", ProvisionerKeyRef: provisionerRef, Network: network(smallstepExternal)},
		{ID: "vaultpki", Type: "vaultpki", Name: "Vault PKI", Endpoint: productionEndpoint(vaultExternal), BearerTokenRef: secretRef, Mount: "pki", Role: "dod-role", Network: network(vaultExternal)},
		{ID: "venafi", Type: "venafi", Name: "Venafi", Endpoint: productionEndpoint(venafiExternal), AccessTokenRef: secretRef, PolicyDN: `\VED\Policy\dod`, PollInterval: "1ms", Network: network(venafiExternal)},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("external CA production config: %v", err)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dispatcherCtx, cancelDispatcher := context.WithCancel(ctx)
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		srv.RunDispatcher(dispatcherCtx)
	}()
	t.Cleanup(func() {
		cancelDispatcher()
		<-dispatcherDone
	})
	token := dodExternalCAAPIToken(t, st)
	dodAssertExternalCACatalog(t, srv, token)
	csr := dodExternalCACSR(t, "dod.external-ca.test")

	dodProveExternalCA(t, srv, token, csr, "external_ca.registry", "registry", registryExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.adcs", "adcs", adcsExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.awspca", "awspca", awsExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.azurekv", "azurekv", azureExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.digicert", "digicert", digicertExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.ejbca", "ejbca", ejbcaExternal)
	dodProveExternalCAWithRoot(t, srv, token, csr, "external_ca.entrust", "entrust", entrustExternal, entrustIssuanceRoot)
	dodProveExternalCA(t, srv, token, csr, "external_ca.gcpcas", "gcpcas", gcpExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.globalsign", "globalsign", globalSignExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.letsencrypt", "letsencrypt", letsEncryptExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.sectigo", "sectigo", sectigoExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.shellca", "shellca", shellExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.smallstep", "smallstep", smallstepExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.vaultpki", "vaultpki", vaultExternal)
	dodProveExternalCA(t, srv, token, csr, "external_ca.venafi", "venafi", venafiExternal)
}

type dodExternalCAResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *dodExternalCAResponse) Header() http.Header { return w.header }
func (w *dodExternalCAResponse) WriteHeader(status int) {
	w.status = status
}
func (w *dodExternalCAResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func dodAssertExternalCACatalog(t *testing.T, srv *Server, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "/api/v1/external-cas", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := &dodExternalCAResponse{header: make(http.Header)}
	srv.Handler().ServeHTTP(response, request)
	var catalog struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if response.status != http.StatusOK || json.Unmarshal(response.body.Bytes(), &catalog) != nil {
		t.Fatalf("production external-CA catalog status=%d body=%s", response.status, response.body.Bytes())
	}
	for _, item := range catalog.Items {
		if item.ID == "registry" && item.Status == "available" {
			return
		}
	}
	t.Fatalf("production external-CA catalog omitted configured registry integration: %s", response.body.Bytes())
}

func dodAssertExternalCANoRepoStateMutation(t *testing.T, repo string) {
	t.Helper()
	dataRoot := filepath.Join(repo, "internal", "server", "data")
	before, err := dodManagedKeySnapshotTree(dataRoot)
	if err != nil {
		t.Fatalf("snapshot external-CA proof repository state: %v", err)
	}
	t.Cleanup(func() {
		after, snapshotErr := dodManagedKeySnapshotTree(dataRoot)
		if snapshotErr != nil {
			t.Errorf("snapshot external-CA proof repository state after run: %v", snapshotErr)
			return
		}
		if !dodManagedKeySnapshotsEqual(before, after) {
			t.Errorf("external-CA proof changed repository data tree; before=%v after=%v", before, after)
		}
	})
}

func dodStartExternalCASigner(t *testing.T, dir, azureEndpoint string) runSigner {
	t.Helper()
	privateLicenseKey, publicLicenseKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate external-CA proof license key: %v", err)
	}
	defer secret.Wipe(privateLicenseKey)
	rawLicense, err := license.Sign(license.Claims{
		V: 1, ID: "dod-external-ca-license", Customer: "DoD external CA runtime", Tier: license.TierEnterprise,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}, privateLicenseKey)
	if err != nil {
		t.Fatalf("sign external-CA proof license: %v", err)
	}
	licenseFile := filepath.Join(dir, "external-ca-enterprise-license.json")
	if err := os.WriteFile(licenseFile, rawLicense, 0o600); err != nil {
		t.Fatalf("write external-CA proof license: %v", err)
	}
	azureTokenFile := filepath.Join(dir, "azure-signer-token")
	if err := os.WriteFile(azureTokenFile, []byte("dod-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	network := dodExternalCANetwork(t, azureEndpoint)
	managedConfig, err := json.Marshal(config.ManagedKeys{
		Enabled: true, Provider: config.ManagedKeyProviderAzureKeyVault,
		Azure: config.ManagedKeysAzureKV{
			VaultURL: dodExternalSignerAzureVault, Endpoint: azureEndpoint,
			BearerTokenFile: azureTokenFile, PrivateEgressCIDRs: network.PrivateEgressCIDRs,
		},
	})
	if err != nil {
		t.Fatalf("marshal signer managed-key config: %v", err)
	}
	managedConfigFile := filepath.Join(dir, "external-signer-managed-keys.json")
	if err := os.WriteFile(managedConfigFile, managedConfig, 0o600); err != nil {
		t.Fatalf("write signer managed-key config: %v", err)
	}
	authFile := filepath.Join(dir, "external-signer-auth.bin")
	parentAuthorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("load parent external-CA sign-token provider: %v", err)
	}
	t.Cleanup(parentAuthorizer.Destroy)
	return dodStartShippedSignerProcess(t, dir, "external-ca", authFile, managedConfigFile, parentAuthorizer, dodShippedSignerLicense{
		file: licenseFile, trustedPublicKey: publicLicenseKey,
	})
}

func dodExternalCANetwork(t *testing.T, endpoint string) config.ExternalCANetworkConfig {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(u.Hostname())
	if err != nil || !address.Is4() || !address.IsLoopback() {
		t.Fatalf("external CA HTTP substrate must advertise a loopback address, got %q", endpoint)
	}
	return config.ExternalCANetworkConfig{
		AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()},
		AllowInsecureHTTP: true, Timeout: "10s",
	}
}

func dodExternalCASecretFile(t *testing.T, dir, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return "file:" + path
}

func dodExternalCAAPIToken(t *testing.T, st *store.Store) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: dodExternalCATenant, TokenHash: hash, Subject: "dod-external-ca-issuer",
		Scopes: []string{string(authz.CertsIssue), string(authz.IssuersRead)},
	}); err != nil {
		secret.Wipe(raw)
		t.Fatal(err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}

func dodExternalCACSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: []string{commonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
}

func dodProveExternalCA(t *testing.T, srv *Server, token string, csrPEM []byte, entryID, caID string, external *proof.ExternalSubstrate) {
	t.Helper()
	dodProveExternalCAWithRoot(t, srv, token, csrPEM, entryID, caID, external, nil)
}

func dodProveExternalCAWithRoot(t *testing.T, srv *Server, token string, csrPEM []byte, entryID, caID string, external *proof.ExternalSubstrate, rootPEM []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"csr_pem": string(csrPEM), "dns_names": []string{"dod.external-ca.test"}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/external-cas/" + caID + "/issue"
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "dod-"+strings.ReplaceAll(entryID, ".", "-"))
	session := proof.Start(t, entryID, srv.Handler(), req)
	if session.StatusCode() != http.StatusCreated {
		t.Fatalf("%s issue status = %d body=%s", entryID, session.StatusCode(), session.ResponseBody())
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(session.ResponseBody(), &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("%s invalid issued certificate: %v body=%s", entryID, err, session.ResponseBody())
	}
	leaf, _ := pem.Decode([]byte(issued.CertificatePEM))
	if len(rootPEM) == 0 {
		rootPEM = dodExternalCARoot(t, external.Endpoint())
	}
	root, _ := pem.Decode(rootPEM)
	if leaf == nil || root == nil {
		t.Fatalf("%s returned invalid leaf/root PEM", entryID)
	}
	if err := crypto.VerifyLeafSignedByCA(leaf.Bytes, root.Bytes); err != nil {
		t.Fatalf("%s chain verification: %v", entryID, err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.CAIssueChain(proof.CAIssueChainProbe{
		Leaf: leaf.Bytes, Chain: []byte(issued.CertificatePEM),
		Verification:     []byte(fmt.Sprintf("verified serial %s against independent OpenSSL substrate root", issued.Serial)),
		ExecutionReceipt: executionReceipt,
	}))
}

func dodExternalCARoot(t *testing.T, endpoint string) []byte {
	t.Helper()
	return dodExternalCARootWithClient(t, endpoint, &http.Client{Timeout: 5 * time.Second})
}

func dodExternalCARootWithClient(t *testing.T, endpoint string, client *http.Client) []byte {
	t.Helper()
	response, err := client.Get(endpoint + "/dod/root")
	if err != nil {
		t.Fatalf("read external CA substrate root: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("external CA substrate root status=%d err=%v", response.StatusCode, err)
	}
	return body
}

func dodExternalCAMTLSClient(t *testing.T, config mtls.SignerPeerConfig, serverName string) *http.Client {
	t.Helper()
	rootPEM, err := os.ReadFile(config.PeerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := mtls.LoadAgentIdentity("dod-entrust-client", config.KeyFile, config.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Destroy)
	transport, err := mtls.AgentHTTPTransport(identity, rootPEM, serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func dodRejectExternalCAMTLSWithoutClient(t *testing.T, endpoint, rootFile, serverName string) {
	t.Helper()
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.AgentHTTPTransport(nil, rootPEM, serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	dodRequireExternalCAMTLSRejection(t, "missing client certificate", endpoint, transport)
}

func dodRejectExternalCAMTLSWithUntrustedClient(t *testing.T, endpoint, rootFile, serverName string) {
	t.Helper()
	untrusted, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := mtls.LoadAgentIdentity("dod-untrusted-entrust-client", untrusted.ControlPlane.KeyFile, untrusted.ControlPlane.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Destroy)
	transport, err := mtls.AgentHTTPTransport(identity, rootPEM, serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	dodRequireExternalCAMTLSRejection(t, "untrusted client certificate", endpoint, transport)
}

func dodRequireExternalCAMTLSRejection(t *testing.T, name, endpoint string, transport http.RoundTripper) {
	t.Helper()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(endpoint + "/dod/root")
	if err != nil {
		return
	}
	_ = response.Body.Close()
	t.Fatalf("Entrust substrate accepted %s", name)
}
