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
	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	dodADCSTLSServerName        = "adcs.dod.test"
	dodADCSTLSServerCertEnv     = "TRSTCTL_ADCS_TLS_SERVER_CERT_FILE"
	dodADCSTLSServerKeyEnv      = "TRSTCTL_ADCS_TLS_SERVER_KEY_FILE"
	dodExternalSignerAzureVault = "https://dod.managedhsm.azure.net"
	dodEntrustTLSServerName     = "entrust.dod.test"
	dodEntrustTLSServerCertEnv  = "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE"
	dodEntrustTLSServerKeyEnv   = "TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE"
	dodEntrustTLSClientCAEnv    = "TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"
)

var dodExternalCAEntryIDs = [...]string{
	"external_ca.registry",
	"external_ca.adcs",
	"external_ca.awspca",
	"external_ca.azurekv",
	"external_ca.digicert",
	"external_ca.ejbca",
	"external_ca.entrust",
	"external_ca.gcpcas",
	"external_ca.globalsign",
	"external_ca.letsencrypt",
	"external_ca.sectigo",
	"external_ca.shellca",
	"external_ca.smallstep",
	"external_ca.vaultpki",
	"external_ca.venafi",
}

type dodExternalCARuntimeCase struct {
	entryID  string
	caID     string
	external *proof.ExternalSubstrate
	rootPEM  []byte
}

type dodExternalCACSRMaterial struct {
	PEM       []byte
	DER       []byte
	PublicDER []byte
}

func dodExternalCASelection(only string) (map[string]struct{}, error) {
	all := make(map[string]struct{}, len(dodExternalCAEntryIDs))
	for _, id := range dodExternalCAEntryIDs {
		all[id] = struct{}{}
	}
	if only == "" {
		return all, nil
	}
	if _, ok := all[only]; !ok {
		return nil, fmt.Errorf("unknown external-CA census selection %q", only)
	}
	return map[string]struct{}{only: {}}, nil
}

func dodExternalCAEndpointIfSelected(resolve func(*proof.ExternalSubstrate) string, external *proof.ExternalSubstrate) string {
	if external == nil {
		return ""
	}
	return resolve(external)
}

func dodExternalCANetworkIfSelected(resolve func(*proof.ExternalSubstrate) config.ExternalCANetworkConfig, external *proof.ExternalSubstrate) config.ExternalCANetworkConfig {
	if external == nil {
		return config.ExternalCANetworkConfig{}
	}
	return resolve(external)
}

func TestExternalCARuntimeSelectionIsExactAndClosed(t *testing.T) {
	all, err := dodExternalCASelection("")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(dodExternalCAEntryIDs) {
		t.Fatalf("full external-CA selection has %d unique cases, want %d", len(all), len(dodExternalCAEntryIDs))
	}
	for _, id := range dodExternalCAEntryIDs {
		exact, exactErr := dodExternalCASelection(id)
		if exactErr != nil {
			t.Fatalf("select %s: %v", id, exactErr)
		}
		if len(exact) != 1 {
			t.Fatalf("selection %s contains %d cases, want one", id, len(exact))
		}
		if _, ok := exact[id]; !ok {
			t.Fatalf("selection %s omitted its exact case", id)
		}
	}
	if selected, err := dodExternalCASelection("external_ca.unknown"); err == nil || selected != nil {
		t.Fatalf("unknown external-CA selection returned cases=%v err=%v", selected, err)
	}
}

func dodStartExternalCARegistry(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.registry" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.registry")
}

func dodStartExternalCAADCS(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.adcs" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.adcs")
}

func dodStartExternalCAAWSPCA(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.awspca" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.awspca")
}

func dodStartExternalCAAzureKV(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.azurekv" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.azurekv")
}

func dodStartExternalCADigiCert(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.digicert" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.digicert")
}

func dodStartExternalCAEJBCA(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.ejbca" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.ejbca")
}

func dodStartExternalCAEntrust(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.entrust" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.entrust")
}

func dodStartExternalCAGCPCAS(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.gcpcas" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.gcpcas")
}

func dodStartExternalCAGlobalSign(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.globalsign" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.globalsign")
}

func dodStartExternalCALetsEncrypt(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.letsencrypt" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.letsencrypt")
}

func dodStartExternalCASectigo(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.sectigo" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.sectigo")
}

func dodStartExternalCAShellCA(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.shellca" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.shellca")
}

func dodStartExternalCASmallstep(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.smallstep" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.smallstep")
}

func dodStartExternalCAVaultPKI(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.vaultpki" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.vaultpki")
}

func dodStartExternalCAVenafi(t *testing.T, only string) *proof.ExternalSubstrate {
	t.Helper()
	if only != "" && only != "external_ca.venafi" {
		return nil
	}
	return proof.StartCommand(t, "external_ca.venafi")
}

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
	// Keep the literal empty initialization: the static wiring tracer evaluates
	// every branch, while the gate-owned runtime envelope replaces it with the
	// one exact selected ID during a focused census.
	only := ""
	only = proof.OnlyExpectation(t)
	selected, err := dodExternalCASelection(only)
	if err != nil {
		t.Fatalf("select external-CA runtime case: %v", err)
	}
	secretDir := t.TempDir()
	var adcsTLS *mtls.SignerPeerMaterial
	if _, ok := selected["external_ca.adcs"]; ok {
		adcsTLS, err = mtls.GenerateSignerPeerMaterial(t.TempDir(), dodADCSTLSServerName, time.Hour)
		if err != nil {
			t.Fatalf("generate AD CS substrate TLS material: %v", err)
		}
		t.Setenv(dodADCSTLSServerCertEnv, adcsTLS.Signer.CertFile)
		t.Setenv(dodADCSTLSServerKeyEnv, adcsTLS.Signer.KeyFile)
	}
	var entrustTLS *mtls.SignerPeerMaterial
	if _, ok := selected["external_ca.entrust"]; ok {
		entrustTLS, err = mtls.GenerateSignerPeerMaterial(t.TempDir(), dodEntrustTLSServerName, time.Hour)
		if err != nil {
			t.Fatalf("generate Entrust substrate mTLS material: %v", err)
		}
		t.Setenv(dodEntrustTLSServerCertEnv, entrustTLS.Signer.CertFile)
		t.Setenv(dodEntrustTLSServerKeyEnv, entrustTLS.Signer.KeyFile)
		t.Setenv(dodEntrustTLSClientCAEnv, entrustTLS.Signer.PeerCAFile)
	}
	registryExternal := dodStartExternalCARegistry(t, only)
	adcsExternal := dodStartExternalCAADCS(t, only)
	awsExternal := dodStartExternalCAAWSPCA(t, only)
	azureExternal := dodStartExternalCAAzureKV(t, only)
	digicertExternal := dodStartExternalCADigiCert(t, only)
	ejbcaExternal := dodStartExternalCAEJBCA(t, only)
	entrustExternal := dodStartExternalCAEntrust(t, only)
	gcpExternal := dodStartExternalCAGCPCAS(t, only)
	globalSignExternal := dodStartExternalCAGlobalSign(t, only)
	letsEncryptExternal := dodStartExternalCALetsEncrypt(t, only)
	sectigoExternal := dodStartExternalCASectigo(t, only)
	shellExternal := dodStartExternalCAShellCA(t, only)
	smallstepExternal := dodStartExternalCASmallstep(t, only)
	vaultExternal := dodStartExternalCAVaultPKI(t, only)
	venafiExternal := dodStartExternalCAVenafi(t, only)
	var adcsIssuanceRoot []byte
	if adcsExternal != nil {
		adcsIssuanceRoot = dodExternalCARootWithClient(t, adcsExternal.Endpoint(), dodExternalCATLSClient(t, adcsTLS.ControlPlane.PeerCAFile, adcsTLS.ServerName))
	}
	productionEndpoints := map[*proof.ExternalSubstrate]string{}
	productionEndpoint := func(external *proof.ExternalSubstrate) string {
		if external == nil {
			t.Fatal("selected external-CA runtime case has no substrate")
		}
		if endpoint := productionEndpoints[external]; endpoint != "" {
			return endpoint
		}
		endpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
		productionEndpoints[external] = endpoint
		return endpoint
	}

	var entrustIssuanceRoot []byte
	if entrustExternal != nil {
		dodRejectExternalCAMTLSWithoutClient(t, entrustExternal.Endpoint(), entrustTLS.ControlPlane.PeerCAFile, entrustTLS.ServerName)
		dodRejectExternalCAMTLSWithUntrustedClient(t, entrustExternal.Endpoint(), entrustTLS.ControlPlane.PeerCAFile, entrustTLS.ServerName)
		entrustIssuanceRoot = dodExternalCARootWithClient(t, entrustExternal.Endpoint(), dodExternalCAMTLSClient(t, entrustTLS.ControlPlane, entrustTLS.ServerName))
	}

	var signer runSigner
	var managedAzureKeyID string
	if azureExternal != nil {
		signer = dodStartExternalCASigner(t, secretDir, productionEndpoint(azureExternal))
		managedAzure, manageErr := signer.signer.Client().ManageKey(context.Background(), signing.ManagedKeyCommand{
			TenantID: dodExternalCATenant, Provider: "azure-key-vault", OperationID: "dod-external-ca-azure-key",
			Action: signing.ManagedKeyGenerate, Algorithm: crypto.RSA2048,
		})
		if manageErr != nil {
			t.Fatalf("provision signer-local Azure CA ref: %v", manageErr)
		}
		managedAzureKeyID = managedAzure.KeyID
	} else {
		signer = dodStartAuthorizedSoftwareSignerProcess(t, secretDir)
	}
	secretRef := dodExternalCASecretFile(t, secretDir, "provider-token", []byte("dod-token"))
	provisionerRef := dodExternalCASecretFile(t, secretDir, "provisioner-key", []byte("0123456789abcdef0123456789abcdef"))
	shellCommand := filepath.Join(repo, "tools", "dodcensus", "substrates", "external_ca.py")
	network := func(external *proof.ExternalSubstrate) config.ExternalCANetworkConfig {
		return dodExternalCANetwork(t, productionEndpoint(external))
	}
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(secretDir, "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(secretDir, "control-plane-issuing-ca.pem")
	cfg.Secrets.KEKFile = filepath.Join(secretDir, "control-plane-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(secretDir, "control-plane-signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(secretDir, "control-plane-sign-auth.bin")
	cfg.PCAS.Delegation.SignerStoreDir = filepath.Join(secretDir, "control-plane-pcas")
	cases := make([]dodExternalCARuntimeCase, 0, len(selected))
	addCase := func(entryID, caID string, external *proof.ExternalSubstrate, caConfig config.ExternalCAConfig, rootPEM []byte) {
		if external == nil {
			return
		}
		cfg.ExternalCAs = append(cfg.ExternalCAs, caConfig)
		cases = append(cases, dodExternalCARuntimeCase{entryID: entryID, caID: caID, external: external, rootPEM: rootPEM})
	}
	endpoint := func(external *proof.ExternalSubstrate) string {
		return dodExternalCAEndpointIfSelected(productionEndpoint, external)
	}
	selectedNetwork := func(external *proof.ExternalSubstrate) config.ExternalCANetworkConfig {
		return dodExternalCANetworkIfSelected(network, external)
	}
	addCase("external_ca.registry", "registry", registryExternal, config.ExternalCAConfig{ID: "registry", Type: "digicert", Name: "Registry Proof CA", Endpoint: endpoint(registryExternal), APIKeyRef: secretRef, Network: selectedNetwork(registryExternal)}, nil)
	if adcsExternal != nil {
		adcsNetwork := dodExternalCANetwork(t, productionEndpoint(adcsExternal))
		adcsNetwork.AllowInsecureHTTP = false
		adcsNetwork.RootCAFile = adcsTLS.ControlPlane.PeerCAFile
		adcsNetwork.ServerName = adcsTLS.ServerName
		addCase("external_ca.adcs", "adcs", adcsExternal, config.ExternalCAConfig{ID: "adcs", Type: "adcs", Name: "ADCS", Endpoint: productionEndpoint(adcsExternal), CAConfig: `HOST\CA`, Template: "WebServer", Username: "dod-user", PasswordRef: secretRef, PollInterval: "1ms", Network: adcsNetwork}, nil)
	}
	addCase("external_ca.awspca", "awspca", awsExternal, config.ExternalCAConfig{ID: "awspca", Type: "awspca", Name: "AWS PCA", Endpoint: endpoint(awsExternal), Region: "us-east-1", CertificateAuthorityARN: "arn:aws:acm-pca:us-east-1:123:certificate-authority/dod", AccessKeyID: "AKIADOD", SecretAccessKeyRef: secretRef, PollInterval: "1ms", Network: selectedNetwork(awsExternal)}, nil)
	if azureExternal != nil {
		azureCAFile := filepath.Join(secretDir, "azure-managed-hsm-ca.pem")
		if err := os.WriteFile(azureCAFile, dodExternalCARoot(t, azureExternal.Endpoint()), 0o644); err != nil {
			t.Fatal(err)
		}
		addCase("external_ca.azurekv", "azurekv", azureExternal, config.ExternalCAConfig{ID: "azurekv", Type: "azurekv", Name: "Azure Managed HSM CA", TenantID: dodExternalCATenant, Endpoint: productionEndpoint(azureExternal), ManagedKeyRef: managedAzureKeyID, CACertFile: azureCAFile, Network: network(azureExternal)}, nil)
	}
	addCase("external_ca.digicert", "digicert", digicertExternal, config.ExternalCAConfig{ID: "digicert", Type: "digicert", Name: "DigiCert", Endpoint: endpoint(digicertExternal), APIKeyRef: secretRef, Network: selectedNetwork(digicertExternal)}, nil)
	addCase("external_ca.ejbca", "ejbca", ejbcaExternal, config.ExternalCAConfig{ID: "ejbca", Type: "ejbca", Name: "EJBCA", Endpoint: endpoint(ejbcaExternal), BearerTokenRef: secretRef, CAName: "DodCA", CertificateProfile: "TLS", EndEntityProfile: "TLS", Network: selectedNetwork(ejbcaExternal)}, nil)
	if entrustExternal != nil {
		entrustNetwork := dodExternalCANetwork(t, productionEndpoint(entrustExternal))
		entrustNetwork.AllowInsecureHTTP = false
		entrustNetwork.RootCAFile = entrustTLS.ControlPlane.PeerCAFile
		entrustNetwork.ClientCertFile = entrustTLS.ControlPlane.CertFile
		entrustNetwork.ClientKeyFile = entrustTLS.ControlPlane.KeyFile
		entrustNetwork.ServerName = entrustTLS.ServerName
		addCase("external_ca.entrust", "entrust", entrustExternal, config.ExternalCAConfig{ID: "entrust", Type: "entrust", Name: "Entrust", Endpoint: productionEndpoint(entrustExternal), CAID: "dod-ca", PollInterval: "1ms", Network: entrustNetwork}, entrustIssuanceRoot)
	}
	addCase("external_ca.gcpcas", "gcpcas", gcpExternal, config.ExternalCAConfig{ID: "gcpcas", Type: "gcpcas", Name: "GCP CAS", Endpoint: endpoint(gcpExternal), CAPool: "projects/dod/locations/us/caPools/dod", BearerTokenRef: secretRef, Network: selectedNetwork(gcpExternal)}, nil)
	addCase("external_ca.globalsign", "globalsign", globalSignExternal, config.ExternalCAConfig{ID: "globalsign", Type: "globalsign", Name: "GlobalSign", Endpoint: endpoint(globalSignExternal), APIKeyRef: secretRef, APISecretRef: secretRef, PollInterval: "1ms", Network: selectedNetwork(globalSignExternal)}, nil)
	letsEncryptEndpoint := endpoint(letsEncryptExternal)
	if letsEncryptEndpoint != "" {
		letsEncryptEndpoint += "/directory"
	}
	addCase("external_ca.letsencrypt", "letsencrypt", letsEncryptExternal, config.ExternalCAConfig{ID: "letsencrypt", Type: "letsencrypt", Name: "Let's Encrypt", DirectoryURL: letsEncryptEndpoint, Network: selectedNetwork(letsEncryptExternal)}, nil)
	addCase("external_ca.sectigo", "sectigo", sectigoExternal, config.ExternalCAConfig{ID: "sectigo", Type: "sectigo", Name: "Sectigo", Endpoint: endpoint(sectigoExternal), Login: "dod-login", PasswordRef: secretRef, CustomerURI: "dod-customer", OrgID: 1, CertType: 2, PollInterval: "1ms", Network: selectedNetwork(sectigoExternal)}, nil)
	var shellArgs []string
	if shellExternal != nil {
		shellArgs = []string{"sign", "--endpoint", productionEndpoint(shellExternal)}
	}
	addCase("external_ca.shellca", "shellca", shellExternal, config.ExternalCAConfig{ID: "shellca", Type: "shellca", Name: "Shell CA", Command: shellCommand, Args: shellArgs, Network: config.ExternalCANetworkConfig{Timeout: "10s"}}, nil)
	addCase("external_ca.smallstep", "smallstep", smallstepExternal, config.ExternalCAConfig{ID: "smallstep", Type: "smallstep", Name: "Smallstep", Endpoint: endpoint(smallstepExternal), ProvisionerName: "dod-provisioner", ProvisionerKeyRef: provisionerRef, Network: selectedNetwork(smallstepExternal)}, nil)
	addCase("external_ca.vaultpki", "vaultpki", vaultExternal, config.ExternalCAConfig{ID: "vaultpki", Type: "vaultpki", Name: "Vault PKI", Endpoint: endpoint(vaultExternal), BearerTokenRef: secretRef, Mount: "pki", Role: "dod-role", Network: selectedNetwork(vaultExternal)}, nil)
	addCase("external_ca.venafi", "venafi", venafiExternal, config.ExternalCAConfig{ID: "venafi", Type: "venafi", Name: "Venafi", Endpoint: endpoint(venafiExternal), AccessTokenRef: secretRef, PolicyDN: `\VED\Policy\dod`, PollInterval: "1ms", Network: selectedNetwork(venafiExternal)}, nil)
	if len(cases) != len(selected) {
		t.Fatalf("external-CA selection matched %d runtime cases, want %d", len(cases), len(selected))
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
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	t.Cleanup(runSecrets.Close)
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
	dodAssertExternalCACatalog(t, srv, token, cases)
	csr := dodExternalCACSR(t, "dod.external-ca.test")

	if only == "" || only == "external_ca.registry" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.registry", "registry", registryExternal)
	}
	if only == "" || only == "external_ca.adcs" {
		dodProveExternalCAWithRoot(t, srv, token, csr, "external_ca.adcs", "adcs", adcsExternal, adcsIssuanceRoot)
	}
	if only == "" || only == "external_ca.awspca" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.awspca", "awspca", awsExternal)
	}
	if only == "" || only == "external_ca.azurekv" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.azurekv", "azurekv", azureExternal)
	}
	if only == "" || only == "external_ca.digicert" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.digicert", "digicert", digicertExternal)
	}
	if only == "" || only == "external_ca.ejbca" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.ejbca", "ejbca", ejbcaExternal)
	}
	if only == "" || only == "external_ca.entrust" {
		dodProveExternalCAWithRoot(t, srv, token, csr, "external_ca.entrust", "entrust", entrustExternal, entrustIssuanceRoot)
	}
	if only == "" || only == "external_ca.gcpcas" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.gcpcas", "gcpcas", gcpExternal)
	}
	if only == "" || only == "external_ca.globalsign" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.globalsign", "globalsign", globalSignExternal)
	}
	if only == "" || only == "external_ca.letsencrypt" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.letsencrypt", "letsencrypt", letsEncryptExternal)
	}
	if only == "" || only == "external_ca.sectigo" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.sectigo", "sectigo", sectigoExternal)
	}
	if only == "" || only == "external_ca.shellca" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.shellca", "shellca", shellExternal)
	}
	if only == "" || only == "external_ca.smallstep" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.smallstep", "smallstep", smallstepExternal)
	}
	if only == "" || only == "external_ca.vaultpki" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.vaultpki", "vaultpki", vaultExternal)
	}
	if only == "" || only == "external_ca.venafi" {
		dodProveExternalCA(t, srv, token, csr, "external_ca.venafi", "venafi", venafiExternal)
	}
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

func dodAssertExternalCACatalog(t *testing.T, srv *Server, token string, cases []dodExternalCARuntimeCase) {
	t.Helper()
	if len(cases) == 0 {
		t.Fatal("external-CA catalog assertion has no selected runtime case")
	}
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
	available := make(map[string]struct{}, len(catalog.Items))
	registryAvailable := false
	for _, item := range catalog.Items {
		if item.Status == "available" {
			available[item.ID] = struct{}{}
		}
		if item.ID == "registry" && item.Status == "available" {
			registryAvailable = true
		}
	}
	if len(cases) == len(dodExternalCAEntryIDs) && !registryAvailable {
		t.Fatalf("production external-CA catalog omitted configured registry integration: %s", response.body.Bytes())
	}
	for _, runtimeCase := range cases {
		if _, ok := available[runtimeCase.caID]; !ok {
			t.Fatalf("production external-CA catalog omitted selected %q integration: %s", runtimeCase.caID, response.body.Bytes())
		}
	}
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
			// azureEndpoint is the literal 127.0.0.1 listener created by
			// dodParentSubstrateLoopbackBridge. The signer deliberately opts in
			// to plaintext only for that test-owned loopback hop; the helper above
			// rejects host.docker.internal and every other non-loopback endpoint.
			AllowInsecureLoopback: true,
			BearerTokenFile:       azureTokenFile,
			PrivateEgressCIDRs:    network.PrivateEgressCIDRs,
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

func dodExternalCACSR(t *testing.T, commonName string) dodExternalCACSRMaterial {
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
	public := key.Public()
	if len(public.DER) == 0 {
		t.Fatal("external-CA CSR key returned no public DER")
	}
	return dodExternalCACSRMaterial{
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
		DER: bytes.Clone(csr), PublicDER: bytes.Clone(public.DER),
	}
}

func dodProveExternalCA(t *testing.T, srv *Server, token string, csr dodExternalCACSRMaterial, entryID, caID string, external *proof.ExternalSubstrate) {
	t.Helper()
	dodProveExternalCAWithRoot(t, srv, token, csr, entryID, caID, external, nil)
}

func dodProveExternalCAWithRoot(t *testing.T, srv *Server, token string, csr dodExternalCACSRMaterial, entryID, caID string, external *proof.ExternalSubstrate, rootPEM []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"csr_pem": string(csr.PEM), "dns_names": []string{"dod.external-ca.test"}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
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
	chain, err := dodExactIssuedCertificatePEMChain([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatalf("%s returned a non-exact certificate chain (certificates=%d): %v", entryID, len(chain), err)
	}
	if len(rootPEM) == 0 {
		rootPEM = dodExternalCARoot(t, external.Endpoint())
	}
	roots, err := dodExactCertificatePEMChain(rootPEM)
	if err != nil || len(roots) != 1 {
		t.Fatalf("%s independent substrate returned a non-exact root PEM (certificates=%d): %v", entryID, len(roots), err)
	}
	leaf := chain[0]
	root := roots[0]
	if !bytes.Equal(chain[len(chain)-1], root) {
		t.Fatalf("%s returned chain does not terminate at the independently fetched substrate root", entryID)
	}
	if err := crypto.VerifyLeafSignedByCA(leaf, root); err != nil {
		t.Fatalf("%s chain verification: %v", entryID, err)
	}
	leafPublic, err := crypto.PublicKeyDERFromCert(leaf)
	if err != nil || !bytes.Equal(leafPublic, csr.PublicDER) {
		t.Fatalf("%s issued leaf public key does not match the caller-owned CSR key: %v", entryID, err)
	}
	info, err := certinfo.Inspect(leaf)
	if err != nil {
		t.Fatalf("%s inspect issued leaf: %v", entryID, err)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "dod.external-ca.test" || len(info.IPAddresses) != 0 || len(info.EmailAddresses) != 0 || len(info.URIs) != 0 {
		t.Fatalf("%s issued leaf SANs do not exactly match the request: dns=%v ip=%v email=%v uri=%v", entryID, info.DNSNames, info.IPAddresses, info.EmailAddresses, info.URIs)
	}
	if info.SerialNumber != issued.Serial {
		t.Fatalf("%s response serial %q differs from issued leaf serial %q", entryID, issued.Serial, info.SerialNumber)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.CAIssueChain(proof.CAIssueChainProbe{
		Leaf: leaf, Chain: []byte(issued.CertificatePEM),
		Verification:     []byte(fmt.Sprintf("verified CSR key, exact DNS SAN, serial %s, and exact chain terminus against independent OpenSSL substrate root", issued.Serial)),
		ExecutionReceipt: executionReceipt,
	}))
}

func dodExactCertificatePEMChain(raw []byte) ([][]byte, error) {
	remaining := raw
	chain := make([][]byte, 0, 2)
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("non-certificate data appears in PEM chain")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return nil, fmt.Errorf("invalid certificate PEM block")
		}
		chain = append(chain, bytes.Clone(block.Bytes))
		remaining = rest
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("certificate PEM chain is empty")
	}
	return chain, nil
}

func dodExactIssuedCertificatePEMChain(raw []byte) ([][]byte, error) {
	chain, err := dodExactCertificatePEMChain(raw)
	if err != nil {
		return nil, err
	}
	if len(chain) != 2 {
		return nil, fmt.Errorf("issued chain contains %d certificates, want exact leaf and root", len(chain))
	}
	return chain, nil
}

func TestExternalCAExactCertificatePEMChainRejectsNonCertificateMaterial(t *testing.T) {
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	second := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{4, 5, 6}})
	exact := append(append([]byte(nil), certificate...), second...)
	chain, err := dodExactIssuedCertificatePEMChain(exact)
	if err != nil || len(chain) != 2 {
		t.Fatalf("exact two-certificate chain rejected: certificates=%d err=%v", len(chain), err)
	}
	for name, raw := range map[string][]byte{
		"empty":              nil,
		"leading garbage":    append([]byte("garbage\n"), certificate...),
		"trailing garbage":   append(append([]byte(nil), certificate...), []byte("garbage\n")...),
		"non-certificate":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"certificate header": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X-Test": "bad"}, Bytes: []byte{1}}),
		"extra certificate":  append(append([]byte(nil), exact...), certificate...),
	} {
		if parsed, parseErr := dodExactIssuedCertificatePEMChain(raw); parseErr == nil {
			t.Errorf("%s parsed as %d certificates", name, len(parsed))
		}
	}
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

func dodExternalCATLSClient(t *testing.T, rootFile, serverName string) *http.Client {
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
