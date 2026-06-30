// Command trstctl-agent is the in-network agent.
//
// The agent registers with the control plane (bootstrap token; attestation is a
// later addition), communicates over mTLS with a short-lived, auto-rotating
// client certificate, and performs all key operations locally so that private
// keys never leave the host. On Windows it can run under the Service Control
// Manager (--service); see service_windows.go. Discovery, deployment, SSH
// trust, and drift reconciliation build on this core in later sprints.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/secretinject"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	service := flag.String("service", "", "Windows service control: install | uninstall | run")
	enrollURL := flag.String("enroll-url", "", "control-plane enrollment base URL")
	token := flag.String("bootstrap-token", "", "development-only inline bootstrap token; use --bootstrap-token-file")
	tokenFile := flag.String("bootstrap-token-file", "", "file containing the one-time bootstrap token")
	allowInlineToken := flag.Bool("allow-insecure-dev-bootstrap-token-arg", false, "allow inline bootstrap tokens in process arguments for local development only")
	caBundle := flag.String("ca-bundle", "", "path to the control-plane CA certificate (PEM)")
	serverAddr := flag.String("server", "", "control-plane gRPC address")
	serverName := flag.String("server-name", "", "expected control-plane server name (defaults to --name)")
	commonName := flag.String("name", "", "this agent's identity (client-cert common name)")
	keyPath := flag.String("key", "agent.key", "path to persist the agent private key")
	certPath := flag.String("cert", "agent.crt", "path to persist the agent certificate")
	rotateEvery := flag.Duration("rotate-every", 12*time.Hour, "how often to rotate the client certificate")
	inventoryCertRoots := flag.String("inventory-cert-roots", "", "comma-separated directories whose public certificates the agent inventories and reports over the agent channel")
	inventoryOSTrustRoots := flag.String("inventory-os-trust-roots", "", "comma-separated OS trust-store files/directories whose public CA certificates the agent inventories")
	inventoryJavaTrustStores := flag.String("inventory-java-trust-stores", "", "comma-separated Java JKS/cacerts trust stores whose public CA certificates the agent inventories")
	inventoryJavaTrustStorePassword := flag.String("inventory-java-trust-store-password", "changeit", "password for Java JKS/cacerts trust stores")
	inventoryNSSTrustRoots := flag.String("inventory-nss-trust-roots", "", "comma-separated NSS profile export files/directories whose public CA certificates the agent inventories")
	inventoryBrowserTrustRoots := flag.String("inventory-browser-trust-roots", "", "comma-separated browser profile export files/directories whose public CA certificates the agent inventories")
	inventoryPrivateKeyRoots := flag.String("inventory-private-key-roots", "", "comma-separated directories whose private-key material the agent locates and classifies without sending key bytes")
	k8sMode := flag.Bool("k8s", false, "run as a Kubernetes DaemonSet: publish the identity into a Secret and reconcile Kubernetes certificate CRDs")
	k8sSecret := flag.String("k8s-secret", "", "Kubernetes Secret to publish the identity into (namespace/name)")
	cmIssuer := flag.String("cert-manager-issuer", "", "cert-manager issuerRef name to bridge (enables the external issuer)")
	cmGroup := flag.String("cert-manager-group", "trstctl.com", "cert-manager issuerRef group")
	cmController := flag.Bool("cert-manager-controller", false, "run the trstctl Issuer/ClusterIssuer/Certificate Kubernetes controller")
	bridgeSignerURL := flag.String("bridge-signer-url", "", "control-plane issuance URL the cert-manager bridge forwards CSRs to")
	bridgeSignerTokenFile := flag.String("bridge-signer-token-file", "", "file containing the API token used by the cert-manager bridge signer")
	reconcileEvery := flag.Duration("reconcile-every", 30*time.Second, "how often the cert-manager bridge reconciles")
	secretInject := flag.Bool("secret-inject", false, "run as a workload secret-injection sidecar")
	secretInjectSourceDir := flag.String("secret-inject-source-dir", secretinject.DefaultSourceDir, "directory containing source secret files")
	secretInjectTargetDir := flag.String("secret-inject-target-dir", secretinject.DefaultTargetDir, "shared directory where injected secret files are published")
	secretInjectMap := flag.String("secret-inject-map", "", "comma-separated key=relative/path mappings; empty copies every source key")
	secretInjectOnce := flag.Bool("secret-inject-once", false, "copy injected secrets once and exit")
	secretInjectInterval := flag.Duration("secret-inject-interval", secretinject.DefaultInterval, "how often the sidecar republishes source secret files")
	// Privileged SSH-trust rewrite (SIGNER-004) — DEFAULT OFF. A one-shot op that
	// adds the SSH CA to this host's TrustedUserCAKeys (additive; never removes
	// existing trust), validated with `sshd -t`, reloaded, and auto-rolled-back on
	// failure. Gated behind --ssh-trust-confirm because weakening sshd trust is a
	// lockout-class mutation (CLAUDE.md §8).
	sshTrustAddCA := flag.Bool("ssh-trust-add-ca", false, "ADD the SSH CA to this host's trust (default off; additive, with rollback). Requires --ssh-trust-confirm")
	sshTrustConfirm := flag.Bool("ssh-trust-confirm", false, "explicit confirmation required to rewrite SSH CA trust")
	sshTrustCAKey := flag.String("ssh-trust-ca-key", "", "path to the SSH CA public key (OpenSSH authorized-key line) to trust")
	sshTrustTenant := flag.String("ssh-trust-tenant", "", "tenant the SSH-trust change is audited under (AN-1)")
	sshTrustConfig := flag.String("ssh-trust-sshd-config", "/etc/ssh/sshd_config", "path to sshd_config")
	sshTrustKeysFile := flag.String("ssh-trust-keys-file", "/etc/ssh/trusted_user_ca_keys", "path to TrustedUserCAKeys")
	sshTrustReloadCmd := flag.String("ssh-trust-reload-cmd", "", "command to reload sshd after a validated config change (e.g. \"systemctl reload sshd\"); required for --ssh-trust-add-ca")
	sshTrustValidateCmd := flag.String("ssh-trust-validate-cmd", "sshd -t", "command that validates sshd config before reload")
	sshTrustHealthCmd := flag.String("ssh-trust-health-cmd", "", "command that proves sshd is healthy after reload (for example, a localhost SSH handshake); required for --ssh-trust-add-ca")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-agent"))
		return
	}

	// Privileged SSH-trust rewrite (SIGNER-004): a self-contained, default-off,
	// explicitly-confirmed one-shot op that does NOT need the enroll/connection
	// settings, so it runs (and exits) before the steady-state agent loop. With the
	// flag off this is a no-op and the agent proceeds normally.
	sshCtx, sshStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if handled, err := runSSHTrustAddCA(sshCtx, sshTrustOptions{
		addCA: *sshTrustAddCA, confirm: *sshTrustConfirm, caKeyPath: *sshTrustCAKey,
		tenantID: *sshTrustTenant, sshdConfig: *sshTrustConfig, trustedKeys: *sshTrustKeysFile,
		reloadCmd: *sshTrustReloadCmd, validateCmd: *sshTrustValidateCmd, healthCmd: *sshTrustHealthCmd,
	}); handled {
		sshStop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
		return
	}
	sshStop()

	if *secretInject {
		mappings, err := secretinject.ParseMappings(*secretInjectMap)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		err = secretinject.Run(ctx, secretinject.Options{
			SourceDir: *secretInjectSourceDir,
			TargetDir: *secretInjectTargetDir,
			Mappings:  mappings,
			Interval:  *secretInjectInterval,
			Once:      *secretInjectOnce,
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
		return
	}

	o := agentOptions{
		enrollURL: *enrollURL, inlineToken: *token, caBundle: *caBundle,
		tokenFile: *tokenFile, serverAddr: *serverAddr, serverName: *serverName, commonName: *commonName,
		keyPath: *keyPath, certPath: *certPath, rotateEvery: *rotateEvery,
		allowInsecureDevBootstrapTokenArg: *allowInlineToken,
		inventoryCertRoots:                splitList(*inventoryCertRoots),
		inventoryOSTrustRoots:             splitList(*inventoryOSTrustRoots),
		inventoryJavaTrustStores:          splitList(*inventoryJavaTrustStores),
		inventoryJavaTrustStorePassword:   *inventoryJavaTrustStorePassword,
		inventoryNSSTrustRoots:            splitList(*inventoryNSSTrustRoots),
		inventoryBrowserTrustRoots:        splitList(*inventoryBrowserTrustRoots),
		inventoryPrivateKeyRoots:          splitList(*inventoryPrivateKeyRoots),
	}
	if o.inlineToken != "" && !o.allowInsecureDevBootstrapTokenArg {
		fmt.Fprintln(os.Stderr, "trstctl-agent: inline bootstrap tokens are development-only because process arguments expose bearer credentials; write the token to a 0600 file and use --bootstrap-token-file")
		os.Exit(2)
	}

	// Uninstalling a service needs no connection settings; everything else does.
	if *service != "uninstall" {
		if o.enrollURL == "" || o.caBundle == "" || o.serverAddr == "" || o.commonName == "" {
			fmt.Fprintln(os.Stderr, "trstctl-agent: --enroll-url, --ca-bundle, --server, and --name are required")
			os.Exit(2)
		}
	}

	if *service != "" {
		if err := handleService(*service, o); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run := runAgent
	if *k8sMode {
		kopts := k8sOptions{
			secret: *k8sSecret, issuer: *cmIssuer, group: *cmGroup,
			controller: *cmController, signerURL: *bridgeSignerURL, signerTokenFile: *bridgeSignerTokenFile,
			reconcileEvery: *reconcileEvery,
		}
		run = func(ctx context.Context, o agentOptions) error { return runKubernetes(ctx, o, kopts) }
	}
	if err := run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
		os.Exit(1)
	}
}

type agentOptions struct {
	enrollURL, inlineToken, tokenFile, caBundle, serverAddr, serverName, commonName, keyPath, certPath string
	rotateEvery                                                                                        time.Duration
	allowInsecureDevBootstrapTokenArg                                                                  bool
	inventoryCertRoots                                                                                 []string
	inventoryOSTrustRoots                                                                              []string
	inventoryJavaTrustStores                                                                           []string
	inventoryJavaTrustStorePassword                                                                    string
	inventoryNSSTrustRoots                                                                             []string
	inventoryBrowserTrustRoots                                                                         []string
	inventoryPrivateKeyRoots                                                                           []string
}

// runAgent bootstraps the agent, connects to the control plane over mTLS, and
// rotates its client certificate on a timer until ctx is cancelled. It is the
// shared loop for both interactive use and the Windows service.
func runAgent(ctx context.Context, o agentOptions) error {
	caPEM, err := os.ReadFile(o.caBundle)
	if err != nil {
		return fmt.Errorf("read CA bundle: %w", err)
	}
	token, err := bootstrapTokenForRun(o)
	if err != nil {
		return err
	}
	defer secret.Wipe(token)
	enrollClient, err := enrollmentHTTPClient(caPEM)
	if err != nil {
		return fmt.Errorf("build enrollment TLS trust: %w", err)
	}
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}

	a := agent.New(agent.Config{
		CommonName:     o.commonName,
		BootstrapToken: token,
		KeyPath:        o.keyPath,
		CertPath:       o.certPath,
		ServerName:     serverName,
		ServerCAPEM:    caPEM,
		RefreshBefore:  o.rotateEvery,
		Version:        buildinfo.Version(),
	}, agent.NewHTTPEnroller(o.enrollURL, enrollClient))

	if err := a.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	creds, err := a.Credentials()
	if err != nil {
		return err
	}
	conn, err := transport.Dial(o.serverAddr, creds)
	if err != nil {
		return fmt.Errorf("connect to control plane: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// The agent steady-state channel (WIRE-004): the agent heartbeats and renews its
	// own certificate over this mTLS gRPC connection. A successful first heartbeat
	// confirms the served channel is reachable and the agent is tenant-attributed.
	ch := channelAdapter{transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version()))}
	fmt.Printf("trstctl-agent: connected to %s as %s (cert serial %s, expires %s)\n",
		o.serverAddr, o.commonName, a.CertificateSerial(), a.CertificateNotAfter().Format(time.RFC3339))
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var nextHeartbeat time.Duration
	heartbeatFailures := 0
	if resp, herr := a.Heartbeat(ctx, ch, nil); herr != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: initial heartbeat failed:", herr)
		nextHeartbeat = rotateBackoff(heartbeatFailures, rng)
		heartbeatFailures++
	} else {
		fmt.Printf("trstctl-agent: heartbeat ok (tenant %s, next in %ds)\n", resp.TenantID, resp.NextHeartbeatSeconds)
		nextHeartbeat = heartbeatDelaySeconds(resp.NextHeartbeatSeconds, defaultHeartbeatInterval, rng)
	}
	if len(o.inventoryCertRoots) > 0 {
		if err := reportFilesystemInventory(ctx, a, ch, o.inventoryCertRoots); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: inventory report failed:", err)
		}
	}
	if hasTrustStoreInventory(o) {
		if err := reportTrustStoreInventory(ctx, a, ch, o); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: trust-store inventory report failed:", err)
		}
	}
	if len(o.inventoryPrivateKeyRoots) > 0 {
		if err := reportPrivateKeyInventory(ctx, a, ch, o.inventoryPrivateKeyRoots); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: private-key inventory report failed:", err)
		}
	}

	heartbeatTimer := time.NewTimer(nextHeartbeat)
	defer heartbeatTimer.Stop()
	rotateTimer := time.NewTimer(o.rotateEvery)
	defer rotateTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("trstctl-agent: shutting down")
			return nil
		case <-heartbeatTimer.C:
			// Heartbeat on the server's requested cadence, with bounded jitter, so a
			// large fleet does not synchronize on the same second after boot or after a
			// control-plane restart. Failures retry with the same full-jitter backoff
			// family as renewal, keeping a saturated control plane from being hammered.
			if resp, herr := a.Heartbeat(ctx, ch, nil); herr != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: heartbeat failed:", herr)
				resetTimer(heartbeatTimer, rotateBackoff(heartbeatFailures, rng))
				heartbeatFailures++
			} else {
				heartbeatFailures = 0
				resetTimer(heartbeatTimer, heartbeatDelaySeconds(resp.NextHeartbeatSeconds, defaultHeartbeatInterval, rng))
			}
		case <-rotateTimer.C:
			// Renew with jittered exponential backoff on failure (RESIL-006): a
			// control-plane outage during the refresh window must not be a single missed
			// attempt that then waits a full rotate-every interval. The existing
			// certificate stays valid until expiry and the identity survives restart.
			renewWithBackoff(ctx, a, ch, o.rotateEvery, rng)
			resetTimer(rotateTimer, o.rotateEvery)
		}
	}
}

func bootstrapToken(o agentOptions) ([]byte, error) {
	if o.inlineToken != "" && o.tokenFile != "" {
		return nil, fmt.Errorf("use only one bootstrap token source; prefer --bootstrap-token-file")
	}
	if o.inlineToken != "" {
		if !o.allowInsecureDevBootstrapTokenArg {
			return nil, fmt.Errorf("inline bootstrap tokens are development-only because process arguments expose bearer credentials; write the token to a 0600 file and use --bootstrap-token-file")
		}
		return []byte(o.inlineToken), nil
	}
	if o.tokenFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap token file: %w", err)
	}
	defer secret.Wipe(data)
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("bootstrap token file %s is empty", o.tokenFile)
	}
	token := append([]byte(nil), trimmed...)
	return token, nil
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func reportFilesystemInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, roots []string) error {
	found, err := agentdiscovery.NewFilesystemSource(roots...).Discover(ctx)
	if err != nil {
		return err
	}
	return reportFoundInventory(ctx, a, ch, agentdiscovery.SourceFilesystem, found, 10, "inventory")
}

func hasTrustStoreInventory(o agentOptions) bool {
	return len(o.inventoryOSTrustRoots) > 0 ||
		len(o.inventoryJavaTrustStores) > 0 ||
		len(o.inventoryNSSTrustRoots) > 0 ||
		len(o.inventoryBrowserTrustRoots) > 0
}

func reportTrustStoreInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, o agentOptions) error {
	var sources []agentdiscovery.Source
	if len(o.inventoryOSTrustRoots) > 0 {
		sources = append(sources, agentdiscovery.NewOSTrustStoreSource(runtime.GOOS, o.inventoryOSTrustRoots...))
	}
	for _, path := range o.inventoryJavaTrustStores {
		sources = append(sources, agentdiscovery.NewJavaTrustStoreSource(path, o.inventoryJavaTrustStorePassword))
	}
	if len(o.inventoryNSSTrustRoots) > 0 {
		sources = append(sources, agentdiscovery.NewNSSTrustStoreSource("configured", o.inventoryNSSTrustRoots...))
	}
	if len(o.inventoryBrowserTrustRoots) > 0 {
		sources = append(sources, agentdiscovery.NewBrowserTrustStoreSource("configured", "configured", o.inventoryBrowserTrustRoots...))
	}
	sink := agentdiscovery.NewMemorySink()
	rep := agentdiscovery.Discover(ctx, sources, sink)
	for _, err := range rep.Errors {
		fmt.Fprintln(os.Stderr, "trstctl-agent: trust-store discovery warning:", err)
	}
	found := sink.All()
	if len(found) == 0 && len(rep.Errors) > 0 {
		return rep.Errors[0]
	}
	return reportFoundInventory(ctx, a, ch, agentdiscovery.SourceTrustStore, found, 20, "trust-store inventory")
}

func reportPrivateKeyInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, roots []string) error {
	found, err := agentdiscovery.NewPrivateKeySource(roots...).Discover(ctx)
	if err != nil {
		return err
	}
	findings := privateKeyInventoryFindings(found)
	if len(findings) == 0 {
		return nil
	}
	resp, err := a.ReportInventory(ctx, ch, agentdiscovery.SourcePrivateKey, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d private-key inventory findings (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	return nil
}

func reportFoundInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, sourceKind string, found []agentdiscovery.Found, risk int, label string) error {
	findings := make([]agent.InventoryFinding, 0, len(found))
	for _, f := range found {
		meta := map[string]string{
			"subject":       f.Cert.Subject,
			"issuer":        f.Cert.Issuer,
			"serial":        f.Cert.SerialNumber,
			"key_algorithm": f.Cert.KeyAlgorithm,
			"not_after":     f.Cert.NotAfter.Format(time.RFC3339),
		}
		for k, v := range f.Metadata {
			meta[k] = v
		}
		findings = append(findings, agent.InventoryFinding{
			Kind:        "x509_certificate",
			Ref:         f.Location,
			Provenance:  f.Source + ":" + f.Location,
			Fingerprint: f.Cert.SHA256Fingerprint,
			RiskScore:   risk,
			Metadata:    meta,
		})
	}
	if len(findings) == 0 {
		return nil
	}
	resp, err := a.ReportInventory(ctx, ch, sourceKind, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d %s findings (run %s, rejected %d)\n", resp.Recorded, label, resp.RunID, resp.Rejected)
	return nil
}

func privateKeyInventoryFindings(found []agentdiscovery.PrivateKeyFound) []agent.InventoryFinding {
	findings := make([]agent.InventoryFinding, 0, len(found))
	for _, f := range found {
		meta := map[string]string{
			"material_class":        "private-key",
			"key_format":            f.Format,
			"key_algorithm":         string(f.Algorithm),
			"fingerprint_basis":     f.FingerprintBasis,
			"encrypted":             strconv.FormatBool(f.Encrypted),
			"key_bytes_present":     "false",
			"file_mode_restricted":  strconv.FormatBool(f.Restricted),
			"source_classification": f.Source,
		}
		for k, v := range f.Metadata {
			meta[k] = v
		}
		findings = append(findings, agent.InventoryFinding{
			Kind:        "private_key",
			Ref:         f.Location,
			Provenance:  f.Source + ":" + f.Location,
			Fingerprint: f.Fingerprint,
			RiskScore:   85,
			Metadata:    meta,
		})
	}
	return findings
}

func bootstrapTokenForRun(o agentOptions) ([]byte, error) {
	if agentIdentityFilesExist(o) {
		return nil, nil
	}
	return bootstrapToken(o)
}

func enrollmentHTTPClient(caPEM []byte) (*http.Client, error) {
	enrollTransport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: enrollTransport, Timeout: 30 * time.Second}, nil
}

func agentIdentityFilesExist(o agentOptions) bool {
	if o.keyPath == "" || o.certPath == "" {
		return false
	}
	if _, err := os.Stat(o.keyPath); err != nil {
		return false
	}
	if _, err := os.Stat(o.certPath); err != nil {
		return false
	}
	return true
}

// channelAdapter adapts the transport gRPC client to the agent package's
// ChannelClient interface, translating between the transport wire messages and the
// agent core's message types so the agent library has no hard dependency on the
// transport message structs.
type channelAdapter struct{ c *transport.AgentClient }

func (a channelAdapter) Heartbeat(ctx context.Context, req *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	resp, err := a.c.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: req.AgentID, Version: req.Version, Status: req.Status,
		CertSerial: req.CertSerial, Inventory: req.Inventory,
	})
	if err != nil {
		return nil, err
	}
	return &agent.HeartbeatResponse{TenantID: resp.TenantID, NextHeartbeatSeconds: resp.NextHeartbeatSeconds}, nil
}

func (a channelAdapter) Renew(ctx context.Context, req *agent.RenewRequest) (*agent.RenewResponse, error) {
	resp, err := a.c.Renew(ctx, &transport.RenewRequest{CSRDER: req.CSRDER})
	if err != nil {
		return nil, err
	}
	return &agent.RenewResponse{CertChainPEM: resp.CertChainPEM, NotAfterUnix: resp.NotAfterUnix}, nil
}

func (a channelAdapter) ReportInventory(ctx context.Context, req *agent.InventoryRequest) (*agent.InventoryResponse, error) {
	findings := make([]transport.InventoryFinding, 0, len(req.Findings))
	for _, f := range req.Findings {
		findings = append(findings, transport.InventoryFinding{
			Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: f.Metadata,
		})
	}
	resp, err := a.c.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: req.SourceKind, Findings: findings})
	if err != nil {
		return nil, err
	}
	return &agent.InventoryResponse{TenantID: resp.TenantID, RunID: resp.RunID, Recorded: resp.Recorded, Rejected: resp.Rejected}, nil
}

// renewWithBackoff attempts a steady-state channel renewal (a.RenewOverChannel), and on
// failure keeps retrying with full-jitter exponential backoff until it succeeds, the
// budget elapses (so the next regular tick takes over), or ctx is cancelled (RESIL-006).
func renewWithBackoff(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, budget time.Duration, rng *rand.Rand) {
	deadline := time.Now().Add(budget)
	for attempt := 0; ; attempt++ {
		if err := a.RenewOverChannel(ctx, ch); err == nil {
			fmt.Printf("trstctl-agent: renewed client certificate over the agent channel (serial %s)\n", a.CertificateSerial())
			return
		} else {
			fmt.Fprintln(os.Stderr, "trstctl-agent: channel renewal failed:", err)
		}
		delay := rotateBackoff(attempt, rng)
		if time.Now().Add(delay).After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// rotateBackoffBase / Max bound the agent's retry schedule on a failed rotation
// (RESIL-006). The delay grows exponentially from the base, is capped at Max, and
// has full jitter applied, so retries are prompt but spread across a fleet.
const (
	rotateBackoffBase = 1 * time.Second
	rotateBackoffMax  = 60 * time.Second
)

const defaultHeartbeatInterval = 30 * time.Second

// rotateBackoff returns the delay before retry attempt n (0-based): an exponential
// backoff base*2^n capped at Max, with full jitter (a uniform value in (0, capped]).
// Full jitter is the AWS-recommended schedule for de-correlating a fleet's retries.
// It never returns a non-positive duration, so a recovering agent cannot spin.
func rotateBackoff(attempt int, rng *rand.Rand) time.Duration {
	d := rotateBackoffBase
	for i := 0; i < attempt && d < rotateBackoffMax; i++ {
		d *= 2
	}
	if d > rotateBackoffMax {
		d = rotateBackoffMax
	}
	// Full jitter in (0, d]: a uniform pick, clamped to at least 1ns so it is strictly
	// positive and the loop always makes progress.
	jittered := time.Duration(rng.Int63n(int64(d))) + 1
	return jittered
}

func heartbeatDelaySeconds(seconds int64, fallback time.Duration, rng *rand.Rand) time.Duration {
	base := fallback
	if base <= 0 {
		base = defaultHeartbeatInterval
	}
	if seconds > 0 {
		base = time.Duration(seconds) * time.Second
	}
	return jitterHeartbeat(base, rng)
}

func jitterHeartbeat(base time.Duration, rng *rand.Rand) time.Duration {
	if base <= time.Nanosecond {
		return time.Nanosecond
	}
	floor := base * 8 / 10
	spread := base - floor
	if spread <= 0 {
		return base
	}
	return floor + time.Duration(rng.Int63n(int64(spread))) + 1
}

func resetTimer(t *time.Timer, d time.Duration) {
	if d <= 0 {
		d = time.Nanosecond
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
