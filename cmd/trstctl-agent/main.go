// SPDX-License-Identifier: MPL-2.0

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
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/secretinject"
	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/revcacheposture"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	tomcatReloadURL := flag.String("tomcat-reload-url", "", "one-shot: reload TLS through the stock Tomcat Manager /manager/text/sslReload on a literal loopback address, then exit")
	tomcatReloadUser := flag.String("tomcat-reload-user", "", "Tomcat Manager username with manager-script permission (one-shot TLS reload)")
	tomcatReloadPasswordFile := flag.String("tomcat-reload-password-file", "", "private file containing the Tomcat Manager password; never pass it in argv")
	tomcatReloadTLSHost := flag.String("tomcat-reload-tls-host", "_default_", "exact Tomcat SSLHostConfig name to reload; defaults to _default_, never all hosts")
	service := flag.String("service", "", "Windows service control: install | uninstall | run")
	enrollURL := flag.String("enroll-url", "", "control-plane enrollment base URL")
	token := flag.String("bootstrap-token", "", "development-only inline bootstrap token; use --bootstrap-token-file")
	tokenFile := flag.String("bootstrap-token-file", "", "file containing the one-time bootstrap token")
	allowInlineToken := flag.Bool("allow-insecure-dev-bootstrap-token-arg", false, "allow inline bootstrap tokens in process arguments for local development only")
	allowLoopbackEnrollment := flag.Bool("allow-insecure-loopback-enrollment", false, "allow bootstrap over plain HTTP only when --enroll-url is a loopback address; the resolved address is rechecked before every dial")
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
	relayClaim := flag.Bool("relay-claim", false, "claim certificate lifecycle jobs allowed by this agent's enrolled roles: host agents execute destinations assigned to their agent ID using --host-exec-profile; network agents execute appliance work in their segment. Off by default; enable deliberately because jobs may redeem credentials")
	selfUpgrade := flag.Bool("self-upgrade", false, "claim this agent's own agent.upgrade jobs from staged rollout campaigns (epic A5): download the campaign's artifact for this platform, verify its sha256, swap the binary, and restart. Off by default because it replaces this executable — the control-plane operator starts the campaign, but replacing the binary on THIS machine is this machine's operator's decision. The previous binary is kept beside it as .old")
	hostExecProfile := flag.String("host-exec-profile", "", "path to this host's connector exec profile: the operator-owned allowlist of directories a deploy may write and commands it may run (epic D1). A file rather than flags, because it is the boundary that stops a compromised control plane running arbitrary commands here — and because it describes THIS machine's paths and binaries. Without it the agent claims no file/reload deploys")
	hostRollbackDir := flag.String("host-rollback-dir", "", "directory for this host agent's encrypted, two-generation connector predecessor bundles (AUD32/G1). Empty stores them beside --key under host-rollbacks. The bundles never return to the control plane and are required for host rollback after restart")
	enrollProxyListen := flag.String("enroll-proxy-listen", "", "serve a LAN-local ACME/EST/SCEP proxy on this address for hosts and devices in this segment that have no route to the control plane (epic A4). The proxy is pass-through: it forwards protocol traffic unaltered, adds no credential of its own, and makes no trust decision — the control plane's validators and policy still decide. Empty disables it")
	enrollProxyUpstream := flag.String("enroll-proxy-upstream", "", "comma-separated https control-plane endpoints the enrolment proxy forwards to. More than one gives automatic failover when an endpoint stops answering; a control-plane ERROR is passed back to the client rather than retried, because it is an answer")
	enrollProxySegment := flag.String("enroll-proxy-segment", "", "stable operator name for the dark segment this relay serves; required with --enroll-proxy-listen and reported as tenant-scoped topology evidence")
	enrollProxyPublicURL := flag.String("enroll-proxy-public-url", "", "stable HTTPS URL stock enrollment clients use for this segment; required with --enroll-proxy-listen and shared by redundant relays so ACME absolute URLs remain on the relay path")
	revCacheListen := flag.String("crl-cache-listen", "", "serve the control plane's CRL to relying parties in this segment on this address (epic R3). The relay holds the CA's signed bytes and hands them over — it signs nothing — and REFUSES to serve a list past its nextUpdate, because a stale CRL still verifies and would have a relying party trust a certificate revoked yesterday. Empty disables it")
	revCacheUpstream := flag.String("crl-cache-upstream", "", "the control plane CRL URL this relay caches, e.g. https://cp.example/crl/<tenant>.crl")
	revCacheIssuer := flag.String("crl-cache-issuer", "", "PEM file holding the issuing CA certificate the cached CRL must verify against. Required with --crl-cache-listen: without it the relay cannot tell a CRL from a captive portal's login page")
	revCacheGrace := flag.Duration("crl-cache-grace", 0, "how long past nextUpdate a cached CRL may still be served. Zero — the default — serves nothing past nextUpdate; any other value is a decision to serve a list the CA said had expired, which only the operator can weigh")
	revCacheSegment := flag.String("revocation-cache-segment", "", "stable operator name for the dark segment served by the legacy single-CRL flags; required with --crl-cache-listen")
	revCacheConfig := flag.String("revocation-cache-config", "", "JSON file defining one segment listener and multiple issuer CRL/OCSP caches. The file holds public issuer paths and upstream URLs, never private keys or credentials")
	pluginDir := flag.String("connector-plugin-dir", "", "directory of signature-verified third-party WASM connectors this relay may execute (epic E4). Each <name>.wasm needs a sibling <name>.wasm.sig from a key named by --connector-plugin-key. Empty disables third-party connectors; a directory with no trust keys is refused rather than loaded")
	pluginKeys := flag.String("connector-plugin-key", "", "comma-separated PEM files holding the publisher public keys whose signatures this relay accepts for third-party connectors. Required whenever --connector-plugin-dir is set: loading unverified partner code inside a customer network is refused, not warned about")
	pluginPins := flag.String("connector-plugin-pin", "", "comma-separated hex SHA-256 digests restricting third-party connectors to exactly these builds. A signature says who built a module; a pin says which build, which is what stops a compromised publisher key from shipping a new one")
	pluginCaps := flag.String("connector-plugin-capability", "", "comma-separated capability grant every third-party connector runs under (fs.read, fs.write, net.dial). Required with --connector-plugin-dir: an unset grant is refused rather than defaulted, because a grant nobody set and a grant that permits nothing are indistinguishable here")
	pluginCapPrefix := flag.String("connector-plugin-capability-prefix", "", "comma-separated resource constraints for the grant above, as capability=prefix (net.dial=appliance.internal:443, fs.read=/etc/partner). A capability with no constraint is unrestricted for that capability")
	workloadAPISocket := flag.String("workload-api-socket", "", "serve the SPIFFE Workload API on this Unix socket for workloads on THIS host (epic B3). Linux and macOS attest the caller from kernel peer credentials; unsupported platforms, including Windows, fail closed instead of issuing without attestation. The SVID key is generated here and never leaves the machine; only a public key travels up for signing. Empty disables it")
	relayPollEvery := flag.Duration("relay-poll-every", 15*time.Second, "how often to ask for relay work when --relay-claim is set")
	inventoryPKCS11Module := flag.String("inventory-pkcs11-module", "", "path to a PKCS#11 module (softhsm2.so, libykcs11.so, opensc-pkcs11.so) whose tokens should be inventoried. Metadata only: reads certificate objects, never private keys, over a read-only session. Requires a cgo-enabled agent build — the default build is statically linked and reports an error rather than an empty token estate")
	inventoryPKCS11Token := flag.String("inventory-pkcs11-token", "", "inventory only the PKCS#11 token with this label; empty inventories every token the module presents")
	inventoryPKCS11PINFile := flag.String("inventory-pkcs11-pin-file", "", "file holding the PKCS#11 user PIN, for tokens whose certificate objects are not public. A file rather than a flag, because process arguments expose credentials — the same rule the bootstrap token follows. Omit it to read only public certificate objects")
	inventoryWindowsStores := flag.String("inventory-windows-stores", "", "comma-separated Windows certificate stores to inventory (MY, WEBHOSTING, CA, ROOT, TRUSTEDPUBLISHER), or \"all\" for every supported store. Metadata only: reads certificates, never private keys. Windows builds only — on any other platform this reports an error rather than an empty estate")
	inventoryWindowsLocation := flag.String("inventory-windows-location", "local-machine", "which Windows certificate hierarchy to inventory: local-machine (service and IIS certificates) or current-user")
	inventoryK8sSecrets := flag.Bool("inventory-k8s-secrets", false, "inventory the TLS Secrets in this pod's Kubernetes namespace (metadata only; reads tls.crt, never tls.key). Requires the in-cluster service-account mount and list access to Secrets in the namespace")
	inventorySSHHostKeyGlobs := flag.String("inventory-ssh-host-key-globs", "", "comma-separated public host-key globs to inventory; empty disables this SSH source")
	inventorySSHUserKeyGlobs := flag.String("inventory-ssh-user-key-globs", "", "comma-separated public user-key globs to inventory; empty disables this SSH source")
	inventorySSHAuthorizedKeys := flag.String("inventory-ssh-authorized-keys", "", "comma-separated authorized_keys paths or globs to inventory; empty disables this SSH source")
	inventorySSHKnownHosts := flag.String("inventory-ssh-known-hosts", "", "comma-separated known_hosts paths or globs to inventory; empty disables this SSH source")
	inventorySSHSSHDConfigs := flag.String("inventory-ssh-sshd-configs", "", "comma-separated sshd_config paths or globs whose TrustedUserCAKeys references are inventoried; empty disables this SSH source")
	k8sMode := flag.Bool("k8s", false, "run as a Kubernetes DaemonSet: publish the identity into a Secret and reconcile Kubernetes certificate CRDs")
	k8sSecret := flag.String("k8s-secret", "", "Kubernetes Secret to publish the identity into (namespace/name)")
	cmIssuer := flag.String("cert-manager-issuer", "", "cert-manager issuerRef name to bridge (enables the external issuer)")
	cmGroup := flag.String("cert-manager-group", "trstctl.com", "cert-manager issuerRef group")
	cmController := flag.Bool("cert-manager-controller", false, "run the trstctl Issuer/ClusterIssuer/Certificate Kubernetes controller")
	bridgeSignerURL := flag.String("bridge-signer-url", "", "control-plane issuance URL the cert-manager bridge forwards CSRs to")
	bridgeSignerTokenFile := flag.String("bridge-signer-token-file", "", "file containing the API token used by the cert-manager bridge signer")
	reconcileEvery := flag.Duration("reconcile-every", 30*time.Second, "how often the cert-manager bridge reconciles")
	prepareIdentityDirPath := flag.String("prepare-identity-dir", "", "prepare a Kubernetes hostPath identity directory, then exit")
	prepareIdentityUID := flag.Int("prepare-identity-uid", 65532, "uid that should own --prepare-identity-dir")
	prepareIdentityGID := flag.Int("prepare-identity-gid", 65532, "gid that should own --prepare-identity-dir")
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
	// lockout-class mutation (SIGNER-004).
	sshTrustAddCA := flag.Bool("ssh-trust-add-ca", false, "ADD the SSH CA to this host's trust (default off; additive, with rollback). Requires --ssh-trust-confirm")
	sshTrustConfirm := flag.Bool("ssh-trust-confirm", false, "explicit confirmation required to rewrite SSH CA trust")
	sshTrustCAKey := flag.String("ssh-trust-ca-key", "", "path to the SSH CA public key (OpenSSH authorized-key line) to trust")
	sshTrustTenant := flag.String("ssh-trust-tenant", "", "tenant the SSH-trust change is audited under (AN-1)")
	sshTrustConfig := flag.String("ssh-trust-sshd-config", "/etc/ssh/sshd_config", "path to sshd_config")
	sshTrustKeysFile := flag.String("ssh-trust-keys-file", "/etc/ssh/trusted_user_ca_keys", "path to TrustedUserCAKeys")
	sshTrustReloadCmd := flag.String("ssh-trust-reload-cmd", "", "validated argv command line to reload sshd after a validated config change (e.g. \"systemctl reload sshd\"); shell metacharacters are rejected; required for --ssh-trust-add-ca")
	sshTrustValidateCmd := flag.String("ssh-trust-validate-cmd", "sshd -t", "validated argv command line that validates sshd config before reload; shell metacharacters are rejected")
	sshTrustHealthCmd := flag.String("ssh-trust-health-cmd", "", "validated argv command line that proves sshd is healthy after reload (for example, a localhost SSH handshake); shell metacharacters are rejected; required for --ssh-trust-add-ca")
	// Workload-held predecessor co-sign (PCAS claim 19, INT-16) — DEFAULT OFF. When
	// --workload-cosign-listen is set, the agent holds the workload's predecessor key
	// and serves the succession co-sign RPC so the control plane can mint a
	// workload-held succession without the platform ever holding the leaf key. It is a
	// self-contained mode (no enrollment settings needed) and requires the enterprise
	// build.
	workloadCoSignListen := flag.String("workload-cosign-listen", "", "serve the workload-held predecessor co-sign service at this address (\"unix:/path\" or \"host:port\"); enterprise build only")
	workloadIdentity := flag.String("workload-identity", "", "workload identity id the agent co-signs successions for")
	workloadTenant := flag.String("workload-tenant", "", "workload tenant id for the co-sign binding")
	workloadDeployment := flag.String("workload-deployment", "", "workload deployment scope for the co-sign binding")
	workloadPredecessorKey := flag.String("workload-predecessor-key", "", "path to the workload predecessor key (PKCS#8 PEM) the agent holds and co-signs with")
	// B6: one-shot, fully offline edge sub-CA modes for a host with no path to
	// the brain. edge-csr generates the delegated key non-extractably in a TPM
	// or PKCS#11 token by default and prints the attestation challenge; edge-issue issues one
	// leaf under the delegated certificate, whose OWN name constraints bound
	// the request — out-of-constraint fails closed here, not at reconcile.
	edgeCSRMode := flag.Bool("edge-csr", false, "one-shot: generate the delegated edge CA's non-extractable key and CSR on this host, print the TPM attestation challenge, and exit")
	edgeTenant := flag.String("edge-tenant", "", "tenant id the delegation is for (bound into the attestation challenge)")
	edgeSegment := flag.String("edge-segment", "", "declared segment id the delegation is for (bound into the attestation challenge)")
	edgeCN := flag.String("edge-cn", "", "common name for the delegated edge CA (edge-csr)")
	edgeKeyProvider := flag.String("edge-key-provider", "tpm2", "edge CA custody provider: tpm2 (default), pkcs11, or software (software needs explicit exception flags and policy)")
	edgeKeyGeneration := flag.String("edge-key-generation", "1", "durable generation label; rerunning the same tenant/segment/generation reconciles the same device key")
	edgeAllowSoftwareKey := flag.Bool("edge-allow-software-key", false, "explicitly permit exportable PEM edge CA custody; the control-plane segment policy must separately permit it")
	edgeKeyOut := flag.String("edge-key-out", "edge-ca.key", "software-exception only: where edge-csr writes the exportable delegated CA private key (0600)")
	edgeKeyHandleOut := flag.String("edge-key-handle-out", "edge-ca.keyref.json", "hardware path: where edge-csr writes the opaque TPM/PKCS#11 public key handle (contains no private key)")
	edgeCSROut := flag.String("edge-csr-out", "edge-ca.csr", "where edge-csr writes the CSR (DER) the operator carries to the brain")
	edgeTPMPath := flag.String("edge-tpm-path", "", "TPM device or swtpm Unix socket; empty uses the Linux TPM default")
	edgeTPMOwnerAuthFile := flag.String("edge-tpm-owner-auth-file", "", "optional file holding TPM owner hierarchy authorization")
	edgeTPMKeyAuthFile := flag.String("edge-tpm-key-auth-file", "", "optional file holding TPM edge-key authorization")
	edgeTPMHandleBase := flag.Uint("edge-tpm-persistent-handle-base", 0, "first owner-persistent TPM handle for reconciled edge CA keys; zero uses the safe backend default")
	edgePKCS11Module := flag.String("edge-pkcs11-module", "", "PKCS#11 module path for non-extractable edge CA custody")
	edgePKCS11Token := flag.String("edge-pkcs11-token", "", "PKCS#11 token label for edge CA custody")
	edgePKCS11PINFile := flag.String("edge-pkcs11-pin-file", "", "file holding the PKCS#11 user PIN; required for pkcs11 custody")
	edgePKCS11KeyLabelPrefix := flag.String("edge-pkcs11-key-label-prefix", "trstctl-edge-ca", "PKCS#11 object-label prefix for edge CA keys")
	edgeIssueMode := flag.Bool("edge-issue", false, "one-shot: issue a leaf locally under the delegated edge CA and record it in the journal, then exit")
	edgeCACert := flag.String("edge-ca-cert", "", "the delegated edge CA certificate (PEM) minted by the brain")
	edgeCAKey := flag.String("edge-ca-key", "", "software-exception only: the exportable delegated edge CA private key written by edge-csr")
	edgeCAKeyHandle := flag.String("edge-ca-key-handle", "", "hardware path: opaque TPM/PKCS#11 public key handle written by edge-csr")
	edgeIssueCN := flag.String("edge-issue-cn", "", "leaf common name (edge-issue)")
	edgeIssueDNS := flag.String("edge-issue-dns", "", "comma-separated leaf DNS SANs; every one must sit inside the delegation's name constraints")
	edgeIssueTTL := flag.Duration("edge-issue-ttl", 24*time.Hour, "leaf validity; capped so a leaf never outlives the delegated CA")
	edgeCertOut := flag.String("edge-cert-out", "edge-leaf.crt", "where edge-issue writes the leaf certificate")
	edgeLeafKeyOut := flag.String("edge-leaf-key-out", "edge-leaf.key", "where edge-issue writes the leaf private key (0600)")
	edgeJournalPath := flag.String("edge-journal", "edge-journal.json", "issuance journal, maintained in the exact shape `trstctl edge delegations reconcile -f` posts")
	flag.Parse()
	tpmPersistentHandleBase, err := checkedTPMPersistentHandleBase(*edgeTPMHandleBase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
		os.Exit(1)
	}

	if handled, err := runEdgeCAOps(edgeCAOptions{
		csrMode: *edgeCSRMode, tenantID: *edgeTenant, segmentID: *edgeSegment,
		commonName: *edgeCN, keyProvider: *edgeKeyProvider, keyGeneration: *edgeKeyGeneration,
		allowSoftwareKey: *edgeAllowSoftwareKey, keyOut: *edgeKeyOut, keyHandleOut: *edgeKeyHandleOut, csrOut: *edgeCSROut,
		tpmPath: *edgeTPMPath, tpmOwnerAuthFile: *edgeTPMOwnerAuthFile, tpmKeyAuthFile: *edgeTPMKeyAuthFile,
		tpmPersistentHandleBase: tpmPersistentHandleBase, pkcs11Module: *edgePKCS11Module,
		pkcs11Token: *edgePKCS11Token, pkcs11PINFile: *edgePKCS11PINFile, pkcs11KeyLabelPrefix: *edgePKCS11KeyLabelPrefix,
		issueMode: *edgeIssueMode, caCert: *edgeCACert, caKey: *edgeCAKey, caKeyHandle: *edgeCAKeyHandle,
		leafCN: *edgeIssueCN, leafDNS: *edgeIssueDNS, leafTTL: *edgeIssueTTL,
		certOut: *edgeCertOut, leafKeyOut: *edgeLeafKeyOut, journal: *edgeJournalPath,
	}, *commonName); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
		return
	}

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-agent"))
		return
	}
	if handled, err := runTomcatReload(context.Background(), tomcatReloadOptions{
		url: *tomcatReloadURL, user: *tomcatReloadUser, passwordFile: *tomcatReloadPasswordFile, tlsHost: *tomcatReloadTLSHost,
	}); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
		fmt.Println("Tomcat acknowledged TLS reload; the connector must verify the served certificate")
		return
	}

	if *prepareIdentityDirPath != "" {
		if err := prepareIdentityDir(*prepareIdentityDirPath, *prepareIdentityUID, *prepareIdentityGID); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent:", err)
			os.Exit(1)
		}
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

	// Workload-held predecessor co-sign service (INT-16): a self-contained, default-off
	// mode that serves the succession co-sign RPC and blocks until signal. It needs no
	// enroll/connection settings, so it runs before the steady-state agent loop.
	if *workloadCoSignListen != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := runWorkloadCoSign(ctx, workloadCoSignConfig{
			Listen:             *workloadCoSignListen,
			DeploymentScope:    *workloadDeployment,
			IdentityID:         *workloadIdentity,
			TenantID:           *workloadTenant,
			PredecessorKeyPath: *workloadPredecessorKey,
		}); err != nil {
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
		allowInsecureLoopbackEnrollment:   *allowLoopbackEnrollment,
		inventoryCertRoots:                splitList(*inventoryCertRoots),
		inventoryOSTrustRoots:             splitList(*inventoryOSTrustRoots),
		inventoryJavaTrustStores:          splitList(*inventoryJavaTrustStores),
		inventoryJavaTrustStorePassword:   *inventoryJavaTrustStorePassword,
		inventoryNSSTrustRoots:            splitList(*inventoryNSSTrustRoots),
		inventoryBrowserTrustRoots:        splitList(*inventoryBrowserTrustRoots),
		inventoryPrivateKeyRoots:          splitList(*inventoryPrivateKeyRoots),
		inventoryK8sSecrets:               *inventoryK8sSecrets,
		inventoryPKCS11Module:             strings.TrimSpace(*inventoryPKCS11Module),
		inventoryPKCS11Token:              strings.TrimSpace(*inventoryPKCS11Token),
		inventoryPKCS11PINFile:            strings.TrimSpace(*inventoryPKCS11PINFile),
		inventoryWindowsStores:            splitList(*inventoryWindowsStores),
		inventoryWindowsLocation:          strings.TrimSpace(*inventoryWindowsLocation),
		relayClaim:                        *relayClaim,
		selfUpgrade:                       *selfUpgrade,
		workloadAPISocket:                 *workloadAPISocket,
		enrollProxyListen:                 *enrollProxyListen,
		enrollProxyUpstream:               *enrollProxyUpstream,
		enrollProxySegment:                *enrollProxySegment,
		enrollProxyPublicURL:              *enrollProxyPublicURL,
		revCacheListen:                    *revCacheListen,
		revCacheUpstream:                  *revCacheUpstream,
		revCacheIssuer:                    *revCacheIssuer,
		revCacheGrace:                     *revCacheGrace,
		revCacheSegment:                   strings.TrimSpace(*revCacheSegment),
		revCacheConfig:                    strings.TrimSpace(*revCacheConfig),
		pluginDir:                         *pluginDir,
		pluginKeys:                        *pluginKeys,
		pluginPins:                        *pluginPins,
		pluginCaps:                        *pluginCaps,
		pluginCapPrefix:                   *pluginCapPrefix,
		relayPollEvery:                    *relayPollEvery,
		hostExecProfile:                   strings.TrimSpace(*hostExecProfile),
		hostRollbackDir:                   strings.TrimSpace(*hostRollbackDir),
		inventorySSH: sshdiscovery.Config{
			HostKeyGlobs:        splitList(*inventorySSHHostKeyGlobs),
			UserKeyGlobs:        splitList(*inventorySSHUserKeyGlobs),
			AuthorizedKeysPaths: splitList(*inventorySSHAuthorizedKeys),
			KnownHostsPaths:     splitList(*inventorySSHKnownHosts),
			SSHDConfigPaths:     splitList(*inventorySSHSSHDConfigs),
		},
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

func checkedTPMPersistentHandleBase(value uint) (uint32, error) {
	if uint64(value) > uint64(math.MaxUint32) {
		return 0, fmt.Errorf("edge TPM persistent handle base %d exceeds 32 bits", value)
	}
	return uint32(value), nil // #nosec G115 -- the MaxUint32 check above proves the narrowing is exact (CWE-190).
}

type agentOptions struct {
	enrollURL, inlineToken, tokenFile, caBundle, serverAddr, serverName, commonName, keyPath, certPath string
	rotateEvery                                                                                        time.Duration
	allowInsecureDevBootstrapTokenArg                                                                  bool
	allowInsecureLoopbackEnrollment                                                                    bool
	inventoryCertRoots                                                                                 []string
	inventoryOSTrustRoots                                                                              []string
	inventoryJavaTrustStores                                                                           []string
	inventoryJavaTrustStorePassword                                                                    string
	inventoryNSSTrustRoots                                                                             []string
	inventoryBrowserTrustRoots                                                                         []string
	inventoryPrivateKeyRoots                                                                           []string
	inventorySSH                                                                                       sshdiscovery.Config
	inventoryK8sSecrets                                                                                bool
	// inventoryWindowsStores names the Windows certificate stores to inventory
	// (epic C1). Empty means the source is off — a Windows estate is only
	// inventoried when an operator says which stores, because "all of them" on a
	// domain controller is a different proposition from the personal store.
	inventoryWindowsStores   []string
	inventoryWindowsLocation string
	// PKCS#11 token inventory (epic C1). The PIN is a FILE path, never an
	// inline value: process arguments are readable by anyone who can list
	// processes, which is why the bootstrap token has the same rule.
	inventoryPKCS11Module  string
	inventoryPKCS11Token   string
	inventoryPKCS11PINFile string
	// relayClaim turns on the A3 relay runtime: claim connector.deploy work for
	// appliances in this segment, redeem its credential for one attempt, deploy,
	// wipe. Off by default because it moves live credential material onto this
	// host, which is an operator's decision to make explicitly.
	relayClaim bool
	// selfUpgrade lets this agent claim its own agent.upgrade jobs (A5). Off
	// by default for the same reason relayClaim is: replacing this binary is
	// this machine's operator's decision, made here, not implied by a
	// control-plane campaign alone.
	selfUpgrade bool
	// workloadAPISocket is the host-local SPIFFE Workload API socket (B3).
	// Empty means the agent serves no Workload API, which is the default: the
	// endpoint issues identities to every workload that can reach it.
	workloadAPISocket string
	// E4: third-party WASM connectors this relay may execute. All five are
	// operator-owned: the modules, the keys that vouch for them, the builds
	// pinned, and the capabilities they run under. None of it is derived from
	// the module or from the control plane, because a publisher who could widen
	// their own grant would make the sandbox decorative.
	// A4: the LAN-local enrolment proxy for dark segments.
	enrollProxyListen    string
	enrollProxyUpstream  string
	enrollProxySegment   string
	enrollProxyPublicURL string

	// R3: the LAN revocation cache.
	revCacheListen   string
	revCacheUpstream string
	revCacheIssuer   string
	revCacheGrace    time.Duration
	revCacheSegment  string
	revCacheConfig   string
	// revCacheHTTPClient is a test-only composition seam. Production flag
	// assembly leaves it nil and always gets the SSRF-guarded client below.
	revCacheHTTPClient *http.Client

	pluginDir       string
	pluginKeys      string
	pluginPins      string
	pluginCaps      string
	pluginCapPrefix string
	relayPollEvery  time.Duration
	// hostExecProfile is the path to this host's operator-owned exec allowlist
	// (epic D1). Empty means this agent executes no file/reload connectors:
	// without an authorized command set there is nothing safe to default to.
	hostExecProfile string
	// hostRollbackDir holds the encrypted two-generation predecessor ledger on
	// this host. Empty derives a stable directory beside keyPath.
	hostRollbackDir string
}

func prepareIdentityDir(path string, uid, gid int) error {
	if runtime.GOOS == "windows" {
		return errors.New("prepare identity dir is supported only on Unix-like systems")
	}
	if uid < 0 || gid < 0 {
		return fmt.Errorf("prepare identity dir owner must be non-negative, got uid=%d gid=%d", uid, gid)
	}
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == string(os.PathSeparator) || !filepath.IsAbs(clean) {
		return fmt.Errorf("refusing unsafe identity directory %q", path)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}
	if err := os.Chown(clean, uid, gid); err != nil {
		return fmt.Errorf("own identity dir: %w", err)
	}
	if err := os.Chmod(clean, 0o700); err != nil { // #nosec G302 -- 0700 on a directory: the execute bit is required to traverse it (CWE-276)
		return fmt.Errorf("chmod identity dir: %w", err)
	}
	return nil
}

var errAgentIdentityRotated = errors.New("agent identity rotated; reconnect the mutual-TLS channel")

// runAgent reconnects the whole steady-state session after each successful
// identity rotation. TLS authenticates only when a connection is established;
// swapping the in-memory certificate cannot change the peer identity of an
// already-open HTTP/2 connection. Re-entering the bounded session closes the old
// channel and every client derived from it, then dials again with the new key and
// certificate before another heartbeat, job, or renewal is attempted.
func runAgent(ctx context.Context, o agentOptions) error {
	for {
		err := runAgentUntilRotation(ctx, o)
		if errors.Is(err, errAgentIdentityRotated) {
			continue
		}
		return err
	}
}

// runAgentUntilRotation bootstraps (or reloads) the agent, connects to the
// control plane over mTLS, and serves one channel lifetime. A successful renewal
// returns errAgentIdentityRotated so runAgent can build a new TLS connection.
func runAgentUntilRotation(ctx context.Context, o agentOptions) error {
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
	enroller := enrollmentEnroller(o, enrollClient)
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
	}, enroller)

	if err := a.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if strings.TrimSpace(o.enrollProxyListen) != "" && !agentCarriesRole(a.Roles(), mtls.AgentRoleNetwork) {
		return fmt.Errorf("--enroll-proxy-listen requires a certificate carrying the %q role; re-enroll this agent with a network-role bootstrap token", mtls.AgentRoleNetwork)
	}
	if revocationCacheConfigured(o) && !agentCarriesRole(a.Roles(), mtls.AgentRoleNetwork) {
		return fmt.Errorf("revocation caching requires a certificate carrying the %q role; re-enroll this agent with a network-role bootstrap token", mtls.AgentRoleNetwork)
	}
	// E4: verify and load third-party connectors BEFORE the first heartbeat.
	// That first beat is the boot record operators trust; reporting an empty
	// runtime and correcting it one interval later would be a false outage.
	pluginRuntime, pluginErr := buildPluginRuntime(ctx, o)
	if pluginErr != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent:", pluginErr)
		return pluginErr
	}
	if pluginRuntime != nil {
		defer func() { _ = pluginRuntime.Close(context.Background()) }()
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
	// Start the relay before the first heartbeat. Otherwise the most important
	// boot-time observation says "not serving" and the truthful topology does
	// not arrive until the next server-selected interval.
	// The relay trusts the same operator-supplied control-plane CA bundle as
	// bootstrap. Its protocol client attaches NO agent certificate; sharing the
	// trust-only HTTP client cannot accidentally lend the relay's identity to a
	// device request.
	reportEnrollmentProxy, stopEnrollProxy := startEnrollProxy(ctx, o, enrollClient)
	defer stopEnrollProxy()
	reportRevocationCaches, stopRevocationCaches := startRevocationCache(ctx, o)
	defer stopRevocationCaches()
	ch := channelAdapter{
		c:                  transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version())),
		enrollmentProxy:    reportEnrollmentProxy,
		revocationCaches:   reportRevocationCaches,
		revocationIssuedAt: &atomic.Int64{},
	}
	if agentCarriesRole(a.Roles(), mtls.AgentRoleNetwork) {
		ch.pluginIdentity = a.Identity()
		ch.pluginCensus = func() []plugincensus.Entry {
			if pluginRuntime == nil {
				return []plugincensus.Entry{}
			}
			return pluginRuntime.Census()
		}
	}
	fmt.Printf("trstctl-agent: connected to %s as %s (cert serial %s, expires %s)\n",
		o.serverAddr, o.commonName, a.CertificateSerial(), a.CertificateNotAfter().Format(time.RFC3339))
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- reconnect jitter, not a security decision (CWE-338)
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
	if hasSSHInventory(o.inventorySSH) {
		if err := reportSSHInventory(ctx, a, ch, o.inventorySSH); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: SSH inventory report failed:", err)
		}
	}
	if o.inventoryK8sSecrets {
		if err := reportKubernetesSecretInventory(ctx, a, ch); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes Secret inventory report failed:", err)
		}
	}
	if o.inventoryPKCS11Module != "" {
		if err := reportPKCS11Inventory(ctx, a, ch, o); err != nil {
			// Surfaced, never swallowed: a cgo-free build says it cannot look
			// rather than reporting a clean token estate (epic C1).
			fmt.Fprintln(os.Stderr, "trstctl-agent: PKCS#11 inventory report failed:", err)
		}
	}
	if len(o.inventoryWindowsStores) > 0 {
		if err := reportWindowsStoreInventory(ctx, a, ch, o); err != nil {
			// The error is surfaced, never swallowed into an empty report: on a
			// non-Windows build this says so out loud rather than letting an
			// operator conclude their Windows estate is clean (epic C1).
			fmt.Fprintln(os.Stderr, "trstctl-agent: Windows certificate store inventory report failed:", err)
		}
	}

	heartbeatTimer := time.NewTimer(nextHeartbeat)
	defer heartbeatTimer.Stop()
	rotateTimer := time.NewTimer(nextRotationDelay(o.rotateEvery, a.CertificateNotAfter(), time.Now(), rng))
	defer rotateTimer.Stop()
	// The relay loop (epic A3) runs beside the heartbeat and renewal timers
	// rather than as its own scheduler, so one agent has one cadence story. It
	// is armed only when the operator asked for it AND this agent's certificate
	// actually carries the network role — a host agent that turned the flag on
	// would poll forever and be handed nothing, which reads as a stalled fabric
	// instead of a misconfiguration.
	relayTimer, relayCh, hostProfile := relayLoopFor(o, a, conn)
	var hostRollback *relay.HostRollbackStore
	if len(hostProfile.AllowedRoots) > 0 {
		stateDir := strings.TrimSpace(o.hostRollbackDir)
		if stateDir == "" {
			stateDir = filepath.Join(filepath.Dir(o.keyPath), "host-rollbacks")
		}
		stateDir, err = filepath.Abs(stateDir)
		if err != nil {
			return fmt.Errorf("resolve host rollback directory: %w", err)
		}
		hostRollback, err = relay.NewHostRollbackStore(stateDir, a.Identity().TenantID())
		if err != nil {
			// Fail before claiming a host deploy. Running without the ledger would
			// make the deploy work and its rollback impossible after a restart.
			return fmt.Errorf("initialize host rollback predecessor store: %w", err)
		}
		fmt.Printf("trstctl-agent: encrypted host rollback state enabled at %s\n", stateDir)
	}
	if relayTimer != nil {
		defer relayTimer.Stop()
	}
	// A5: this agent's own upgrade executor. Built once — the executable path
	// and version do not change for the life of the process, and a nil selfUp
	// means the claim loop never asks for the kind.
	var selfUp *relay.SelfUpgrade
	if o.selfUpgrade {
		if exe, exeErr := os.Executable(); exeErr != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: --self-upgrade disabled: cannot locate own executable:", exeErr)
		} else {
			selfUp = &relay.SelfUpgrade{
				ExecutablePath: exe,
				CurrentVersion: buildinfo.Version(),
				// Private ranges allowed, deliberately: this agent lives inside
				// the customer network and an air-gapped estate's artifact
				// mirror is RFC1918 by construction. --self-upgrade is the
				// machine operator's consent to fetch what campaigns point at;
				// the pinned sha256, not the network path, is the integrity
				// control. Loopback, link-local and the other SSRF classes
				// stay blocked.
				Client: netsec.SafeClientWithOptions(5*time.Minute, netsec.SafeClientOptions{
					AllowPrivateCIDRs: rfc1918AndULA(),
				}),
				Restart: restartSelf,
			}
		}
	}

	// B3: the SPIFFE Workload API, served on this host for the workloads that
	// run on it. Its own goroutine because it is a listener rather than a
	// polling loop — workloads dial it when they need an SVID, and it must be
	// answering before they do.
	stopWorkloadAPI := startWorkloadAPI(ctx, o, conn)
	defer stopWorkloadAPI()
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
		case <-relayTimerChan(relayTimer):
			// Claim, redeem, deploy, wipe, report — one pass. Failures are the
			// job's business, not the loop's: every path inside reports, so work
			// returns to the queue rather than waiting out its lease.
			lease := int(relayLeaseFor(o.relayPollEvery).Seconds())
			var executed int
			var rerr error
			if o.relayClaim {
				executed, rerr = relay.RunOnceWithSelfUpgradeAndHostRollback(ctx, relayCh, relayHTTPClient(), hostProfile, pluginRuntime, selfUp, hostRollback, relayClaimBatch, lease)
			} else {
				// Self-upgrade only: ask for nothing but this agent's own
				// upgrade jobs (A5).
				executed, rerr = relay.RunOnceSelfUpgradeOnly(ctx, relayCh, selfUp, relayClaimBatch, lease)
			}
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: relay claim failed:", rerr)
			} else if executed > 0 {
				fmt.Printf("trstctl-agent: relay executed %d job(s)\n", executed)
			}
			resetTimer(relayTimer, o.relayPollEvery)
		case <-rotateTimer.C:
			// Renew with jittered exponential backoff on failure (RESIL-006): a
			// control-plane outage during the refresh window must not be a single missed
			// attempt that then waits a full rotate-every interval. The existing
			// certificate stays valid until expiry and the identity survives restart.
			if renewWithBackoff(ctx, a, ch, o.rotateEvery, rng) {
				fmt.Println("trstctl-agent: renewed identity adopted; reconnecting the agent channel with the new certificate")
				return errAgentIdentityRotated
			}
			// A5: re-armed from the credential's remaining life, not from the
			// configured cadence alone, so a renewal that failed through an
			// outage comes back before expiry rather than one interval later.
			resetTimer(rotateTimer, nextRotationDelay(o.rotateEvery, a.CertificateNotAfter(), time.Now(), rng))
		}
	}
}

func agentCarriesRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
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

// reportKubernetesSecretInventory is the shipped-agent caller for the k8s-secret
// source kind (C1). A cluster's TLS Secrets are frequently the largest population
// of certificates an organization holds and the one nobody has an inventory of;
// the read side existed unwired, so the kind was advertised and collected nothing.
//
// Metadata only: the enumerator reads `tls.crt`, which is public certificate
// material, and never `tls.key`. The control plane derives the tenant from this
// connection's verified client certificate.
func reportKubernetesSecretInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient) error {
	client, err := k8s.InCluster()
	if err != nil {
		return fmt.Errorf("kubernetes in-cluster client: %w", err)
	}
	found, err := agentdiscovery.NewKubernetesSecretSource(client.Namespace(), client).Discover(ctx)
	if err != nil {
		return err
	}
	return reportFoundInventory(ctx, a, ch, agentdiscovery.SourceKubernetes, found, 30, "kubernetes secret inventory")
}

// reportPKCS11Inventory inventories the certificate objects on the configured
// token(s). Metadata only, over a read-only session; no private key object is
// searched for and none is read.
func reportPKCS11Inventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, o agentOptions) error {
	cfg := agentdiscovery.PKCS11Config{
		ModulePath: o.inventoryPKCS11Module,
		TokenLabel: o.inventoryPKCS11Token,
	}
	if o.inventoryPKCS11PINFile != "" {
		pin, err := os.ReadFile(o.inventoryPKCS11PINFile) // #nosec G304 -- operator-supplied PIN file path, read at their instruction (CWE-22)
		if err != nil {
			return fmt.Errorf("read PKCS#11 PIN file: %w", err)
		}
		// The PIN lives as bytes and is wiped as soon as the read completes
		// (AN-8); it is never turned into a long-lived string here.
		cfg.UserPIN = bytes.TrimSpace(pin)
		defer secret.Wipe(cfg.UserPIN)
	}
	found, err := agentdiscovery.NewPKCS11CertSource(cfg).Discover(ctx)
	if err != nil {
		return err
	}
	return reportFoundInventory(ctx, a, ch, agentdiscovery.SourcePKCS11, found, 30, "pkcs11 token inventory")
}

// reportWindowsStoreInventory inventories the requested Windows certificate
// stores. Metadata only: it reads certificates, never the keys behind them.
//
// A store that cannot be read fails the whole report rather than contributing
// nothing, because a partially-read Windows estate presented as complete is the
// false-clean result epic C1 exists to remove.
func reportWindowsStoreInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, o agentOptions) error {
	location := agentdiscovery.WindowsStoreLocation(o.inventoryWindowsLocation)
	if !agentdiscovery.ValidWindowsStoreLocation(location) {
		return fmt.Errorf("unknown --inventory-windows-location %q (want local-machine or current-user)", o.inventoryWindowsLocation)
	}
	stores := o.inventoryWindowsStores
	if len(stores) == 1 && strings.EqualFold(stores[0], "all") {
		stores = agentdiscovery.WindowsStoreNames()
	}
	var found []agentdiscovery.Found
	for _, store := range stores {
		if !agentdiscovery.ValidWindowsStoreName(store) {
			return fmt.Errorf("unknown Windows certificate store %q (want one of %v, or \"all\")", store, agentdiscovery.WindowsStoreNames())
		}
		got, err := agentdiscovery.NewWindowsCertStoreSource(location, store).Discover(ctx)
		if err != nil {
			return fmt.Errorf("read Windows store %s/%s: %w", location, store, err)
		}
		found = append(found, got...)
	}
	return reportFoundInventory(ctx, a, ch, agentdiscovery.SourceWindowsCert, found, 30, "windows certificate store inventory")
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
	findingKind := "x509_certificate"
	if sourceKind == agentdiscovery.SourceTrustStore {
		// A trust anchor is still an X.509 certificate, but the Graph builder must
		// distinguish "this public certificate is installed as trusted" from an
		// ordinary leaf inventory record. The source describes the scan; the kind
		// describes what each resulting record means.
		findingKind = agentdiscovery.SourceTrustStore
	}
	for _, f := range found {
		meta := map[string]string{
			"subject":        f.Cert.Subject,
			"issuer":         f.Cert.Issuer,
			"serial":         f.Cert.SerialNumber,
			"key_algorithm":  f.Cert.KeyAlgorithm,
			"not_after":      f.Cert.NotAfter.Format(time.RFC3339),
			"spki_sha256":    f.Cert.SPKISHA256,
			"subject_key_id": f.Cert.SubjectKeyID,
		}
		for k, v := range f.Metadata {
			meta[k] = v
		}
		findings = append(findings, agent.InventoryFinding{
			Kind:        findingKind,
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

type inventoryReporter interface {
	ReportInventory(context.Context, agent.ChannelClient, string, []agent.InventoryFinding) (*agent.InventoryResponse, error)
}

func hasSSHInventory(cfg sshdiscovery.Config) bool {
	return len(cfg.HostKeyGlobs) > 0 ||
		len(cfg.UserKeyGlobs) > 0 ||
		len(cfg.AuthorizedKeysPaths) > 0 ||
		len(cfg.KnownHostsPaths) > 0 ||
		len(cfg.SSHDConfigPaths) > 0
}

// reportSSHInventory is the shipped-agent caller for F42. Collection is
// explicitly configured and metadata-only: public key bytes never cross the
// agent channel. The control plane derives the tenant from this connection's
// verified client certificate.
func reportSSHInventory(ctx context.Context, reporter inventoryReporter, ch agent.ChannelClient, cfg sshdiscovery.Config) error {
	found, err := sshdiscovery.New(cfg).Discover(ctx)
	if err != nil {
		return err
	}
	findings := make([]agent.InventoryFinding, 0, len(found))
	for _, f := range found {
		risk := 20
		if f.StandingAccess {
			risk = 70
		}
		if f.Orphaned {
			risk = 90
		}
		findings = append(findings, agent.InventoryFinding{
			Kind:        "ssh_key",
			Ref:         f.Location,
			Provenance:  f.Source + ":" + f.Location + ":" + f.Fingerprint,
			Fingerprint: f.Fingerprint,
			RiskScore:   risk,
			Metadata: map[string]string{
				"source":          f.Source,
				"location":        f.Location,
				"key_type":        f.KeyType,
				"comment":         f.Comment,
				"standing_access": strconv.FormatBool(f.StandingAccess),
				"orphaned":        strconv.FormatBool(f.Orphaned),
				"key_bytes":       "not_collected",
			},
		})
	}
	if len(findings) == 0 {
		return nil
	}
	resp, err := reporter.ReportInventory(ctx, ch, sshdiscovery.SourceKind, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d SSH inventory findings (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	return nil
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

// enrollmentEnroller keeps the development exception narrow. HTTPS always uses
// the operator-provided CA bundle. Only an explicit HTTP loopback command gets a
// nil client, which makes NewHTTPEnroller install its DNS-rechecking loopback-only
// transport; the flag can never turn a general HTTP client into plaintext egress.
func enrollmentEnroller(o agentOptions, pinnedClient *http.Client) *agent.HTTPEnroller {
	if o.allowInsecureLoopbackEnrollment && strings.HasPrefix(strings.ToLower(strings.TrimSpace(o.enrollURL)), "http://") {
		return agent.NewHTTPEnroller(o.enrollURL, nil, agent.WithLoopbackDevHTTP())
	}
	return agent.NewHTTPEnroller(o.enrollURL, pinnedClient)
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
type channelAdapter struct {
	c                *transport.AgentClient
	enrollmentProxy  func() *transport.EnrollmentProxyReport
	pluginIdentity   *mtls.AgentIdentity
	pluginCensus     func() []plugincensus.Entry
	revocationCaches func() []revcacheposture.Entry
	// revocationIssuedAt makes signed evidence strictly newer across immediate
	// reconnects even when the wall clock has only one-second wire precision.
	revocationIssuedAt *atomic.Int64
}

func (a channelAdapter) Heartbeat(ctx context.Context, req *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	wire := &transport.HeartbeatRequest{
		AgentID: req.AgentID, Version: req.Version, Status: req.Status,
		CertSerial: req.CertSerial, Inventory: workloadAPICounters(req.Inventory),
	}
	if a.enrollmentProxy != nil {
		wire.EnrollmentProxy = a.enrollmentProxy()
	}
	if a.pluginCensus != nil {
		if a.pluginIdentity == nil {
			return nil, errors.New("plugin census signer is not configured")
		}
		report, err := transport.SignedPluginCensus(a.pluginIdentity,
			a.pluginIdentity.TenantID(), a.pluginIdentity.CommonName(),
			a.pluginCensus(), time.Now().UTC().Unix())
		if err != nil {
			return nil, fmt.Errorf("sign relay plugin census: %w", err)
		}
		wire.RelayPlugins = report
	}
	if a.revocationCaches != nil {
		if a.pluginIdentity == nil {
			return nil, errors.New("revocation cache posture signer is not configured")
		}
		issuedAt := time.Now().UTC().Unix()
		if a.revocationIssuedAt != nil {
			issuedAt = nextMonotonicUnix(a.revocationIssuedAt, issuedAt)
		}
		report, err := transport.SignedRevocationCachePosture(a.pluginIdentity,
			a.pluginIdentity.TenantID(), a.pluginIdentity.CommonName(),
			a.revocationCaches(), issuedAt)
		if err != nil {
			return nil, fmt.Errorf("sign revocation cache posture: %w", err)
		}
		wire.RevocationCaches = report
	}
	resp, err := a.c.Heartbeat(ctx, wire)
	if err != nil {
		return nil, err
	}
	return &agent.HeartbeatResponse{TenantID: resp.TenantID, NextHeartbeatSeconds: resp.NextHeartbeatSeconds}, nil
}

func nextMonotonicUnix(last *atomic.Int64, now int64) int64 {
	for {
		prior := last.Load()
		next := now
		if next <= prior {
			next = prior + 1
		}
		if last.CompareAndSwap(prior, next) {
			return next
		}
	}
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
func renewWithBackoff(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, budget time.Duration, rng *rand.Rand) bool {
	deadline := time.Now().Add(budget)
	for attempt := 0; ; attempt++ {
		if err := a.RenewOverChannel(ctx, ch); err == nil {
			fmt.Printf("trstctl-agent: renewed client certificate over the agent channel (serial %s)\n", a.CertificateSerial())
			return true
		} else {
			fmt.Fprintln(os.Stderr, "trstctl-agent: channel renewal failed:", err)
		}
		delay := rotateBackoff(attempt, rng)
		if time.Now().Add(delay).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
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

// nextRotationDelay decides when the agent next attempts to rotate (epic A5).
//
// The rotate timer used to be the configured interval and nothing else, which
// makes the agent's own expiry a thing it can sleep through. Three ordinary
// situations produce that: --rotate-every set longer than the certificate's
// lifetime, a control-plane outage spanning a whole interval so the one attempt
// in the window fails and the next is a full interval away, and an agent that
// starts late holding a certificate already most of the way through its life.
// In each the agent wakes up after its credential expired and can no longer
// authenticate to renew it — the failure that needs a human on the box, for a
// fleet whose whole point is not needing one.
//
// So the delay is bounded by the credential's REMAINING LIFE as the local clock
// sees it, not by the configured cadence. This is deliberately a local-clock
// decision: an agent that cannot reach the control plane is exactly the agent
// that needs to renew early, and it has no other clock to consult.
//
// Jitter spreads a fleet that enrolled together. Without it ten thousand agents
// installed by the same automation renew in the same second, and the thundering
// herd arrives precisely when the control plane is least able to absorb it —
// during the recovery from the outage that synchronised them.
func nextRotationDelay(rotateEvery time.Duration, notAfter, now time.Time, rng *rand.Rand) time.Duration {
	if rotateEvery <= 0 {
		rotateEvery = 12 * time.Hour
	}
	if notAfter.IsZero() {
		// No credential expiry known — bootstrap, or an identity that carries
		// no NotAfter. Fall back to the configured cadence rather than
		// inventing urgency from an absent value.
		return rotateEvery
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		// Already expired. Retry promptly; the backoff inside renewWithBackoff
		// is what keeps this from becoming a spin.
		return time.Second
	}
	// Aim to renew with a third of the lifetime left, and take the configured
	// cadence only when it is SOONER.
	//
	// This min() is the whole guarantee, and it is worth being precise about
	// which half carries it: two-thirds-of-remaining is strictly less than
	// remaining, so the next attempt lands before expiry no matter how long the
	// operator set --rotate-every. A first draft also clamped to
	// remaining-remaining/10 "so it never sleeps past expiry"; mutation-testing
	// showed deleting that clamp changed no outcome, because 2/3 is already
	// below 9/10. It was dead code under a comment claiming to be load-bearing,
	// which is worse than no comment.
	//
	// Two thirds through is early enough that a failed attempt has room for
	// several retries before anything is at risk, and late enough not to churn
	// certificates.
	target := remaining * 2 / 3
	if target > rotateEvery {
		target = rotateEvery
	}
	// +/-10% jitter, floored so it never returns zero or negative.
	if rng != nil && target > 0 {
		spread := target / 5
		if spread > 0 {
			target = target - spread/2 + time.Duration(rng.Int63n(int64(spread)))
		}
	}
	if target < time.Second {
		target = time.Second
	}
	return target
}
