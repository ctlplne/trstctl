package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/k8s"
)

// k8sOptions configures the agent's Kubernetes DaemonSet mode.
type k8sOptions struct {
	secret         string // "namespace/name" of the TLS Secret to write the identity into
	issuer         string // cert-manager issuerRef name to bridge (empty disables the bridge)
	group          string // cert-manager issuerRef group
	signerURL      string // control-plane issuance URL the bridge forwards CSRs to
	reconcileEvery time.Duration
}

// runKubernetes runs the agent as a DaemonSet pod: it bootstraps its identity,
// publishes it into a Kubernetes Secret, and (when configured) reconciles
// cert-manager CertificateRequests as an external issuer.
func runKubernetes(ctx context.Context, o agentOptions, k k8sOptions) error {
	client, err := k8s.InCluster()
	if err != nil {
		return err
	}

	caPEM, err := os.ReadFile(o.caBundle)
	if err != nil {
		return fmt.Errorf("read CA bundle: %w", err)
	}
	token, err := bootstrapTokenForRun(o)
	if err != nil {
		return err
	}
	enrollClient, err := enrollmentHTTPClient(caPEM)
	if err != nil {
		return fmt.Errorf("build enrollment TLS trust: %w", err)
	}
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}
	a := agent.New(agent.Config{
		CommonName: o.commonName, BootstrapToken: token,
		KeyPath: o.keyPath, CertPath: o.certPath,
		ServerName: serverName, ServerCAPEM: caPEM, RefreshBefore: o.rotateEvery,
	}, agent.NewHTTPEnroller(o.enrollURL, enrollClient))
	if err := a.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	if k.secret != "" {
		ns, name, ok := strings.Cut(k.secret, "/")
		if !ok {
			return fmt.Errorf("--k8s-secret must be namespace/name, got %q", k.secret)
		}
		certPEM, err := os.ReadFile(o.certPath)
		if err != nil {
			return fmt.Errorf("read certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(o.keyPath)
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
		if err := k8s.NewSecretDestination(client, ns, name).Install(ctx, destination.Credential{CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
			return fmt.Errorf("write secret %s: %w", k.secret, err)
		}
		fmt.Printf("trstctl-agent: published identity into secret %s\n", k.secret)
	}

	var bridge *k8s.Bridge
	switch {
	case k.issuer == "":
		// No bridge configured.
	case k.signerURL == "":
		fmt.Fprintln(os.Stderr, "trstctl-agent: --cert-manager-issuer set but --bridge-signer-url is empty; cert-manager bridge disabled")
	default:
		bridge = k8s.NewBridge(client, k8s.NewHTTPSigner(k.signerURL, enrollClient), k.issuer, k.group)
		fmt.Printf("trstctl-agent: cert-manager bridge active for issuer %q\n", k.issuer)
	}

	if bridge == nil {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(k.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			n, err := bridge.Reconcile(ctx, client.Namespace())
			if err != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: cert-manager reconcile:", err)
			} else if n > 0 {
				fmt.Printf("trstctl-agent: signed %d cert-manager request(s)\n", n)
			}
		}
	}
}
