// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// k8sOptions configures the agent's Kubernetes DaemonSet mode.
type k8sOptions struct {
	secret          string // "namespace/name" of the TLS Secret to write the identity into
	issuer          string // cert-manager issuerRef name to bridge (empty disables the bridge)
	group           string // cert-manager issuerRef group
	controller      bool   // run the trstctl Issuer/ClusterIssuer CRD controller
	signerURL       string // control-plane issuance URL the bridge forwards CSRs to
	signerTokenFile string // file containing the API token for the signer URL
	reconcileEvery  time.Duration
}

// runKubernetes runs the agent as a DaemonSet pod: it bootstraps its identity,
// publishes it into a Kubernetes Secret, and (when configured) reconciles
// trstctl Issuer/ClusterIssuer/Certificate resources, cert-manager
// CertificateRequests, and native Kubernetes CertificateSigningRequests.
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
		CommonName: o.commonName, BootstrapToken: token,
		KeyPath: o.keyPath, CertPath: o.certPath,
		ServerName: serverName, ServerCAPEM: caPEM, RefreshBefore: o.rotateEvery,
		Version: buildinfo.Version(),
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
	var issuerController *k8s.IssuerController
	switch {
	case k.issuer == "" && !k.controller:
		// No cert-manager integration configured.
	case k.signerURL == "":
		fmt.Fprintln(os.Stderr, "trstctl-agent: cert-manager integration configured but --bridge-signer-url is empty; cert-manager signing disabled")
	case k.signerTokenFile == "":
		fmt.Fprintln(os.Stderr, "trstctl-agent: cert-manager integration configured but --bridge-signer-token-file is empty; cert-manager signing disabled")
	default:
		signerToken, err := os.ReadFile(k.signerTokenFile)
		if err != nil {
			return fmt.Errorf("read cert-manager signer token: %w", err)
		}
		defer secret.Wipe(signerToken)
		signer := k8s.NewHTTPSigner(k.signerURL, enrollClient, k8s.WithBearerToken(bytes.TrimSpace(signerToken)))
		if k.issuer != "" {
			bridge = k8s.NewBridge(client, signer, k.issuer, k.group)
			fmt.Printf("trstctl-agent: cert-manager bridge active for issuer %q\n", k.issuer)
		}
		if k.controller {
			issuerController = k8s.NewIssuerController(client, signer, k.group)
			fmt.Printf("trstctl-agent: trstctl Issuer/ClusterIssuer/Certificate controller active for group %q\n", k.group)
		}
	}

	if bridge == nil && issuerController == nil {
		<-ctx.Done()
		return nil
	}
	var postureClient *transport.AgentClient
	if issuerController != nil {
		creds, err := a.Credentials()
		if err != nil {
			return fmt.Errorf("build Kubernetes posture channel credentials: %w", err)
		}
		conn, err := transport.Dial(o.serverAddr, creds)
		if err != nil {
			return fmt.Errorf("connect Kubernetes posture channel: %w", err)
		}
		defer func() { _ = conn.Close() }()
		postureClient = transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version()))
	}
	// Leader election for the cluster-scoped controller. The agent is a
	// DaemonSet, so without this every node reconciles the same
	// Issuer/ClusterIssuer/TrustBundle objects. Signing and status writes are
	// idempotent, so this is about not multiplying API-server work and audit
	// noise by the node count. A follower idles and takes over within one
	// lease duration if the holder dies. The namespaced cert-manager bridge
	// is unaffected. Absent RBAC for leases, we log once and reconcile
	// anyway: losing the controller entirely would be worse than duplicating
	// idempotent work.
	var lease *k8s.Lease
	if issuerController != nil {
		lease = k8s.NewLease(client, k8sControllerLeaseName, k.leaseIdentity())
	}
	leaseWarned := false

	ticker := time.NewTicker(k.reconcileEvery)
	defer ticker.Stop()
	reconcile := func() {
		if lease != nil {
			leading, err := lease.Acquire(ctx)
			if err != nil {
				if !leaseWarned {
					fmt.Fprintln(os.Stderr, "trstctl-agent: leader election unavailable, reconciling without it:", err)
					leaseWarned = true
				}
			} else if !leading {
				return
			}
		}
		total := 0
		if bridge != nil {
			n, err := bridge.Reconcile(ctx, client.Namespace())
			if err != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: cert-manager bridge reconcile:", err)
			} else {
				total += n
			}
		}
		if issuerController != nil {
			result, reconcileErr := issuerController.Reconcile(ctx, client.Namespace())
			total += result.SignedRequests + result.NativeCertificatesIssued + result.KubernetesCSRsSigned
			report := result.PostureReport(client.ClusterID(), k.reconcileEvery)
			if _, err := postureClient.ReportKubernetesPosture(ctx, transportKubernetesPostureReport(report)); err != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes posture report:", err)
			}
			if reconcileErr != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes issuer-controller reconcile:", reconcileErr)
			}
		}
		if total > 0 {
			fmt.Printf("trstctl-agent: reconciled %d Kubernetes certificate request(s)\n", total)
		}
	}
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reconcile()
		}
	}
}

// k8sControllerLeaseName is the coordination.k8s.io Lease the DaemonSet's pods
// contend for before running the cluster-scoped controller.
const k8sControllerLeaseName = "trstctl-agent-issuer-controller"

// leaseIdentity identifies this pod in the lease. POD_NAME comes from the
// downward API in the shipped DaemonSet; the hostname is the same value in
// practice and the fallback keeps a hand-run agent working.
func (k k8sOptions) leaseIdentity() string {
	if name := strings.TrimSpace(os.Getenv("POD_NAME")); name != "" {
		return name
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "trstctl-agent"
}

func transportKubernetesPostureReport(report k8s.ControllerPostureReport) *transport.KubernetesPostureRequest {
	convert := func(section k8s.PostureSection) transport.KubernetesPostureSection {
		resources := make([]transport.KubernetesPostureResource, 0, len(section.Resources))
		for _, resource := range section.Resources {
			resources = append(resources, transport.KubernetesPostureResource{
				Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID,
				ResourceVersion: resource.ResourceVersion, State: resource.State,
				Reason: resource.Reason, PublicHash: resource.PublicHash,
			})
		}
		return transport.KubernetesPostureSection{Complete: section.Complete, FailureCode: section.FailureCode, Resources: resources}
	}
	return &transport.KubernetesPostureRequest{
		ReportID: report.ReportID, ClusterID: report.ClusterID,
		ReconcileIntervalSeconds: report.ReconcileIntervalSeconds,
		CertificateSigning:       convert(report.CertificateSigning), TrustBundles: convert(report.TrustBundles),
	}
}
