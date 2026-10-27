// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
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
	resync          time.Duration // the controller's full re-check beyond its watches
	trustRollouts   bool          // apply TrustBundles the control plane rolls out here
	// csrApprover lets the issuing CA approve or deny native CSRs for trstctl
	// signer names (A195); off leaves approval to a Kubernetes approver.
	csrApprover bool
}

func (k k8sOptions) validateIssuerConfig() error {
	if k.controller && k.issuer != "" {
		return fmt.Errorf("cert-manager signing modes cannot combine --cert-manager-controller with --cert-manager-issuer")
	}
	if k.issuer == "" && !k.controller {
		if k.signerURL != "" || k.signerTokenFile != "" {
			return fmt.Errorf("cert-manager signer flags require --cert-manager-controller or --cert-manager-issuer")
		}
		return nil
	}
	if k.signerURL == "" || k.signerTokenFile == "" {
		return fmt.Errorf("cert-manager integration requires --bridge-signer-url and --bridge-signer-token-file")
	}
	endpoint, err := url.Parse(k.signerURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("cert-manager issuance URL must be HTTPS without credentials, query, or fragment")
	}
	if k.reconcileEvery <= 0 {
		return fmt.Errorf("cert-manager reconcile interval must be positive")
	}
	if k.controller && k.resync < 0 {
		return fmt.Errorf("the Kubernetes controller resync interval must not be negative")
	}
	if k.csrApprover && !k.controller {
		return fmt.Errorf("--k8s-csr-approver requires --cert-manager-controller")
	}
	return nil
}

// runKubernetes runs the agent as a DaemonSet pod: it bootstraps its identity,
// publishes it into a Kubernetes Secret, and (when configured) reconciles
// trstctl Issuer/ClusterIssuer/Certificate resources, cert-manager
// CertificateRequests, and native Kubernetes CertificateSigningRequests.
func runKubernetes(ctx context.Context, o agentOptions, k k8sOptions) error {
	if err := k.validateIssuerConfig(); err != nil {
		return err
	}
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
	enroller := enrollmentEnroller(o, enrollClient)
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}
	a := agent.New(agent.Config{
		CommonName: o.commonName, BootstrapToken: token,
		KeyPath: o.keyPath, CertPath: o.certPath,
		ServerName: serverName, ServerCAPEM: caPEM, RefreshBefore: o.rotateEvery,
		Version: buildinfo.Version(),
	}, enroller)
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
			issuerController, err = k8s.NewIssuerController(client, signer, k.group, k.signerURL)
			if err != nil {
				return err
			}
			fmt.Printf("trstctl-agent: trstctl Issuer/ClusterIssuer/Certificate controller active for group %q\n", k.group)
			if k.csrApprover {
				issuerController.WithCSRApprover(signer)
				fmt.Printf("trstctl-agent: native CSRs for %s/* signer names are approved or denied by the issuing CA's profile\n", k.group)
			}
		}
	}

	if bridge == nil && issuerController == nil {
		<-ctx.Done()
		return nil
	}
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
		postureClient := transport.NewAgentClient(conn, transport.WithAgentVersion(buildinfo.Version()))
		return runKubernetesController(ctx, client, issuerController, postureClient, k)
	}

	ticker := time.NewTicker(k.reconcileEvery)
	defer ticker.Stop()
	reconcile := func() {
		n, err := bridge.Reconcile(ctx, client.Namespace())
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: cert-manager bridge reconcile:", err)
		} else if n > 0 {
			fmt.Printf("trstctl-agent: reconciled %d Kubernetes certificate request(s)\n", n)
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

// runKubernetesController runs the cluster-scoped controller event-driven:
// informers watch its resources and a work queue converges each object as it
// changes, re-checking everything every k.resync and reporting posture after
// each burst of changes and every k.reconcileEvery.
//
// The agent is a DaemonSet, so the controller first wins a coordination.k8s.io
// Lease: without it every node would reconcile the same Issuer/ClusterIssuer/
// TrustBundle objects. Signing and status writes are idempotent, so this is
// about not multiplying API-server work and audit noise by the node count. A
// follower idles and takes over within one lease duration if the holder dies,
// and a holder that loses the lease stops its watches. Absent RBAC for leases,
// it logs once and runs anyway: losing the controller entirely would be worse
// than duplicating idempotent work.
func runKubernetesController(ctx context.Context, client *k8s.Client, controller *k8s.IssuerController, postureClient *transport.AgentClient, k k8sOptions) error {
	opts := k8s.RunOptions{
		ClusterID: client.ClusterID(), ReportEvery: k.reconcileEvery, Resync: k.resync,
		Report: func(ctx context.Context, report k8s.ControllerPostureReport) {
			response, err := postureClient.ReportKubernetesPosture(ctx, transportKubernetesPostureReport(report))
			if err != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes posture report:", err)
				return
			}
			// The control plane answers with the TrustBundles it is rolling
			// out to this cluster; the controller's watch distributes them and
			// the next report proves them.
			if !k.trustRollouts || len(response.DesiredTrustBundles) == 0 {
				return
			}
			desired := make([]k8s.DesiredTrustBundle, 0, len(response.DesiredTrustBundles))
			for _, bundle := range response.DesiredTrustBundles {
				desired = append(desired, k8s.DesiredTrustBundle{
					RolloutID: bundle.RolloutID, Name: bundle.Name, CABundlePEM: bundle.CABundlePEM, BundleSHA256: bundle.BundleSHA256,
					ConfigMapName: bundle.ConfigMapName, Key: bundle.Key, Namespaces: bundle.Namespaces,
				})
			}
			if n, err := controller.ApplyDesiredTrustBundles(ctx, desired); err != nil {
				fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes trust rollout:", err)
			} else if n > 0 {
				fmt.Printf("trstctl-agent: applied %d rolled-out TrustBundle(s)\n", n)
			}
		},
	}
	lease := k8s.NewLease(client, k8sControllerLeaseName, k.leaseIdentity())
	leaseWarned := false
	var stop context.CancelFunc
	var stopped chan struct{}
	halt := func() {
		if stop != nil {
			stop()
			<-stopped
			stop, stopped = nil, nil
		}
	}
	defer halt()
	renew := time.NewTicker(k8s.LeaseRenewInterval)
	defer renew.Stop()
	for {
		leading, err := lease.Acquire(ctx)
		if err != nil {
			if !leaseWarned {
				fmt.Fprintln(os.Stderr, "trstctl-agent: leader election unavailable, reconciling without it:", err)
				leaseWarned = true
			}
			leading = true
		}
		switch {
		case leading && stop == nil:
			runCtx, cancel := context.WithCancel(ctx)
			stop, stopped = cancel, make(chan struct{})
			go func(done chan struct{}) {
				defer close(done)
				if err := controller.Run(runCtx, opts); err != nil {
					fmt.Fprintln(os.Stderr, "trstctl-agent: Kubernetes controller:", err)
				}
			}(stopped)
			fmt.Println("trstctl-agent: leading the Kubernetes controller")
		case !leading && stop != nil:
			halt()
			fmt.Println("trstctl-agent: lost the Kubernetes controller lease; following")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-renew.C:
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
				ParentUID: resource.ParentUID, ParentName: resource.ParentName,
			})
		}
		return transport.KubernetesPostureSection{Complete: section.Complete, FailureCode: section.FailureCode, Resources: resources}
	}
	return &transport.KubernetesPostureRequest{
		ReportID: report.ReportID, ClusterID: report.ClusterID,
		ReconcileIntervalSeconds: report.ReconcileIntervalSeconds,
		CertificateSigning:       convert(report.CertificateSigning), TrustBundles: convert(report.TrustBundles),
		CertificateRequests: ptrKubernetesPostureSection(convert(report.CertificateRequests)),
	}
}

func ptrKubernetesPostureSection(section transport.KubernetesPostureSection) *transport.KubernetesPostureSection {
	return &section
}
