package api

import (
	"net/http"
	"time"
)

type KubernetesCSRSupportRule struct {
	APIGroup string   `json:"api_group"`
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
}

type KubernetesCSRSupport struct {
	Capability             string                     `json:"capability"`
	Served                 bool                       `json:"served"`
	GeneratedAt            string                     `json:"generated_at"`
	APIGroup               string                     `json:"api_group"`
	APIVersion             string                     `json:"api_version"`
	Resource               string                     `json:"resource"`
	SignerNames            []string                   `json:"signer_names"`
	ControllerFlow         []string                   `json:"controller_flow"`
	RBACRules              []KubernetesCSRSupportRule `json:"rbac_rules"`
	StatusFields           []string                   `json:"status_fields"`
	ArchitectureControls   []string                   `json:"architecture_controls"`
	EvidenceRefs           []string                   `json:"evidence_refs"`
	Residuals              []string                   `json:"residuals"`
	RecommendedNextActions []string                   `json:"recommended_next_actions"`
}

type KubernetesTrustBundleDistribution struct {
	Capability             string                     `json:"capability"`
	Served                 bool                       `json:"served"`
	GeneratedAt            string                     `json:"generated_at"`
	APIGroup               string                     `json:"api_group"`
	APIVersion             string                     `json:"api_version"`
	Resource               string                     `json:"resource"`
	DistributionTargets    []string                   `json:"distribution_targets"`
	ControllerFlow         []string                   `json:"controller_flow"`
	RBACRules              []KubernetesCSRSupportRule `json:"rbac_rules"`
	StatusFields           []string                   `json:"status_fields"`
	ArchitectureControls   []string                   `json:"architecture_controls"`
	EvidenceRefs           []string                   `json:"evidence_refs"`
	Residuals              []string                   `json:"residuals"`
	RecommendedNextActions []string                   `json:"recommended_next_actions"`
}

func (a *API) getKubernetesCSRSupport(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildKubernetesCSRSupport(time.Now().UTC().Format(time.RFC3339)))
}

func (a *API) getKubernetesTrustBundleDistribution(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildKubernetesTrustBundleDistribution(time.Now().UTC().Format(time.RFC3339)))
}

func buildKubernetesCSRSupport(generatedAt string) KubernetesCSRSupport {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return KubernetesCSRSupport{
		Capability:  "CAP-K8S-04",
		Served:      true,
		GeneratedAt: generatedAt,
		APIGroup:    "certificates.k8s.io",
		APIVersion:  "certificates.k8s.io/v1",
		Resource:    "certificatesigningrequests",
		SignerNames: []string{
			"trstctl.com/trstctl",
			"trstctl.com/<clusterissuer-name>",
			"trstctl.com/<issuer-name> with trstctl.com/issuer-kind=Issuer",
		},
		ControllerFlow: []string{
			"DaemonSet trstctl-agent runs --cert-manager-controller with a mounted certs:issue API token",
			"controller lists certificates.k8s.io/v1 CertificateSigningRequests",
			"controller signs only Approved requests whose signerName maps to an existing trstctl Issuer or ClusterIssuer",
			"CSR DER or PEM bytes are forwarded to the served trstctl issuance endpoint with a stable Idempotency-Key",
			"issued certificate chain is written to status.certificate and Ready=True is upserted",
		},
		RBACRules: []KubernetesCSRSupportRule{
			{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verbs: []string{"get", "list", "watch"}},
			{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests/status", Verbs: []string{"update", "patch"}},
		},
		StatusFields: []string{
			"status.certificate",
			"status.conditions[type=Ready]",
		},
		ArchitectureControls: []string{
			"only approved CertificateSigningRequests are signed",
			"signerName must map to an existing trstctl Issuer or ClusterIssuer",
			"the agent writes the status subresource only and never approves requests itself",
			"only CSR bytes cross the control-plane boundary; private keys stay with the workload or Kubernetes client",
			"the HTTP signer uses a stable Idempotency-Key so retries do not mint duplicates",
		},
		EvidenceRefs: []string{
			"internal/agent/k8s/certificate_signing_request.go",
			"internal/agent/k8s/issuer_controller.go",
			"internal/agent/k8s/signer.go",
			"deploy/kubernetes/rbac.yaml",
			"deploy/kubernetes/daemonset.yaml",
			"internal/server/kubernetes_csr_served_test.go",
		},
		Residuals: []string{
			"the controller is poll-based rather than informer/workqueue-backed",
			"approval policy remains a Kubernetes approver responsibility; trstctl signs only requests Kubernetes has already approved",
			"multi-cluster rollout uses one DaemonSet/install per cluster",
		},
		RecommendedNextActions: []string{
			"move reconciliation to informer-backed queues for very large clusters",
			"publish sample approver policy for signerName-to-tenant/profile governance",
			"add per-CSR delivery receipts to the operations queue",
		},
	}
}

func buildKubernetesTrustBundleDistribution(generatedAt string) KubernetesTrustBundleDistribution {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return KubernetesTrustBundleDistribution{
		Capability:  "CAP-K8S-07",
		Served:      true,
		GeneratedAt: generatedAt,
		APIGroup:    "trstctl.com",
		APIVersion:  "trstctl.com/v1alpha1",
		Resource:    "trustbundles",
		DistributionTargets: []string{
			"v1 ConfigMap data[ca-bundle.pem] in each declared target namespace",
			"one trstctl-agent DaemonSet/install per cluster, with the same TrustBundle spec applied per cluster",
			"status.conditions[type=Ready], status.targets, and status.bundleSHA256 on the TrustBundle resource",
		},
		ControllerFlow: []string{
			"operator applies a cluster-scoped trstctl.com/v1alpha1 TrustBundle with public PEM caBundlePEM and target namespaces",
			"trstctl-agent lists TrustBundle resources using the service-account token",
			"the controller validates that caBundlePEM contains only PEM CERTIFICATE blocks",
			"the controller creates or updates the named ConfigMap in every target namespace with the public CA bundle",
			"the controller updates TrustBundle status with target count, bundleSHA256, and Ready=True",
		},
		RBACRules: []KubernetesCSRSupportRule{
			{APIGroup: "trstctl.com", Resource: "trustbundles", Verbs: []string{"get", "list", "watch"}},
			{APIGroup: "trstctl.com", Resource: "trustbundles/status", Verbs: []string{"update", "patch"}},
			{APIGroup: "", Resource: "configmaps", Verbs: []string{"get", "list", "watch", "create", "update", "patch"}},
		},
		StatusFields: []string{
			"status.targets",
			"status.bundleSHA256",
			"status.conditions[type=Ready]",
		},
		ArchitectureControls: []string{
			"only public PEM CERTIFICATE blocks are accepted; private-key PEM blocks fail closed before any ConfigMap write",
			"ConfigMaps receive public CA bundles only; no private key or service-account credential is copied",
			"updates are idempotent create-or-update writes keyed by namespace/name and Kubernetes resourceVersion",
			"distribution stays in the Kubernetes agent controller and does not add a new control-plane datastore or signer path",
			"multi-cluster distribution is explicit: apply the same TrustBundle resource to each enrolled cluster/agent install",
		},
		EvidenceRefs: []string{
			"internal/agent/k8s/trust_bundle.go",
			"internal/agent/k8s/issuer_controller.go",
			"deploy/kubernetes/certmanager-issuer-crds.yaml",
			"deploy/kubernetes/rbac.yaml",
			"internal/agent/k8s/issuer_controller_test.go",
			"internal/server/kubernetes_trust_bundle_served_test.go",
		},
		Residuals: []string{
			"the controller is poll-based rather than informer/workqueue-backed",
			"multi-cluster rollout requires applying the TrustBundle CRD and object to each cluster where the agent runs",
			"the first served target is ConfigMap distribution; Secret, projected volume, and CSI distribution modes are not claimed",
		},
		RecommendedNextActions: []string{
			"move reconciliation to informer-backed queues for very large clusters",
			"add fleet-level receipts that aggregate TrustBundle propagation across clusters",
			"add optional namespace label selectors after a policy review for least-privilege rollout blast radius",
		},
	}
}
