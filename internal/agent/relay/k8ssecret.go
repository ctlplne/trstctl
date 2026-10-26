// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/connector"
)

// KubernetesSecretConnector is the in-cluster delivery target: the
// kubernetes.io/tls Secret an Ingress or Gateway names, written by a host-role
// agent running inside that cluster. The agent generates the key there, so the
// key never leaves the cluster and the control plane never generates it.
const KubernetesSecretConnector = "k8s_secret"

// ProfileGrantsHostWork reports whether an operator profile lets this agent
// take host deploys at all: host roots for file and reload connectors, or a
// cluster agent's Kubernetes namespaces for k8s_secret.
func ProfileGrantsHostWork(profile connector.LocalOpsConfig) bool {
	return len(profile.AllowedRoots) > 0 || len(profile.KubernetesSecretNamespaces) > 0
}

// newKubernetesClient reaches the cluster the agent runs in through the pod's
// service account. Tests point it at a fake API server.
var newKubernetesClient = k8s.InCluster

var (
	kubernetesLabelPattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	kubernetesSubdomainPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

func kubernetesNamespaceName(name string) bool {
	return len(name) <= 63 && kubernetesLabelPattern.MatchString(name)
}

func kubernetesObjectName(name string) bool {
	return len(name) <= 253 && kubernetesSubdomainPattern.MatchString(name)
}

// kubernetesSecretTarget decodes the Secret a target names and checks it
// against the operator's profile. It runs before a key exists: a key generated
// for a Secret this agent may not write would have no consumer.
func kubernetesSecretTarget(profile connector.LocalOpsConfig, intent DeployIntent) (namespace, name string, err error) {
	var target HostTargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return "", "", fmt.Errorf("relay: decode Kubernetes Secret target: %w", err)
		}
	}
	namespace, name = strings.TrimSpace(target.Namespace), strings.TrimSpace(target.SecretName)
	if !kubernetesNamespaceName(namespace) || !kubernetesObjectName(name) {
		return "", "", errors.New("relay: a Kubernetes Secret target needs a namespace and a secret_name that Kubernetes accepts")
	}
	if !slices.Contains(profile.KubernetesSecretNamespaces, namespace) {
		return "", "", fmt.Errorf("relay: this agent's profile does not allow writing Secrets in namespace %q", namespace)
	}
	return namespace, name, nil
}

// installKubernetesSecret writes the serving chain and key into the target
// Secret and reads it back. An accepted write is not proof on its own: the
// install succeeds only when the cluster holds the certificate just written.
func installKubernetesSecret(ctx context.Context, profile connector.LocalOpsConfig, intent DeployIntent, servingCertPEM, keyPEM []byte) (connector.Stats, error) {
	namespace, name, err := kubernetesSecretTarget(profile, intent)
	if err != nil {
		return connector.Stats{}, err
	}
	client, err := newKubernetesClient()
	if err != nil {
		return connector.Stats{}, fmt.Errorf("relay: reach the cluster API: %w", err)
	}
	readback, err := k8s.NewSecretDestination(client, namespace, name).InstallAndRead(ctx,
		destination.Credential{CertPEM: servingCertPEM, KeyPEM: keyPEM})
	if err != nil {
		return connector.Stats{}, err
	}
	if !bytes.Equal(readback.CertPEM, servingCertPEM) {
		return connector.Stats{}, fmt.Errorf("relay: Secret %s/%s does not hold the certificate just written", namespace, name)
	}
	return connector.Stats{}, nil
}

// dryRunKubernetesSecret is the k8s_secret preflight: the target fits the
// operator's namespace allowlist, the cluster API answers for that Secret, and
// any configured listener is reachable. It reads; it never writes.
func dryRunKubernetesSecret(ctx context.Context, profile connector.LocalOpsConfig, intent DeployIntent, plan Plan) Plan {
	namespace, name, err := kubernetesSecretTarget(profile, intent)
	if err != nil {
		plan.Steps = append(plan.Steps, PlanStep{Name: "target-config", Status: StepFailed, Detail: strings.TrimPrefix(err.Error(), "relay: ")})
		return plan
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "target-config", Status: StepOK,
		Detail: fmt.Sprintf("the target names Secret %s/%s, inside the namespaces this agent's profile allows", namespace, name),
	})
	client, err := newKubernetesClient()
	if err != nil {
		plan.Steps = append(plan.Steps, PlanStep{Name: "host-authority", Status: StepFailed, Detail: "the cluster API is not reachable from this agent: " + err.Error()})
		return plan
	}
	status, err := k8s.NewSecretDestination(client, namespace, name).Status(ctx)
	switch {
	case err != nil:
		plan.Steps = append(plan.Steps, PlanStep{Name: "host-authority", Status: StepFailed, Detail: "the cluster API did not answer for the Secret: " + err.Error()})
		return plan
	case status == http.StatusOK:
		plan.Steps = append(plan.Steps, PlanStep{Name: "host-authority", Status: StepOK, Detail: "the Secret exists and a deploy would replace its certificate and key"})
	case status == http.StatusNotFound:
		plan.Steps = append(plan.Steps, PlanStep{Name: "host-authority", Status: StepOK, Detail: "the Secret does not exist yet and a deploy would create it"})
	default:
		plan.Steps = append(plan.Steps, PlanStep{Name: "host-authority", Status: StepFailed,
			Detail: fmt.Sprintf("the cluster API answered %d for the Secret; check this agent's RBAC for Secrets in %s", status, namespace)})
		return plan
	}
	plan.Endpoint = strings.TrimSpace(intent.VerifyAddress)
	reachability := probeHostListenerWithNative(ctx, plan.Endpoint, strings.TrimSpace(intent.VerifyServerName), connectorTLSNegotiation(intent.Connector), profile.TLSProbeOpenSSL)
	plan.Steps = append(plan.Steps, reachability)
	if reachability.Status == StepFailed {
		return plan
	}
	plan.Ready = true
	plan.WouldMutate = []string{fmt.Sprintf("replace tls.crt and tls.key in Secret %s/%s", namespace, name)}
	return plan
}
