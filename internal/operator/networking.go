// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
)

// The control plane's network surface (A133), reconciled like its Deployment:
// a Service for the API/UI port, a default-deny NetworkPolicy that opens only
// what the control plane needs, an optional Ingress, and in the isolated signer
// topology the signer's own Deployment, Service and NetworkPolicy behind the
// mutually pinned mTLS channel. The shapes follow the Helm chart
// (deploy/helm/trstctl), so both install paths give the same network posture.

// ServiceSpec is the control plane's Service.
type ServiceSpec struct {
	Type        string            `json:"type"`
	Port        int               `json:"port"`
	Annotations map[string]string `json:"annotations"`
}

// IngressSpec is an optional Ingress for the API/UI. The control plane
// terminates TLS itself, so the backend is HTTPS; give the controller its
// backend-protocol annotation (ingress-nginx:
// nginx.ingress.kubernetes.io/backend-protocol: HTTPS).
type IngressSpec struct {
	Enabled     bool              `json:"enabled"`
	ClassName   string            `json:"className"`
	Host        string            `json:"host"`
	TLSSecret   string            `json:"tlsSecret"`
	Annotations map[string]string `json:"annotations"`
}

// NetworkPolicySpec scopes who may reach the control plane and where it may
// connect. It is on unless enabled is false.
type NetworkPolicySpec struct {
	Enabled            *bool                 `json:"enabled"`
	IngressController  IngressControllerPeer `json:"ingressController"`
	AllowSameNamespace bool                  `json:"allowSameNamespace"`
	AllowedNamespaces  []string              `json:"allowedNamespaces"`
	EgressCIDRs        []string              `json:"egressCIDRs"`
	PostgresPort       int                   `json:"postgresPort"`
	NATSPort           int                   `json:"natsPort"`
}

// IngressControllerPeer names the ingress controller pods admitted to the API
// port. Unset labels default to the ingress-nginx convention, as in the chart.
type IngressControllerPeer struct {
	Disabled        bool              `json:"disabled"`
	NamespaceLabels map[string]string `json:"namespaceLabels"`
	PodLabels       map[string]string `json:"podLabels"`
}

// SignerMTLSSpec names the material for the isolated signer's mutually pinned
// channel: the signer's own Secret and the control plane's, each holding
// tls.crt, tls.key, peer-ca.pem (the CA anchoring the other side) and peer-pin
// (the hex SHA-256 pin of the other side's key).
type SignerMTLSSpec struct {
	SignerSecret       string `json:"signerSecret"`
	ControlPlaneSecret string `json:"controlPlaneSecret"`
	ServerName         string `json:"serverName"`
}

const (
	managedByLabel        = "app.kubernetes.io/managed-by"
	managedByOperator     = "trstctl-operator"
	ownerLabel            = "trstctl.com/owner"
	controlPlaneLabel     = "trstctl.com/control-plane"
	signerPodLabel        = "trstctl.com/signer"
	desiredHashAnnotation = "trstctl.com/desired-hash"
	// managedAnnotationsKey lists the user annotations the operator set, so a
	// key removed from the spec is removed from the object too.
	managedAnnotationsKey = "trstctl.com/managed-annotations"
	signerMTLSPort        = 9443
	controlPlanePort      = 8443
)

// ActionDelete means the operator removed an object it owns that the spec no
// longer asks for (an Ingress turned off, a signer no longer isolated).
const ActionDelete Action = "delete"

func (s ControlPlaneSpec) networkPolicyEnabled() bool {
	return s.NetworkPolicy.Enabled == nil || *s.NetworkPolicy.Enabled
}

func (s ControlPlaneSpec) servicePort() int {
	if s.Service.Port > 0 && s.Service.Port < 65536 {
		return s.Service.Port
	}
	return controlPlanePort
}

func (s ControlPlaneSpec) serviceType() string {
	switch strings.ToLower(strings.TrimSpace(s.Service.Type)) {
	case "nodeport":
		return "NodePort"
	case "loadbalancer":
		return "LoadBalancer"
	default:
		return "ClusterIP"
	}
}

func signerMTLSSecret(cr controlPlaneObject) string {
	return firstNonEmpty(strings.TrimSpace(cr.Spec.Signer.MTLS.SignerSecret), cr.Metadata.Name+"-signer-mtls")
}

func controlPlaneMTLSSecret(cr controlPlaneObject) string {
	return firstNonEmpty(strings.TrimSpace(cr.Spec.Signer.MTLS.ControlPlaneSecret), cr.Metadata.Name+"-cp-signer-mtls")
}

func (r *Reconciler) signerName(cr string) string { return cr + "-signer" }

// signerMTLSServerName is the name the control plane verifies on the signer's
// certificate: the spec's, or the signer Service's in-cluster DNS name.
func (r *Reconciler) signerMTLSServerName(namespace string, cr controlPlaneObject) string {
	return firstNonEmpty(strings.TrimSpace(cr.Spec.Signer.MTLS.ServerName),
		fmt.Sprintf("%s.%s.svc", r.signerName(cr.Metadata.Name), namespace))
}

// managedObject is one Kubernetes object the operator owns for a control plane.
type managedObject struct {
	kind, name                string
	collectionPath, itemPath  string
	object                    map[string]any
	userAnnotations           map[string]string
	namespace, controlPlaneCR string
}

func serviceCollectionPath(ns string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/services", ns)
}
func serviceItemPath(ns, name string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/services/%s", ns, name)
}
func networkPolicyCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", ns)
}
func networkPolicyItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/%s", ns, name)
}
func ingressCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/ingresses", ns)
}
func ingressItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/ingresses/%s", ns, name)
}

func ownedMetadata(namespace, name string, cr controlPlaneObject, component string) map[string]any {
	return map[string]any{
		"name":      name,
		"namespace": namespace,
		"labels": map[string]any{
			"app.kubernetes.io/name":      "trstctl",
			"app.kubernetes.io/component": component,
			managedByLabel:                managedByOperator,
			ownerLabel:                    cr.Metadata.Name,
		},
		"ownerReferences": ownerReferences(cr),
	}
}

// desiredHash fingerprints everything the operator sets on an object, so an
// unchanged spec costs one GET and nothing else.
func desiredHash(object map[string]any, userAnnotations map[string]string) string {
	h := fnv.New64a()
	_ = json.NewEncoder(h).Encode(struct {
		Metadata    any
		Spec        any
		Annotations map[string]string
	}{object["metadata"], object["spec"], userAnnotations})
	return fmt.Sprintf("%016x", h.Sum64())
}

// applyManaged converges one owned object: create it when missing; when the
// desired hash changed, merge-patch its labels, annotations, owner reference and
// spec, removing user annotations the spec no longer lists. An object of the
// same name the operator does not own is refused rather than taken over.
func (r *Reconciler) applyManaged(ctx context.Context, obj managedObject) (Action, error) {
	hash := desiredHash(obj.object, obj.userAnnotations)
	meta, _ := obj.object["metadata"].(map[string]any)
	annotations := map[string]any{desiredHashAnnotation: hash}
	keys := make([]string, 0, len(obj.userAnnotations))
	for key, value := range obj.userAnnotations {
		annotations[key] = value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	annotations[managedAnnotationsKey] = strings.Join(keys, ",")
	meta["annotations"] = annotations

	st, body, err := r.client.do(ctx, http.MethodGet, obj.itemPath, "", nil)
	if err != nil {
		return ActionNone, err
	}
	if st == http.StatusNotFound {
		st, body, err = r.client.do(ctx, http.MethodPost, obj.collectionPath, "", obj.object)
		if err != nil {
			return ActionCreate, err
		}
		if st == http.StatusConflict {
			return ActionCreate, nil // raced our own previous create; the next pass converges it
		}
		if st/100 != 2 {
			return ActionCreate, fmt.Errorf("operator: create %s %s/%s: status %d: %s", obj.kind, obj.namespace, obj.name, st, string(body))
		}
		return ActionCreate, nil
	}
	if st/100 != 2 {
		return ActionNone, fmt.Errorf("operator: get %s %s/%s: status %d: %s", obj.kind, obj.namespace, obj.name, st, string(body))
	}
	var live struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &live); err != nil {
		return ActionNone, fmt.Errorf("operator: decode %s %s/%s: %w", obj.kind, obj.namespace, obj.name, err)
	}
	if live.Metadata.Labels[managedByLabel] != managedByOperator || live.Metadata.Labels[ownerLabel] != obj.controlPlaneCR {
		return ActionNone, fmt.Errorf("operator: %s %s/%s exists and is not owned by control plane %s; rename or remove it",
			obj.kind, obj.namespace, obj.name, obj.controlPlaneCR)
	}
	if live.Metadata.Annotations[desiredHashAnnotation] == hash {
		return ActionNone, nil
	}
	for _, previous := range strings.Split(live.Metadata.Annotations[managedAnnotationsKey], ",") {
		if previous == "" {
			continue
		}
		if _, still := obj.userAnnotations[previous]; !still {
			annotations[previous] = nil
		}
	}
	patch := map[string]any{
		"metadata": map[string]any{
			"labels":          meta["labels"],
			"annotations":     annotations,
			"ownerReferences": meta["ownerReferences"],
		},
		"spec": obj.object["spec"],
	}
	st, body, err = r.client.do(ctx, http.MethodPatch, obj.itemPath, "application/merge-patch+json", patch)
	if err != nil {
		return ActionUpdate, err
	}
	if st/100 != 2 {
		return ActionUpdate, fmt.Errorf("operator: patch %s %s/%s: status %d: %s", obj.kind, obj.namespace, obj.name, st, string(body))
	}
	return ActionUpdate, nil
}

// deleteManaged removes an object this control plane owns that the spec no
// longer asks for. Anything else at that name is left alone.
func (r *Reconciler) deleteManaged(ctx context.Context, kind, itemPath, cr string) (bool, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, itemPath, "", nil)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		return false, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("operator: get %s %s: status %d: %s", kind, itemPath, st, string(body))
	}
	var live struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &live); err != nil {
		return false, fmt.Errorf("operator: decode %s %s: %w", kind, itemPath, err)
	}
	if live.Metadata.Labels[managedByLabel] != managedByOperator || live.Metadata.Labels[ownerLabel] != cr {
		return false, nil
	}
	st, body, err = r.client.do(ctx, http.MethodDelete, itemPath, "", nil)
	if err != nil {
		return false, err
	}
	if st/100 != 2 && st != http.StatusNotFound {
		return false, fmt.Errorf("operator: delete %s %s: status %d: %s", kind, itemPath, st, string(body))
	}
	return true, nil
}

// reconcileNetwork converges the control plane's network surface and, in the
// isolated topology, its signer, returning what it did to each surface.
func (r *Reconciler) reconcileNetwork(ctx context.Context, namespace string, cr controlPlaneObject) (map[string]Action, error) {
	actions := map[string]Action{}
	apply := func(surface string, obj managedObject) error {
		action, err := r.applyManaged(ctx, obj)
		actions[surface] = action
		return err
	}
	remove := func(surface, kind, itemPath string) error {
		removed, err := r.deleteManaged(ctx, kind, itemPath, cr.Metadata.Name)
		if removed {
			actions[surface] = ActionDelete
		}
		return err
	}
	name := r.deploymentName(cr.Metadata.Name)
	signer := r.signerName(cr.Metadata.Name)
	isolated := cr.Spec.desiredSignerMode() == "isolated"

	if err := apply("service", r.serviceObject(namespace, cr)); err != nil {
		return actions, err
	}
	if cr.Spec.networkPolicyEnabled() {
		if err := apply("networkPolicy", r.networkPolicyObject(namespace, cr)); err != nil {
			return actions, err
		}
	} else if err := remove("networkPolicy", "NetworkPolicy", networkPolicyItemPath(namespace, name)); err != nil {
		return actions, err
	}
	if cr.Spec.Ingress.Enabled {
		if err := apply("ingress", r.ingressObject(namespace, cr)); err != nil {
			return actions, err
		}
	} else if err := remove("ingress", "Ingress", ingressItemPath(namespace, name)); err != nil {
		return actions, err
	}

	if isolated {
		if err := apply("signer", r.signerDeploymentObject(namespace, cr)); err != nil {
			return actions, err
		}
		if err := apply("signerService", r.signerServiceObject(namespace, cr)); err != nil {
			return actions, err
		}
		if cr.Spec.networkPolicyEnabled() {
			if err := apply("signerNetworkPolicy", r.signerNetworkPolicyObject(namespace, cr)); err != nil {
				return actions, err
			}
		} else if err := remove("signerNetworkPolicy", "NetworkPolicy", networkPolicyItemPath(namespace, signer)); err != nil {
			return actions, err
		}
		return actions, nil
	}
	for _, owned := range []struct{ surface, kind, path string }{
		{"signer", "Deployment", deploymentItemPath(namespace, signer)},
		{"signerService", "Service", serviceItemPath(namespace, signer)},
		{"signerNetworkPolicy", "NetworkPolicy", networkPolicyItemPath(namespace, signer)},
		// A pair the operator generated; Secrets someone else provided stay.
		{"signerMTLS", "Secret", secretItemPath(namespace, signerMTLSSecret(cr))},
		{"signerMTLS", "Secret", secretItemPath(namespace, controlPlaneMTLSSecret(cr))},
	} {
		if err := remove(owned.surface, owned.kind, owned.path); err != nil {
			return actions, err
		}
	}
	return actions, nil
}

func (r *Reconciler) serviceObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.deploymentName(cr.Metadata.Name)
	return managedObject{
		kind: "Service", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: serviceCollectionPath(namespace), itemPath: serviceItemPath(namespace, name),
		userAnnotations: cr.Spec.Service.Annotations,
		object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata":   ownedMetadata(namespace, name, cr, "control-plane"),
			"spec": map[string]any{
				"type":     cr.Spec.serviceType(),
				"selector": map[string]any{controlPlaneLabel: cr.Metadata.Name},
				"ports": []map[string]any{{
					"name": "https", "port": cr.Spec.servicePort(), "targetPort": "https", "protocol": "TCP",
				}},
			},
		},
	}
}

// networkPolicyObject is default-deny in both directions, then admits the API
// port from the scoped peers the spec names (never every pod in the
// namespace unless allowSameNamespace says so), and lets the control plane
// reach DNS, its datastores and, when isolated, only its signer's mTLS port.
func (r *Reconciler) networkPolicyObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.deploymentName(cr.Metadata.Name)
	spec := cr.Spec.NetworkPolicy
	var peers []map[string]any
	if !spec.IngressController.Disabled {
		namespaceLabels := stringMap(spec.IngressController.NamespaceLabels, map[string]string{"kubernetes.io/metadata.name": "ingress-nginx"})
		podLabels := stringMap(spec.IngressController.PodLabels, map[string]string{"app.kubernetes.io/name": "ingress-nginx"})
		peers = append(peers, map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": namespaceLabels},
			"podSelector":       map[string]any{"matchLabels": podLabels},
		})
	}
	if spec.AllowSameNamespace {
		peers = append(peers, map[string]any{"podSelector": map[string]any{}})
	}
	for _, allowed := range spec.AllowedNamespaces {
		if allowed = strings.TrimSpace(allowed); allowed != "" {
			peers = append(peers, map[string]any{"namespaceSelector": map[string]any{
				"matchLabels": map[string]any{"kubernetes.io/metadata.name": allowed},
			}})
		}
	}
	ingress := []map[string]any{}
	if len(peers) > 0 {
		ingress = append(ingress, map[string]any{
			"from":  peers,
			"ports": []map[string]any{{"protocol": "TCP", "port": controlPlanePort}},
		})
	}
	postgresPort, natsPort := spec.PostgresPort, spec.NATSPort
	if postgresPort <= 0 || postgresPort > 65535 {
		postgresPort = 5432
	}
	if natsPort <= 0 || natsPort > 65535 {
		natsPort = 4222
	}
	datastores := map[string]any{"ports": []map[string]any{
		{"protocol": "TCP", "port": postgresPort}, {"protocol": "TCP", "port": natsPort},
	}}
	if len(spec.EgressCIDRs) > 0 {
		to := make([]map[string]any, 0, len(spec.EgressCIDRs))
		for _, cidr := range spec.EgressCIDRs {
			to = append(to, map[string]any{"ipBlock": map[string]any{"cidr": cidr}})
		}
		datastores["to"] = to
	}
	egress := []map[string]any{
		{
			"to":    []map[string]any{{"namespaceSelector": map[string]any{}}},
			"ports": []map[string]any{{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}},
		},
		datastores,
	}
	if cr.Spec.desiredSignerMode() == "isolated" {
		egress = append(egress, map[string]any{
			"to":    []map[string]any{{"podSelector": map[string]any{"matchLabels": map[string]any{signerPodLabel: cr.Metadata.Name}}}},
			"ports": []map[string]any{{"protocol": "TCP", "port": signerMTLSPort}},
		})
	}
	return managedObject{
		kind: "NetworkPolicy", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: networkPolicyCollectionPath(namespace), itemPath: networkPolicyItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata":   ownedMetadata(namespace, name, cr, "control-plane"),
			"spec": map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{controlPlaneLabel: cr.Metadata.Name}},
				"policyTypes": []string{"Ingress", "Egress"},
				"ingress":     ingress,
				"egress":      egress,
			},
		},
	}
}

func (r *Reconciler) ingressObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.deploymentName(cr.Metadata.Name)
	spec := cr.Spec.Ingress
	rule := map[string]any{"http": map[string]any{"paths": []map[string]any{{
		"path": "/", "pathType": "Prefix",
		"backend": map[string]any{"service": map[string]any{"name": name, "port": map[string]any{"name": "https"}}},
	}}}}
	if host := strings.TrimSpace(spec.Host); host != "" {
		rule["host"] = host
	}
	ingressSpec := map[string]any{"rules": []map[string]any{rule}, "ingressClassName": nil, "tls": nil}
	if className := strings.TrimSpace(spec.ClassName); className != "" {
		ingressSpec["ingressClassName"] = className
	}
	if secret := strings.TrimSpace(spec.TLSSecret); secret != "" {
		tls := map[string]any{"secretName": secret}
		if host := strings.TrimSpace(spec.Host); host != "" {
			tls["hosts"] = []string{host}
		}
		ingressSpec["tls"] = []map[string]any{tls}
	}
	return managedObject{
		kind: "Ingress", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: ingressCollectionPath(namespace), itemPath: ingressItemPath(namespace, name),
		userAnnotations: spec.Annotations,
		object: map[string]any{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "Ingress",
			"metadata":   ownedMetadata(namespace, name, cr, "control-plane"),
			"spec":       ingressSpec,
		},
	}
}

// signerDeploymentObject runs the signer as its own pod (AN-4): no HTTP server,
// no SQL, only the mTLS gRPC listener, pinning the control plane's key.
func (r *Reconciler) signerDeploymentObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.signerName(cr.Metadata.Name)
	podLabels := map[string]any{
		"app.kubernetes.io/name": "trstctl", "app.kubernetes.io/component": "signer",
		managedByLabel: managedByOperator, signerPodLabel: cr.Metadata.Name,
	}
	container := map[string]any{
		"name":    "signer",
		"image":   cr.Spec.desiredImage(),
		"command": []string{"/usr/local/bin/trstctl-signer"},
		"args": []string{
			fmt.Sprintf("--mtls-listen=:%d", signerMTLSPort),
			"--mtls-cert=/etc/trstctl/signer-mtls/tls.crt",
			"--mtls-key=/etc/trstctl/signer-mtls/tls.key",
			"--mtls-peer-ca=/etc/trstctl/signer-mtls/peer-ca.pem",
			"--mtls-peer-pin=$(SIGNER_MTLS_PEER_PIN)",
			"--keystore=/data/signer/keys",
			"--kek=/etc/trstctl/kek/" + signerKekSecretKey(cr),
			"--auth-secret=/etc/trstctl/signer-auth/" + signerAuthSecretKey(cr),
		},
		"env":   []map[string]any{envSecret("SIGNER_MTLS_PEER_PIN", signerMTLSSecret(cr), "peer-pin")},
		"ports": []map[string]any{{"containerPort": signerMTLSPort, "name": "grpc-mtls"}},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"runAsNonRoot":             true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
		"volumeMounts": []map[string]any{
			{"name": "signer-mtls", "mountPath": "/etc/trstctl/signer-mtls", "readOnly": true},
			{"name": "signer-keys", "mountPath": "/data/signer"},
			{"name": "kek", "mountPath": "/etc/trstctl/kek", "readOnly": true},
			{"name": "signer-auth", "mountPath": "/etc/trstctl/signer-auth", "readOnly": true},
		},
	}
	return managedObject{
		kind: "Deployment", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: deploymentCollectionPath(namespace), itemPath: deploymentItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": deploymentsGroup,
			"kind":       "Deployment",
			"metadata":   ownedMetadata(namespace, name, cr, "signer"),
			"spec": map[string]any{
				"replicas": 1,
				"selector": map[string]any{"matchLabels": map[string]any{signerPodLabel: cr.Metadata.Name}},
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": podLabels,
						// A new mTLS pair rolls the signer with the control plane.
						"annotations": map[string]any{signerMTLSFingerprintAnnotation: cr.Spec.signerMTLSFingerprint},
					},
					"spec": map[string]any{
						"automountServiceAccountToken": false,
						"securityContext":              podSecurityContext(),
						"containers":                   []map[string]any{container},
						"volumes": []map[string]any{
							{"name": "signer-mtls", "secret": map[string]any{"secretName": signerMTLSSecret(cr), "defaultMode": 288}},
							r.signerKeysVolume(cr),
							{"name": "kek", "secret": map[string]any{"secretName": signerKekSecret(cr), "defaultMode": 288}},
							{"name": "signer-auth", "secret": map[string]any{"secretName": signerAuthSecret(cr), "defaultMode": 288}},
						},
					},
				},
			},
		},
	}
}

func (r *Reconciler) signerServiceObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.signerName(cr.Metadata.Name)
	return managedObject{
		kind: "Service", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: serviceCollectionPath(namespace), itemPath: serviceItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata":   ownedMetadata(namespace, name, cr, "signer"),
			"spec": map[string]any{
				"type":     "ClusterIP",
				"selector": map[string]any{signerPodLabel: cr.Metadata.Name},
				"ports": []map[string]any{{
					"name": "grpc-mtls", "port": signerMTLSPort, "targetPort": "grpc-mtls", "protocol": "TCP",
				}},
			},
		},
	}
}

// signerNetworkPolicyObject turns the signer's process isolation into network
// isolation: only this control plane's pods may reach its mTLS port, and it may
// reach only DNS and HTTPS (an external KMS).
func (r *Reconciler) signerNetworkPolicyObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.signerName(cr.Metadata.Name)
	return managedObject{
		kind: "NetworkPolicy", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: networkPolicyCollectionPath(namespace), itemPath: networkPolicyItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata":   ownedMetadata(namespace, name, cr, "signer"),
			"spec": map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{signerPodLabel: cr.Metadata.Name}},
				"policyTypes": []string{"Ingress", "Egress"},
				"ingress": []map[string]any{{
					"from":  []map[string]any{{"podSelector": map[string]any{"matchLabels": map[string]any{controlPlaneLabel: cr.Metadata.Name}}}},
					"ports": []map[string]any{{"protocol": "TCP", "port": signerMTLSPort}},
				}},
				"egress": []map[string]any{{
					"ports": []map[string]any{{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}, {"protocol": "TCP", "port": 443}},
				}},
			},
		},
	}
}

func stringMap(values, fallback map[string]string) map[string]any {
	source := values
	if len(source) == 0 {
		source = fallback
	}
	out := make(map[string]any, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
