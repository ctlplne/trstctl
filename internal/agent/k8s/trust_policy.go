// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/kubetrust"
)

// TrustDistributionPolicy is the cluster operator's local admission policy.
// Its zero value allows no remote execution or namespaced distribution.
type TrustDistributionPolicy struct {
	allowRemote bool
	namespaces  map[string]struct{}
}

func ParseTrustDistributionPolicy(allowRemote bool, names string) (TrustDistributionPolicy, error) {
	p := TrustDistributionPolicy{allowRemote: allowRemote}
	if names == "" {
		return p, nil
	}
	p.namespaces = make(map[string]struct{})
	for namespace := range strings.SplitSeq(names, ",") {
		if !kubetrust.ValidTrustNamespace(namespace) {
			return TrustDistributionPolicy{}, fmt.Errorf("invalid --k8s-trust-namespaces entry %q", namespace)
		}
		if _, exists := p.namespaces[namespace]; exists {
			return TrustDistributionPolicy{}, fmt.Errorf("duplicate --k8s-trust-namespaces entry %q", namespace)
		}
		p.namespaces[namespace] = struct{}{}
	}
	return p, nil
}

func (p TrustDistributionPolicy) admitNamespaces(namespaces []string) error {
	for _, namespace := range namespaces {
		if _, allowed := p.namespaces[namespace]; !allowed {
			return fmt.Errorf("namespace %q is outside the local --k8s-trust-namespaces allowlist", namespace)
		}
	}
	return nil
}

const trustRolloutHashAnnotation = "trstctl.com/rollout-sha256"

type trustOrigin struct {
	rolloutID   string
	hash        string
	hashPresent bool
}

// trustBundleOrigin treats the presence of either marker as remote origin.
// An invalid remote identity is never eligible for local processing or status.
func trustBundleOrigin(meta map[string]any) (trustOrigin, error) {
	rawAnnotations, annotated := meta["annotations"]
	annotations, ok := rawAnnotations.(map[string]any)
	if annotated && !ok {
		return trustOrigin{}, errors.New("invalid TrustBundle metadata.annotations")
	}
	rawID, hasID := annotations[trustRolloutAnnotation]
	rawHash, hasHash := annotations[trustRolloutHashAnnotation]
	if !hasID && !hasHash {
		return trustOrigin{}, nil
	}
	id, _ := rawID.(string)
	labels, _ := meta["labels"].(map[string]any)
	if labels["app.kubernetes.io/managed-by"] != "trstctl-agent" || !kubetrust.ValidRolloutID(id) {
		return trustOrigin{}, errors.New("remote TrustBundle has no valid agent rollout identity")
	}
	hash, _ := rawHash.(string)
	return trustOrigin{rolloutID: id, hash: hash, hashPresent: hasHash}, nil
}

func trustBundleIdentity(obj map[string]any) (string, trustOrigin, error) {
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if !kubetrust.ValidBundleName(name) {
		return "", trustOrigin{}, errors.New("invalid or reserved TrustBundle name")
	}
	origin, err := trustBundleOrigin(meta)
	return name, origin, err
}

type admittedTrustBundle struct {
	name               string
	pem                string
	hash               string
	configMap          string
	key                string
	namespaces         []string
	secret             *trustSecretTarget
	clusterTrustBundle string
}

func parseStoredTrustBundle(obj map[string]any, allowRemote, requireTargets bool) (admittedTrustBundle, error) {
	var out admittedTrustBundle
	name, origin, err := trustBundleIdentity(obj)
	if err != nil {
		return out, err
	}
	remote := origin.rolloutID != ""
	if remote && !allowRemote {
		return out, errors.New("remote TrustBundle requires local --k8s-trust-rollouts opt-in")
	}
	spec, _ := obj["spec"].(map[string]any)
	bundle, hash, err := trustBundlePEM(spec)
	if err != nil {
		return out, err
	}
	if remote && (!kubetrust.ValidBundleHash(origin.hash) || hash != origin.hash || spec["caBundlePEM"] != bundle) {
		return out, errors.New("remote TrustBundle does not match its admitted canonical bundle hash")
	}
	out.name, out.pem, out.hash = name, bundle, hash
	rawTarget, present := spec["target"]
	if !present && !remote && !requireTargets {
		return out, nil
	}
	target, ok := rawTarget.(map[string]any)
	if !ok || target == nil {
		return out, errors.New("spec.target must be a Kubernetes trust target object")
	}
	if remote {
		_, hasSecret := target["secret"]
		_, hasClusterBundle := target["clusterTrustBundle"]
		if hasSecret || hasClusterBundle {
			return out, errors.New("remote TrustBundle can only distribute ConfigMaps")
		}
	}
	out.configMap = trustTargetString(target, "configMapName", name)
	out.key = trustTargetString(target, "key", "ca-bundle.pem")
	rawNamespaces, ok := target["namespaces"].([]any)
	if !ok || len(rawNamespaces) > kubetrust.MaxNamespaces {
		return out, errors.New("spec.target.namespaces must be an array of at most 100 namespace names")
	}
	out.namespaces = make([]string, len(rawNamespaces))
	for i, raw := range rawNamespaces {
		ns, ok := raw.(string)
		if !ok {
			return out, errors.New("spec.target.namespaces entries must be strings")
		}
		out.namespaces[i] = ns
	}
	if err := kubetrust.ValidateTargets(out.name, out.configMap, out.key, out.namespaces); err != nil {
		return out, err
	}
	out.secret, err = parseTrustSecretTarget(target)
	if err != nil {
		return out, err
	}
	out.clusterTrustBundle, err = parseClusterTrustBundleTarget(target)
	return out, err
}

func trustTargetString(obj map[string]any, key, fallback string) string {
	raw, present := obj[key]
	if !present {
		return fallback
	}
	value, _ := raw.(string)
	return value
}
