// SPDX-License-Identifier: BUSL-1.1

// Package kubetrust shares Kubernetes trust rollout admission between the
// control plane and the cluster agent without linking either one's runtime.
package kubetrust

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const MaxNamespaces = 100

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dataKey  = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
	sha256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func ValidNamespace(name string) bool {
	return len(name) <= 63 && dnsLabel.MatchString(name)
}

func ValidTrustNamespace(name string) bool {
	return ValidNamespace(name) && !strings.HasPrefix(name, "kube-")
}

func ValidObjectName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for part := range strings.SplitSeq(name, ".") {
		if !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func ValidTargetName(name string) bool {
	return name != "trstctl-ca-bundle" && name != "trstctl-secrets-csi" && ValidObjectName(name)
}

// ValidBundleName also enforces the size bound of the target ownership label.
func ValidBundleName(name string) bool {
	return len(name) <= 63 && ValidTargetName(name)
}

func ValidDataKey(key string) bool {
	return dataKey.MatchString(key) && key != "." && !strings.HasPrefix(key, "..")
}

func ValidRolloutID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil && id == u.String()
}

func ValidBundleHash(hash string) bool {
	return sha256.MatchString(hash)
}

// ValidateTargets checks all ConfigMap destinations of a rollout or a local
// TrustBundle before the agent applies its separate namespace allowlist.
func ValidateTargets(bundleName, configMapName, key string, namespaces []string) error {
	if !ValidBundleName(bundleName) {
		return errors.New("TrustBundle name must be an unreserved Kubernetes name of at most 63 characters")
	}
	if !ValidTargetName(configMapName) {
		return errors.New("ConfigMap name must be an unreserved Kubernetes object name")
	}
	if !ValidDataKey(key) {
		return errors.New("ConfigMap key must be a valid Kubernetes data key")
	}
	if len(namespaces) == 0 || len(namespaces) > MaxNamespaces {
		return fmt.Errorf("targets must name 1 to %d namespaces", MaxNamespaces)
	}
	seen := make(map[string]struct{}, len(namespaces))
	for _, namespace := range namespaces {
		if !ValidTrustNamespace(namespace) {
			return fmt.Errorf("namespace %q is not an eligible Kubernetes trust namespace", namespace)
		}
		if _, exists := seen[namespace]; exists {
			return fmt.Errorf("namespace %q is listed more than once", namespace)
		}
		seen[namespace] = struct{}{}
	}
	return nil
}

// NormalizeBundle returns the canonical public certificate bytes and their hash.
func NormalizeBundle(raw string) (string, string, error) {
	pem, err := certinfo.NormalizePublicCertificatePEM([]byte(raw))
	if err != nil {
		return "", "", err
	}
	return string(pem), crypto.SHA256Hex(pem), nil
}
