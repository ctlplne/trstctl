// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Used only when the Kubernetes request supplies no lifetime. The served CA
// profile still enforces its own maximum and issuer-expiry clamp.
const defaultCertificateTTL = 24 * time.Hour

func certificateRequestTTL(spec map[string]any) (time.Duration, error) {
	raw, _ := spec["duration"].(string)
	if strings.TrimSpace(raw) == "" {
		return defaultCertificateTTL, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl < time.Second || ttl%time.Second != 0 {
		return 0, fmt.Errorf("k8s: CertificateRequest.spec.duration must be positive whole seconds")
	}
	return ttl, nil
}

func kubernetesCSRRequestedTTL(spec map[string]any) (time.Duration, error) {
	raw, exists := spec["expirationSeconds"]
	if !exists || raw == nil {
		return defaultCertificateTTL, nil
	}
	seconds, ok := raw.(float64)
	if !ok || seconds < 1 || seconds != math.Trunc(seconds) || seconds > float64(math.MaxInt64/int64(time.Second)) {
		return 0, fmt.Errorf("k8s: CertificateSigningRequest.spec.expirationSeconds must be a positive whole number of seconds")
	}
	return time.Duration(int64(seconds)) * time.Second, nil
}
