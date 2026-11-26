// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// A bound principal reference carries the target and name that created a
// lease. The target digest does not contain an administrator credential. A
// provider must compare it before any revoke call, because a missing user on
// a different target says nothing about the old user's standing.
func boundPrincipalRef(provider, prefix, name string, targetParts ...string) string {
	return "v1:" + boundTargetDigest(provider, targetParts...) + ":" +
		sanitizeFragment(prefix, defaultDynsecretPrefix) + ":" + name
}

func principalFromBoundRef(ref, provider string, targetParts ...string) (string, error) {
	parts := strings.SplitN(ref, ":", 4)
	if len(parts) != 4 || parts[0] != "v1" {
		return "", errors.New("dynsecret: legacy target-unbound lease reference needs manual revocation at its original target")
	}
	if parts[1] != boundTargetDigest(provider, targetParts...) {
		return "", fmt.Errorf("dynsecret: refusing to revoke a %s lease on a different target", provider)
	}
	if parts[2] == "" || !issuedPrincipalName(parts[2], parts[3]) {
		return "", fmt.Errorf("dynsecret: %s lease reference has no issued principal", provider)
	}
	return parts[3], nil
}

// Opaque vendor key IDs have no issued-principal shape. Keep their original
// reference intact after the target and issuing prefix so the provider can
// still apply its own binding and ID checks before deletion.
func boundOpaqueRef(provider, prefix, ref string, targetParts ...string) string {
	return "v2:" + boundTargetDigest(provider, targetParts...) + ":" +
		sanitizeFragment(prefix, defaultDynsecretPrefix) + ":" + ref
}

// v3 binds the immutable issued owner/key as well as the management target.
// A v2 reference binds only its target: changing its raw owner or key while
// keeping the target digest would otherwise redirect a revoke to another key.
func boundIssuedOpaqueRef(provider, prefix, ref string, targetParts ...string) string {
	prefix = sanitizeFragment(prefix, defaultDynsecretPrefix)
	return "v3:" + issuedOpaqueDigest(provider, prefix, ref, targetParts...) + ":" + prefix + ":" + ref
}

func issuedOpaqueDigest(provider, prefix, ref string, targetParts ...string) string {
	parts := make([]string, 0, len(targetParts)+3)
	parts = append(parts, "issued-opaque-v3")
	parts = append(parts, targetParts...)
	parts = append(parts, prefix, ref)
	return boundTargetDigest(provider, parts...)
}

// issuedOpaqueFromBoundRef distinguishes a v3 reference whose original raw
// owner/key is bound from a legacy v2 target-only reference. Callers may use
// the v3 owner after a role rebind; v2 still needs the old role safeguard.
func issuedOpaqueFromBoundRef(ref, provider string, targetParts ...string) (raw, prefix string, issued bool, err error) {
	if !strings.HasPrefix(ref, "v3:") {
		raw, prefix, err = opaqueFromBoundRef(ref, provider, targetParts...)
		return raw, prefix, false, err
	}
	digest, prefix, raw, err := opaqueBoundRefShapeVersion(ref, "v3")
	if err != nil {
		return "", "", false, err
	}
	if digest != issuedOpaqueDigest(provider, prefix, raw, targetParts...) {
		return "", "", false, fmt.Errorf("dynsecret: refusing to revoke a %s lease with changed target or issued key", provider)
	}
	return raw, prefix, true, nil
}

func opaqueFromBoundRef(ref, provider string, targetParts ...string) (raw, prefix string, err error) {
	digest, prefix, raw, err := opaqueBoundRefShape(ref)
	if err != nil {
		return "", "", err
	}
	if digest != boundTargetDigest(provider, targetParts...) {
		return "", "", fmt.Errorf("dynsecret: refusing to revoke a %s lease on a different target", provider)
	}
	return raw, prefix, nil
}

func opaqueBoundRefShape(ref string) (digest, prefix, raw string, err error) {
	return opaqueBoundRefShapeVersion(ref, "v2")
}

func opaqueBoundRefShapeVersion(ref, version string) (digest, prefix, raw string, err error) {
	parts := strings.SplitN(ref, ":", 4)
	if len(parts) != 4 || parts[0] != version {
		return "", "", "", errors.New("dynsecret: legacy target-unbound lease reference needs manual revocation at its original target")
	}
	if len(parts[1]) != 64 || !lowerHexID([]byte(parts[1]), 64) ||
		parts[2] == "" || sanitizeFragment(parts[2], defaultDynsecretPrefix) != parts[2] || parts[3] == "" {
		return "", "", "", errors.New("dynsecret: target-bound lease reference is malformed")
	}
	return parts[1], parts[2], parts[3], nil
}

func boundTargetDigest(provider string, parts ...string) string {
	var b strings.Builder
	for _, part := range append([]string{provider}, parts...) {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return crypto.SHA256Hex([]byte(b.String()))
}
