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

func boundTargetDigest(provider string, parts ...string) string {
	var b strings.Builder
	for _, part := range append([]string{provider}, parts...) {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return crypto.SHA256Hex([]byte(b.String()))
}
