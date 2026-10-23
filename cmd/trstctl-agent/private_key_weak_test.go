// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
)

// Part 4: a private key the inspector rates weak reaches the inventory rated
// weak with its reason and a higher risk; a sound key does not.
func TestPrivateKeyInventoryFindingsRateWeakKeys(t *testing.T) {
	got := privateKeyInventoryFindings([]agentdiscovery.PrivateKeyFound{
		{Source: agentdiscovery.SourcePrivateKey, Location: "/etc/ssl/private/legacy.key", Format: "PKCS8", Algorithm: "RSA-1024", Fingerprint: "aa", WeakReasons: []string{"RSA-1024 is below the 2048-bit minimum"}},
		{Source: agentdiscovery.SourcePrivateKey, Location: "/etc/ssl/private/site.key", Format: "PKCS8", Algorithm: "ECDSA-P256", Fingerprint: "bb"},
	})
	if len(got) != 2 {
		t.Fatalf("findings = %+v", got)
	}
	weak, sound := got[0], got[1]
	if weak.RiskScore != 95 || weak.Metadata["key_strength"] != "weak" || weak.Metadata["key_weak_reason"] != "RSA-1024 is below the 2048-bit minimum" || weak.Metadata["key_algorithm"] != "RSA-1024" {
		t.Fatalf("weak key finding = %+v", weak)
	}
	if sound.RiskScore != 85 || sound.Metadata["key_strength"] != "" || sound.Metadata["key_weak_reason"] != "" {
		t.Fatalf("sound key finding = %+v", sound)
	}
}
