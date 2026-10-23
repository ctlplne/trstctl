// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/keyposture"
)

// Part 4: a relay's TLS finding names the served issuers by hash and the
// weak-key checks by code; the control plane matches the hashes against its
// own list, words the reasons, and raises the risk.
func TestRelayKeyObservationIsRatedByTheControlPlane(t *testing.T) {
	meta := map[string]any{}
	risk := applyRelayKeyObservation(meta, segmentscan.Finding{
		Fingerprint:     strings.Repeat("cd", 32),
		SPKISHA256:      strings.Repeat("ab", 32),
		ChainSPKISHA256: []string{"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8"},
		ChainCertSHA256: []string{strings.Repeat("ef", 32)},
		WeakKeyChecks:   []string{"key_size"},
	}, 30)
	if meta[keyposture.MetaDistrustEntry] != "EM OV TLS CA - G3C" || meta[keyposture.MetaDistrustHow] != "chain" || meta[keyposture.MetaKeyStrength] != "weak" ||
		!strings.Contains(meta[keyposture.MetaWeakKeyReason].(string), "size floor") || risk != keyposture.RiskDistrusted {
		t.Fatalf("metadata %v risk %d", meta, risk)
	}
	clean := map[string]any{}
	if risk := applyRelayKeyObservation(clean, segmentscan.Finding{Fingerprint: strings.Repeat("cd", 32)}, 30); risk != 30 || len(clean) != 0 {
		t.Fatalf("an unrated finding changed: %v %d", clean, risk)
	}
}
