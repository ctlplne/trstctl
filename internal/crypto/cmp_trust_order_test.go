// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestCMPRejectsUntrustedProtectionBeforeSignatureWork(t *testing.T) {
	request, _ := buildCMPStrictFixtures(t)
	var message cmpStrictMessage
	if _, err := asn1.Unmarshal(request, &message); err != nil {
		t.Fatal(err)
	}
	message.Protection.Bytes[0] ^= 1
	request, err := asn1.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherKey.Destroy)
	otherAnchor, err := crypto.SelfSignedCACert(otherKey, "unrelated CMP anchor", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := crypto.NewCMPTrustAnchors([][]byte{otherAnchor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.ParseCMPRequestWithTrust(request, nil, anchors, crypto.CMPAllowRAEnrollment); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("untrusted protection reached signature verification: %v", err)
	}
}
