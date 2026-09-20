// SPDX-License-Identifier: BUSL-1.1

package letsencrypt

import (
	"errors"
	"strings"
	"testing"
)

func TestACMEFailureClassIsUsefulWithoutRetainingUpstreamText(t *testing.T) {
	const attackerControlled = "credential-that-must-not-be-retained"
	err := dvFailureOrGeneric(errors.New("acmekey: finalize: " + attackerControlled))
	if strings.Contains(err.Error(), attackerControlled) {
		t.Fatalf("safe error retained upstream text: %q", err)
	}
	classified, ok := err.(interface{ SafeDeliveryClass() string })
	if !ok {
		t.Fatalf("safe error has no delivery class: %T", err)
	}
	if got := classified.SafeDeliveryClass(); got != "external_ca_finalize_failed" {
		t.Fatalf("safe class = %q, want external_ca_finalize_failed", got)
	}
}
