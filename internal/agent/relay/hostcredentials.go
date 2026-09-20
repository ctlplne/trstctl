// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Host-generated certificate keys are never redeemed. Management credentials
// such as a Java store password are borrowed for one reviewed job attempt.
func redeemHostManagement(ctx context.Context, ch Channel, job Job, refs []string) (Material, func(), error) {
	if len(refs) == 0 {
		return Material{}, func() {}, nil
	}
	expected := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "secret://") || strings.TrimSpace(strings.TrimPrefix(ref, "secret://")) == "" || expected[ref] {
			return nil, nil, errors.New("host job must name distinct management credential references")
		}
		expected[ref] = true
	}
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	// Wipe every wire buffer even on partial responses, refusal or adoption
	// failure. Only AdoptMaterial's locked buffers survive this call.
	defer func() {
		for _, value := range items {
			secret.Wipe(value)
		}
	}()
	if err != nil {
		return nil, nil, err
	}
	if len(items) != len(expected) {
		return nil, nil, errors.New("host management credential response has an unexpected set of names")
	}
	for ref, value := range items {
		if !expected[ref] || len(value) == 0 {
			return nil, nil, errors.New("host management credential response is incomplete or unrelated")
		}
	}
	return AdoptMaterial(items)
}
