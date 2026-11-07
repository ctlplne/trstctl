// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func wipeRedeemedItems(items []transport.RedeemedSecret) {
	for _, item := range items {
		secret.Wipe(item.Value)
	}
}

// redeemedItemMap transfers each unique wire buffer exactly once. Refusal
// wipes the entire reply, including entries not reached before the duplicate.
func redeemedItemMap(items []transport.RedeemedSecret) (map[string][]byte, error) {
	result := make(map[string][]byte, len(items))
	for _, item := range items {
		if _, exists := result[item.Name]; exists || item.Name == "" {
			wipeRedeemedItems(items)
			return nil, errors.New("agent: ambiguous redeemed credential envelope")
		}
		result[item.Name] = item.Value
	}
	return result, nil
}
