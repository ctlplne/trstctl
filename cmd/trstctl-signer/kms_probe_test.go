// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// probeWrapper is a key wrapper whose wrap or unwrap can fail or lie.
type probeWrapper struct {
	wrapErr, unwrapErr error
	lie                bool
}

func (p probeWrapper) WrapDEK(dek []byte) ([]byte, error) {
	if p.wrapErr != nil {
		return nil, p.wrapErr
	}
	return append([]byte("w:"), dek...), nil
}

func (p probeWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	if p.unwrapErr != nil {
		return nil, p.unwrapErr
	}
	out := bytes.Clone(wrapped[2:])
	if p.lie {
		out[0] ^= 0xff
	}
	return out, nil
}

// A200: before the signer serves, a wrap and an unwrap through the external
// adapter must round-trip; otherwise startup stops with the adapter's reason
// (here a disabled KMS key), which the key store's generic seal error hides.
func TestExternalKMSCustodyProbeStopsStartupWithTheAdaptersReason(t *testing.T) {
	if err := probeKeystoreWrapper(probeWrapper{}); err != nil {
		t.Fatalf("a round-tripping adapter = %v", err)
	}
	disabled := errors.New("kmswrap: external KMS wrap failed: exit status 1: trstctl-kms-wrap: wrap under awskms: DisabledException")
	for name, w := range map[string]probeWrapper{
		"wrap fails":   {wrapErr: disabled},
		"unwrap fails": {unwrapErr: disabled},
	} {
		if err := probeKeystoreWrapper(w); err == nil || !strings.Contains(err.Error(), "DisabledException") {
			t.Fatalf("%s: probe = %v, want the adapter's reason", name, err)
		}
	}
	if err := probeKeystoreWrapper(probeWrapper{lie: true}); err == nil || !strings.Contains(err.Error(), "different value") {
		t.Fatalf("an adapter returning another value: probe = %v", err)
	}
}
