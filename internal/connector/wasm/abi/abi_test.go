// SPDX-License-Identifier: BUSL-1.1

package abi_test

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/wasm/abi"
)

// An error keeps its text and its sentinels across the boundary; a name the
// receiving side does not know is ignored, never trusted.
func TestErrorsCrossWithTheirSentinels(t *testing.T) {
	original := fmt.Errorf("f5: rollback: %w", connector.ErrNoPredecessorInstalled)
	crossed := abi.Encode(original).Decode()
	if crossed.Error() != original.Error() || !errors.Is(crossed, connector.ErrNoPredecessorInstalled) || errors.Is(crossed, connector.ErrDenied) {
		t.Fatalf("crossed error = %v", crossed)
	}
	missing := abi.Encode(fmt.Errorf("read current certificate: %w", fs.ErrNotExist)).Decode()
	if !errors.Is(missing, fs.ErrNotExist) {
		t.Fatalf("a missing file lost its identity: %v", missing)
	}
	forged := (&abi.Error{Message: "boom", Is: []string{"admin_override", "denied"}}).Decode()
	if !errors.Is(forged, connector.ErrDenied) || forged.Error() != "boom" {
		t.Fatalf("known sentinel names must still decode: %v", forged)
	}
	if abi.Encode(nil) != nil || (*abi.Error)(nil).Decode() != nil {
		t.Fatal("nil must stay nil across the boundary")
	}
}
