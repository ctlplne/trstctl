// SPDX-License-Identifier: BUSL-1.1

package pluginhost_test

import "trstctl.com/trstctl/internal/pluginhost/wasmgen"

// The sandbox tests need guest modules that carry a real path in their own linear
// memory, so they use the shared builder rather than hand-encoded bytes. See
// internal/pluginhost/wasmgen for why hand-encoded fixtures could not exercise
// this ABI at all.

func guestModule(fn string, nParams int, args []int32, data []byte) []byte {
	return wasmgen.Module(fn, nParams, data, []wasmgen.Export{{Name: "run", Args: args}})
}

func writeGuest(path, content string) []byte { return wasmgen.WriteGuest(path, content) }
func readGuest(path string) []byte           { return wasmgen.ReadGuest(path) }
func dialGuest(addr string) []byte           { return wasmgen.DialGuest(addr) }
