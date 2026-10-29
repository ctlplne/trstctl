// SPDX-License-Identifier: BUSL-1.1
package pluginhost_test

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// This guest writes a canary from the WASM start section, before Invoke is
// called. A trusted positive control proves the side effect actually works.
func startWriteGuest(path string) []byte {
	length := func(value []byte) uint32 {
		n := len(value)
		if n < 0 || int64(n) > math.MaxUint32 {
			panic("test fixture exceeds WASM section limit")
		}
		return uint32(n)
	}
	section := func(id byte, payload []byte) []byte {
		out := append([]byte{id}, wasmgen.ULEB(length(payload))...)
		return append(out, payload...)
	}
	data := []byte(path + "started")
	body := []byte{0} // no locals
	for _, arg := range wasmgen.WriteArgs(path, "started") {
		body = append(body, 0x41)
		body = append(body, wasmgen.SLEB(arg)...)
	}
	body = append(body, 0x10, 0, 0x0b) // call cap_write, return status
	code := append([]byte{2}, wasmgen.ULEB(length(body))...)
	code = append(code, body...)
	code = append(code, 5, 0, 0x10, 1, 0x1a, 0x0b) // start: call run; drop; end (5 bytes)
	out := []byte{0, 0x61, 0x73, 0x6d, 1, 0, 0, 0}
	for _, encoded := range [][]byte{
		section(1, []byte{3, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f, 0x60, 0, 0}),
		section(2, []byte{1, 3, 'e', 'n', 'v', 9, 'c', 'a', 'p', '_', 'w', 'r', 'i', 't', 'e', 0, 0}),
		section(3, []byte{2, 1, 2}), section(5, []byte{1, 0, 1}),
		section(7, []byte{2, 3, 'r', 'u', 'n', 0, 1, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0}),
		section(8, []byte{2}), section(10, code),
		section(11, append(append([]byte{1, 0, 0x41, 0, 0x0b}, wasmgen.ULEB(length(data))...), data...)),
	} {
		out = append(out, encoded...)
	}
	return out
}

func TestVerifiedAdmissionRefusesBeforeGuestStart(t *testing.T) {
	for _, withProvenance := range []bool{false, true} {
		name := "LoadVerified"
		if withProvenance {
			name = "LoadVerifiedWithProvenance"
		}
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"unsigned", "tampered", "wrong_key", "unpinned", "nil_policy", "trusted"} {
				t.Run(kind, func(t *testing.T) {
					ctx := context.Background()
					h := pluginhost.New()
					t.Cleanup(func() { _ = h.Close(ctx) })
					dir := t.TempDir()
					target := filepath.Join(dir, "canary")
					guest := startWriteGuest(target)
					tp, sign := trustedSigner(t)
					signature := sign(guest)
					switch kind {
					case "unsigned":
						signature = nil
					case "tampered":
						guest[len(guest)-1] = 'X'
					case "wrong_key":
						_, other := trustedSigner(t)
						signature = other(guest)
					case "unpinned":
						tp, sign = trustedSigner(t, "0000000000000000000000000000000000000000000000000000000000000000")
						signature = sign(guest)
					case "nil_policy":
						tp = nil
					}
					grant := pluginhost.NewGrant(pluginhost.CapFSWrite).WithPathPrefix(pluginhost.CapFSWrite, dir)
					var p *pluginhost.Plugin
					var err error
					if withProvenance {
						p, _, err = h.LoadVerifiedWithProvenance(ctx, guest, signature, tp, grant)
					} else {
						p, err = h.LoadVerified(ctx, guest, signature, tp, grant)
					}
					if p != nil {
						defer func() { _ = p.Close(ctx) }()
					}
					got, readErr := os.ReadFile(target) // #nosec G304 -- owned canary under t.TempDir (CWE-22).
					if kind == "trusted" {
						if err != nil || readErr != nil || string(got) != "started" {
							t.Fatalf("start positive control: load=%v read=%v content=%q", err, readErr, got)
						}
					} else {
						if err == nil || p != nil {
							t.Fatal("untrusted module admitted")
						}
						if !errors.Is(readErr, os.ErrNotExist) {
							t.Fatalf("guest start ran before refusal: read=%v content=%q", readErr, got)
						}
					}
				})
			}
		})
	}
}
