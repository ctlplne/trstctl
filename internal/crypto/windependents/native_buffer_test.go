// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"unicode/utf16"
	"unicode/utf8"
)

func TestNativeServicePrivateConfigAndUTF16A267(t *testing.T) {
	private := []byte("owned-private-command-argument")
	first := serviceConfigurationHash("owned-service", "S-1-5-21-1-2-3-1001", []uint32{16, 3}, [][]byte{private, []byte("ab"), []byte("c")})
	same := serviceConfigurationHash("owned-service", "S-1-5-21-1-2-3-1001", []uint32{16, 3}, [][]byte{private, []byte("ab"), []byte("c")})
	boundary := serviceConfigurationHash("owned-service", "S-1-5-21-1-2-3-1001", []uint32{16, 3}, [][]byte{private, []byte("a"), []byte("bc")})
	numeric := serviceConfigurationHash("owned-service", "S-1-5-21-1-2-3-1001", []uint32{1}, nil)
	field := serviceConfigurationHash("owned-service", "S-1-5-21-1-2-3-1001", nil, [][]byte{{1, 0, 0, 0}})
	if first != same || first == boundary || numeric == field || len(first) != 64 {
		t.Fatal("native config hash is unstable or ambiguous")
	}
	wire, err := json.Marshal(Service{Name: "owned-service", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: first})
	if err != nil || bytes.Contains(wire, private) {
		t.Fatal("native private config escaped the boundary")
	}
	if err := quick.Check(func(value string) bool {
		password := append([]byte("Tr5!owned-"), []byte(value)...)
		if len(password) < 16 {
			password = append(password, []byte("padding")...)
		}
		held, err := lockedWindowsPassword(password)
		valid := len(password) <= 1024 && utf8.Valid(password) && !bytes.Contains(password, []byte{0})
		if err != nil {
			return !valid
		}
		defer held.Destroy()
		if !valid {
			return false
		}
		reference := utf16.Encode([]rune(string(password)))
		if len(held.Bytes()) != (len(reference)+1)*2 {
			return false
		}
		for i, unit := range reference {
			if binary.LittleEndian.Uint16(held.Bytes()[i*2:]) != unit {
				return false
			}
		}
		return binary.LittleEndian.Uint16(held.Bytes()[len(held.Bytes())-2:]) == 0
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func TestNativeServiceDiscoveryRefusesIncompleteAuthorityA267(t *testing.T) {
	driver := &ownedServiceDriver{current: ownedService()}
	adapter := Services{driver: driver}
	if found, err := adapter.Discover(t.Context(), driver.current.AccountSID); err != nil || len(found) != 1 {
		t.Fatal("selected native service discovery failed")
	}
	if _, err := adapter.Discover(t.Context(), "S-1-5-18"); err == nil {
		t.Fatal("built-in system account admitted for password rotation")
	}
	driver.current.AccountSID = "S-1-5-21-100-200-300-1002"
	if _, err := adapter.Discover(t.Context(), ownedService().AccountSID); err == nil {
		t.Fatal("foreign discovery record admitted")
	}
	driver.current = ownedService()
	driver.current.Dependencies = []string{"same", "SAME"}
	if _, err := adapter.Discover(t.Context(), ownedService().AccountSID); err == nil {
		t.Fatal("ambiguous native dependencies admitted")
	}
	driver.current.Dependencies = []string{strings.Repeat("a", 257)}
	if _, err := adapter.Discover(t.Context(), ownedService().AccountSID); err == nil {
		t.Fatal("unbounded native dependency admitted")
	}
}
func FuzzNativeServiceBufferA267(f *testing.F) {
	f.Add([]byte{'a', 0, 0, 0}, 0, false)
	f.Add([]byte{'a', 0, 0, 0, 0, 0}, 0, true)
	f.Add([]byte{0}, -1, false)
	f.Fuzz(func(t *testing.T, raw []byte, offset int, multi bool) {
		if len(raw) > 64<<10 {
			return
		}
		value, err := nativeWideBytes(raw, offset, multi)
		if err == nil {
			if offset < 0 || offset%2 != 0 || len(value)%2 != 0 || len(value) > len(raw) {
				t.Fatal("unbounded native UTF-16 view")
			}
			if !multi {
				if _, e := publicNativeText(value); e == nil && len(value) > 8192 {
					t.Fatal("unbounded native public name")
				}
			}
		}
	})
}
