// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"encoding/binary"
	"fmt"
	"testing"
	"testing/quick"
	"unicode/utf16"
)

func TestPoolWorkerMetadataScopeA267(t *testing.T) {
	raw := []byte("<appcmd><WP WP.NAME=\"41\" APPPOOL.NAME=\"owned-pool\" /></appcmd>")
	if found, err := parsePoolWorkerMetadata(raw, "owned-pool"); err != nil || len(found) != 1 || found[0] != 41 {
		t.Fatal("native worker metadata rejected")
	}
	for _, raw := range []string{"<appcmd><WP WP.NAME=\"41\" APPPOOL.NAME=\"foreign\" /></appcmd>", "<appcmd><WP WP.NAME=\"0\" APPPOOL.NAME=\"owned-pool\" /></appcmd>", "<appcmd><WP WP.NAME=\"41\" WP.NAME=\"42\" APPPOOL.NAME=\"owned-pool\" /></appcmd>", "<appcmd><nested /></appcmd>", "<!DOCTYPE appcmd><appcmd/>", "<appcmd/><appcmd/>"} {
		if _, err := parsePoolWorkerMetadata([]byte(raw), "owned-pool"); err == nil {
			t.Fatal("unscoped or malformed worker metadata admitted")
		}
	}
	if err := quick.Check(func(pid uint32) bool {
		if pid == 0 {
			return true
		}
		raw := []byte(fmt.Sprintf("<appcmd><WP WP.NAME=\"%d\" APPPOOL.NAME=\"owned-pool\" /></appcmd>", pid))
		found, err := parsePoolWorkerMetadata(raw, "owned-pool")
		return err == nil && len(found) == 1 && found[0] == pid
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func FuzzPoolWorkerMetadataA267(f *testing.F) {
	f.Add([]byte("<appcmd><WP WP.NAME=\"41\" APPPOOL.NAME=\"owned-pool\" /></appcmd>"))
	f.Add([]byte("<appcmd/>"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		found, err := parsePoolWorkerMetadata(raw, "owned-pool")
		if err == nil {
			if len(found) > 128 {
				t.Fatal("unbounded native worker set")
			}
			seen := map[uint32]bool{}
			for _, pid := range found {
				if pid == 0 || seen[pid] {
					t.Fatal("invalid native worker set")
				}
				seen[pid] = true
			}
		}
	})
}

func TestPoolWorkerMetadataRejectsAmbiguousEncodingA267(t *testing.T) {
	for _, raw := range []string{
		`<appcmd xmlns:x="urn:foreign"><WP x:WP.NAME="41" APPPOOL.NAME="owned-pool" /></appcmd>`,
		`<appcmd xmlns:x="urn:foreign"><WP WP.NAME="41" x:APPPOOL.NAME="owned-pool" /></appcmd>`,
	} {
		if _, err := parsePoolWorkerMetadata([]byte(raw), "owned-pool"); err == nil {
			t.Fatal("namespaced native identity admitted")
		}
	}
	units := utf16.Encode([]rune(`<appcmd><WP WP.NAME="41" APPPOOL.NAME="owned-pool" other="`))
	units = append(units, 0xd800)
	units = append(units, utf16.Encode([]rune(`" /></appcmd>`))...)
	raw := make([]byte, 2+len(units)*2)
	raw[0], raw[1] = 0xff, 0xfe
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[2+i*2:], unit)
	}
	if _, err := parsePoolWorkerMetadata(raw, "owned-pool"); err == nil {
		t.Fatal("invalid UTF-16 worker metadata admitted")
	}
}
