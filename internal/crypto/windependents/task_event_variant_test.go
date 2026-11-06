// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"testing"
	"time"
	"unsafe"
)

func TestTaskEventVariantRefusesPointerAuthorityA267(t *testing.T) {
	if unsafe.Sizeof(taskEventVariant{}) != 16 {
		t.Fatal("native event variant layout differs")
	}
	for _, kind := range []uint32{0, 1, 2, 15, 19, 32, 35, 0x88} {
		if _, err := (taskEventVariant{Type: kind, Value: 0}).unsigned(); err == nil {
			t.Fatal("native pointer/text/array/null interpreted as successful result code")
		}
	}
	if value, err := (taskEventVariant{Type: 8, Value: 42}).unsigned(); err != nil || value != 42 {
		t.Fatal("native result decoded incorrectly")
	}
	if _, err := (taskEventVariant{Type: 8, Count: 1, Value: 0}).unsigned(); err == nil {
		t.Fatal("native array interpreted as scalar result")
	}
	if value, err := (taskEventVariant{Type: 13, Value: 1}).boolean(); err != nil || !value {
		t.Fatal("native enabled flag differs")
	}
}
func FuzzTaskEventVariantA267(f *testing.F) {
	f.Add(uint32(8), uint32(0), uint64(0))
	f.Add(uint32(19), uint32(0), uint64(0))
	f.Fuzz(func(t *testing.T, kind, count uint32, value uint64) {
		_, err := (taskEventVariant{Type: kind, Count: count, Value: value}).unsigned()
		allowed := count == 0 && (kind == 4 || kind == 6 || kind == 8 || kind == 10 || kind == 20 || kind == 21)
		if (err == nil) != allowed {
			t.Fatal("native event scalar authority classification differs")
		}
	})
}

func TestNativeTaskEventTimeA267(t *testing.T) {
	const epoch = uint64(11644473600)
	const seconds = uint64(1700000000)
	const fractional = uint64(1234567)
	value := taskEventVariant{Type: 17, Value: (seconds+epoch)*10000000 + fractional}
	got, e := value.fileTime()
	if e != nil || got.Unix() != int64(seconds) || got.Nanosecond() != int(fractional*100) || got.Location() != time.UTC {
		t.Fatal("native UTC FILETIME lost its exact event timestamp")
	}
	for _, candidate := range []taskEventVariant{{Type: 17, Value: 0}, {Type: 17, Count: 1, Value: value.Value}, {Type: 1, Value: value.Value}, {Type: 18, Value: value.Value}, {Type: 19, Value: value.Value}, {Type: 17, Value: ^uint64(0)}} {
		if _, e = candidate.fileTime(); e == nil {
			t.Fatal("native null, pointer, array, systemtime or out-of-range time accepted as event FILETIME")
		}
	}
}
