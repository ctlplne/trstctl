// SPDX-License-Identifier: BUSL-1.1
package sshgateway

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestExecCommandRequiresOneBoundedSSHString(t *testing.T) {
	for _, raw := range [][]byte{{}, {0, 0, 0}, {0, 0, 0, 2, 'r'}, {0, 0, 0, 1, 'r', 'm'}, bytes.Repeat([]byte{'x'}, MaxExecCommandBytes+5)} {
		if _, ok := ExecCommand(raw); ok {
			t.Fatal("malformed exec envelope accepted")
		}
	}
	for _, command := range [][]byte{[]byte("rm /owned/file"), {}, bytes.Repeat([]byte{'x'}, MaxExecCommandBytes)} {
		raw := make([]byte, len(command)+4)
		binary.BigEndian.PutUint32(raw, uint32(len(command))) // #nosec G115 -- bounded by MaxExecCommandBytes (CWE-190)
		copy(raw[4:], command)
		got, ok := ExecCommand(raw)
		if !ok || !bytes.Equal(got, command) {
			t.Fatal("valid exec envelope changed")
		}
	}
}

func FuzzSSHExecCommand(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 'r', 'm'})
	f.Add([]byte{0, 0, 0, 1, 'r', 'm'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		command, ok := ExecCommand(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("wire parser changed traffic")
		}
		if ok && (len(command) > MaxExecCommandBytes || len(raw) != len(command)+4 || uint64(binary.BigEndian.Uint32(raw)) != uint64(len(command))) {
			t.Fatal("invalid envelope accepted")
		}
	})
}
