// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func sftpPacket(kind byte, id uint32, fields ...[]byte) []byte {
	body := []byte{kind}
	body = binary.BigEndian.AppendUint32(body, id)
	for _, f := range fields {
		body = append(body, f...)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...) // #nosec G115 -- test packets are small (CWE-190)
}

func sftpStr(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...) // #nosec G115 -- test strings are small (CWE-190)
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// The recording of an SFTP session is its operations, never the contents.
func TestSFTPTrackerRecordsOperationsNotContentsA255(t *testing.T) {
	var ops []sftpOp
	tr := newSFTPTracker(func(op sftpOp) { ops = append(ops, op) })
	client := func(b []byte) { // split each packet to prove reassembly
		tr.Client(b[:3])
		tr.Client(b[3:])
	}
	// put: open, two writes, close.
	client(sftpPacket(sftpOpen, 1, sftpStr("/srv/report.csv"), u32(0x1a), u32(0)))
	tr.Target(sftpPacket(sftpHandle, 1, sftpStr("h1")))
	client(sftpPacket(sftpWrite, 2, sftpStr("h1"), u64(0), sftpStr("secret-file-contents")))
	tr.Target(sftpPacket(sftpStatus, 2, u32(0)))
	client(sftpPacket(sftpWrite, 3, sftpStr("h1"), u64(20), sftpStr("more")))
	tr.Target(sftpPacket(sftpStatus, 3, u32(0)))
	client(sftpPacket(sftpClose, 4, sftpStr("h1")))
	tr.Target(sftpPacket(sftpStatus, 4, u32(0)))
	// get: open, read, data, close.
	client(sftpPacket(sftpOpen, 5, sftpStr("/etc/motd"), u32(1), u32(0)))
	tr.Target(sftpPacket(sftpHandle, 5, sftpStr("h2")))
	client(sftpPacket(sftpRead, 6, sftpStr("h2"), u64(0), u32(32768)))
	tr.Target(sftpPacket(sftpData, 6, sftpStr("welcome")))
	client(sftpPacket(sftpClose, 7, sftpStr("h2")))
	tr.Target(sftpPacket(sftpStatus, 7, u32(0)))
	// remove refused, rename done.
	client(sftpPacket(sftpRemove, 8, sftpStr("/etc/passwd")))
	tr.Target(sftpPacket(sftpStatus, 8, u32(3)))
	client(sftpPacket(sftpRename, 9, sftpStr("/tmp/a"), sftpStr("/tmp/b")))
	tr.Target(sftpPacket(sftpStatus, 9, u32(0)))
	want := []sftpOp{
		{Op: "write", Path: "/srv/report.csv", Bytes: 24, Status: "ok"},
		{Op: "read", Path: "/etc/motd", Bytes: 7, Status: "ok"},
		{Op: "remove", Path: "/etc/passwd", Status: "permission_denied"},
		{Op: "rename", Path: "/tmp/a", To: "/tmp/b", Status: "ok"},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %+v\nwant %+v", ops, want)
	}
}
