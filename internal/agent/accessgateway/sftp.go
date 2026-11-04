// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"encoding/binary"
	"strconv"
)

// SFTP (draft-ietf-secsh-filexfer-02, the version OpenSSH speaks) packet
// types the recording reads. File contents are never recorded: an SFTP
// session is recorded as its operations — op, path, bytes moved, result.
const (
	sftpOpen     = 3
	sftpClose    = 4
	sftpRead     = 5
	sftpWrite    = 6
	sftpSetstat  = 9
	sftpOpendir  = 11
	sftpRemove   = 13
	sftpMkdir    = 14
	sftpRmdir    = 15
	sftpRename   = 18
	sftpSymlink  = 20
	sftpStatus   = 101
	sftpHandle   = 102
	sftpData     = 103
	sftpMaxFrame = 256 << 10
)

// sftpOp is one recorded SFTP operation.
type sftpOp struct {
	Op     string `json:"op"`
	Path   string `json:"path,omitempty"`
	To     string `json:"to,omitempty"`
	Bytes  uint64 `json:"bytes,omitempty"`
	Status string `json:"status,omitempty"`
}

// sftpTracker turns one SFTP channel's two byte streams into operations.
// Requests are matched to their responses by id; bytes read and written are
// summed per open handle and reported when the handle closes.
type sftpTracker struct {
	in, out  []byte
	pending  map[uint32]sftpOp
	opening  map[uint32]string // request id → path being opened
	reads    map[uint32]string // read request id → its handle
	handles  map[string]*sftpHandleState
	reported func(sftpOp)
}

type sftpHandleState struct {
	path, op      string
	read, written uint64
}

// closed is the operation a handle amounts to: a write if anything was
// written, else a read if anything was read, else its open.
func (h *sftpHandleState) closed() sftpOp {
	switch {
	case h.written > 0:
		return sftpOp{Op: "write", Path: h.path, Bytes: h.written}
	case h.read > 0:
		return sftpOp{Op: "read", Path: h.path, Bytes: h.read}
	}
	return sftpOp{Op: h.op, Path: h.path}
}

func newSFTPTracker(report func(sftpOp)) *sftpTracker {
	return &sftpTracker{pending: map[uint32]sftpOp{}, opening: map[uint32]string{}, reads: map[uint32]string{},
		handles: map[string]*sftpHandleState{}, reported: report}
}

// Client feeds bytes the client sent; Target bytes the target sent.
func (t *sftpTracker) Client(p []byte) { t.in = t.feed(t.in, p, t.request) }
func (t *sftpTracker) Target(p []byte) { t.out = t.feed(t.out, p, t.response) }

func (t *sftpTracker) feed(buf, p []byte, handle func(kind byte, body []byte)) []byte {
	buf = append(buf, p...)
	for len(buf) >= 5 {
		n := binary.BigEndian.Uint32(buf)
		if n == 0 || n > sftpMaxFrame {
			// Not SFTP framing any more; stop reading this stream.
			return nil
		}
		if uint64(len(buf)) < 4+uint64(n) {
			break
		}
		handle(buf[4], buf[5:4+n])
		buf = buf[4+n:]
	}
	return append([]byte(nil), buf...)
}

func (t *sftpTracker) request(kind byte, body []byte) {
	if len(body) < 4 {
		return
	}
	id, rest := binary.BigEndian.Uint32(body), body[4:]
	switch kind {
	case sftpOpen, sftpOpendir:
		if path, _, ok := sftpString(rest); ok {
			t.opening[id] = path
			op := "open"
			if kind == sftpOpendir {
				op = "opendir"
			}
			t.pending[id] = sftpOp{Op: op, Path: path}
		}
	case sftpRead, sftpWrite:
		handle, rest, ok := sftpString(rest)
		h := t.handles[handle]
		if !ok || len(rest) < 8 || h == nil {
			return
		}
		if kind == sftpRead {
			t.reads[id] = handle
		} else if data, _, ok := sftpString(rest[8:]); ok {
			h.written += uint64(len(data))
		}
	case sftpClose:
		if handle, _, ok := sftpString(rest); ok {
			if h := t.handles[handle]; h != nil {
				t.pending[id] = h.closed()
				delete(t.handles, handle)
			}
		}
	case sftpRemove, sftpMkdir, sftpRmdir, sftpSetstat:
		if path, _, ok := sftpString(rest); ok {
			t.pending[id] = sftpOp{Op: map[byte]string{sftpRemove: "remove", sftpMkdir: "mkdir", sftpRmdir: "rmdir", sftpSetstat: "setstat"}[kind], Path: path}
		}
	case sftpRename, sftpSymlink:
		from, rest, ok := sftpString(rest)
		to, _, ok2 := sftpString(rest)
		if ok && ok2 {
			op := "rename"
			if kind == sftpSymlink {
				op = "symlink"
			}
			t.pending[id] = sftpOp{Op: op, Path: from, To: to}
		}
	}
}

func (t *sftpTracker) response(kind byte, body []byte) {
	if len(body) < 4 {
		return
	}
	id, rest := binary.BigEndian.Uint32(body), body[4:]
	switch kind {
	case sftpHandle:
		handle, _, ok := sftpString(rest)
		path, opening := t.opening[id]
		delete(t.opening, id)
		op := t.pending[id]
		delete(t.pending, id)
		if ok && opening {
			t.handles[handle] = &sftpHandleState{path: path, op: op.Op}
		}
	case sftpData:
		// Bytes read are summed on the handle that asked; contents are not
		// kept.
		handle, asked := t.reads[id]
		delete(t.reads, id)
		if data, _, ok := sftpString(rest); ok && asked && t.handles[handle] != nil {
			t.handles[handle].read += uint64(len(data))
		}
	case sftpStatus:
		delete(t.opening, id)
		delete(t.reads, id)
		op, ok := t.pending[id]
		delete(t.pending, id)
		if !ok || len(rest) < 4 {
			return
		}
		code := binary.BigEndian.Uint32(rest)
		op.Status = sftpStatusName(code)
		t.reported(op)
	}
}

func sftpStatusName(code uint32) string {
	switch code {
	case 0:
		return "ok"
	case 1:
		return "eof"
	case 2:
		return "no_such_file"
	case 3:
		return "permission_denied"
	case 4:
		return "failure"
	default:
		return "status_" + strconv.FormatUint(uint64(code), 10)
	}
}

func sftpString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if int64(len(b)-4) < int64(n) {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}
