// SPDX-License-Identifier: MPL-2.0

//go:build linux

package proof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// artifactMutationWatch makes swap-then-restore observable even when the
// hardened Rosetta signer deliberately makes /proc/PID/exe unreadable. Reads
// and execs do not trigger this mask; every operation that can replace or alter
// a gate-built executable does.
type artifactMutationWatch struct {
	mu     sync.Mutex
	fd     int
	watch  int
	closed bool
}

func newArtifactMutationWatch(directory string) (*artifactMutationWatch, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	mask := uint32(unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE |
		unix.IN_DELETE_SELF | unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_MOVED_FROM | unix.IN_MOVED_TO)
	watch, err := unix.InotifyAddWatch(fd, directory, mask)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &artifactMutationWatch{fd: fd, watch: watch}, nil
}

func (w *artifactMutationWatch) AssertQuiet() error {
	if w == nil {
		return fmt.Errorf("shipped-artifact mutation watch is absent")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.fd < 0 || w.watch < 0 {
		return fmt.Errorf("shipped-artifact mutation watch is closed")
	}
	buffer := make([]byte, 4096)
	for {
		n, err := unix.Read(w.fd, buffer)
		switch {
		case n > 0:
			return fmt.Errorf("gate-built executable directory recorded a mutation event: %s", describeArtifactMutation(buffer[:n]))
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil
		default:
			return fmt.Errorf("read shipped-artifact mutation watch: %w", err)
		}
	}
}

func describeArtifactMutation(buffer []byte) string {
	const headerSize = 16
	var events []string
	for len(buffer) >= headerSize {
		mask := binary.NativeEndian.Uint32(buffer[4:8])
		nameLength := int(binary.NativeEndian.Uint32(buffer[12:16]))
		if nameLength < 0 || nameLength > len(buffer)-headerSize {
			events = append(events, "malformed-event")
			break
		}
		name := string(bytes.TrimRight(buffer[headerSize:headerSize+nameLength], "\x00"))
		if name == "" {
			name = "."
		}
		events = append(events, name+"["+artifactMutationMask(mask)+"]")
		buffer = buffer[headerSize+nameLength:]
	}
	if len(events) == 0 {
		return "unparseable-event"
	}
	return strings.Join(events, ",")
}

func artifactMutationMask(mask uint32) string {
	type namedMask struct {
		value uint32
		name  string
	}
	known := []namedMask{
		{unix.IN_ATTRIB, "ATTRIB"}, {unix.IN_CLOSE_WRITE, "CLOSE_WRITE"},
		{unix.IN_CREATE, "CREATE"}, {unix.IN_DELETE, "DELETE"},
		{unix.IN_DELETE_SELF, "DELETE_SELF"}, {unix.IN_MODIFY, "MODIFY"},
		{unix.IN_MOVE_SELF, "MOVE_SELF"}, {unix.IN_MOVED_FROM, "MOVED_FROM"},
		{unix.IN_MOVED_TO, "MOVED_TO"}, {unix.IN_IGNORED, "IGNORED"},
		{unix.IN_ISDIR, "ISDIR"}, {unix.IN_Q_OVERFLOW, "Q_OVERFLOW"},
	}
	parts := make([]string, 0, len(known)+1)
	remaining := mask
	for _, item := range known {
		if mask&item.value != 0 {
			parts = append(parts, item.name)
			remaining &^= item.value
		}
	}
	if remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", remaining))
	}
	if len(parts) == 0 {
		return "NONE"
	}
	return strings.Join(parts, "|")
}

func (w *artifactMutationWatch) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	err := unix.Close(w.fd)
	w.fd, w.watch = -1, -1
	return err
}
