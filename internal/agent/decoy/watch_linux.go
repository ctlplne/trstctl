// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package decoy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Watcher holds a decoy watch the kernel has armed: an open made after Arm
// returns is reported by Run.
type Watcher struct {
	mechanism string
	run       func(ctx context.Context, report func(Access)) error
}

// Mechanism is "fanotify" or "inotify".
func (w *Watcher) Mechanism() string { return w.mechanism }

// Run reports every open of a decoy until ctx ends, then releases the watch.
func (w *Watcher) Run(ctx context.Context, report func(Access)) error { return w.run(ctx, report) }

// Arm watches the decoys for opens. fanotify names the process that opened a
// file; Arm uses it when the kernel lets it (CAP_SYS_ADMIN), and otherwise
// inotify, which sees the open but not who made it. An open by the agent's
// own process is never reported by fanotify; the agent's scans skip its
// decoys (Is), so inotify does not see the agent either.
func Arm(decoys []Decoy) (*Watcher, error) {
	if len(decoys) == 0 {
		return nil, errors.New("decoy: nothing to watch")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err == nil {
		marked := true
		for _, d := range decoys {
			if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN, unix.AT_FDCWD, d.Path); err != nil {
				marked = false
				break
			}
		}
		if marked {
			paths := planted(decoys)
			return &Watcher{mechanism: "fanotify", run: func(ctx context.Context, report func(Access)) error {
				return watchFanotify(ctx, fd, paths, report)
			}}, nil
		}
		_ = unix.Close(fd)
	}
	fd, paths, err := armInotify(decoys)
	if err != nil {
		return nil, err
	}
	return &Watcher{mechanism: "inotify", run: func(ctx context.Context, report func(Access)) error {
		return watchInotify(ctx, fd, paths, report)
	}}, nil
}

// Watch arms a watch on the decoys and runs it until ctx ends, returning the
// mechanism that watched.
func Watch(ctx context.Context, decoys []Decoy, report func(Access)) (string, error) {
	w, err := Arm(decoys)
	if err != nil {
		return "", err
	}
	return w.Mechanism(), w.Run(ctx, report)
}

// planted maps each decoy's resolved path — what the kernel names an open
// file by — back to the path it was planted at.
func planted(decoys []Decoy) map[string]string {
	out := map[string]string{}
	for _, d := range decoys {
		out[d.Path] = d.Path
		if real, err := filepath.EvalSymlinks(d.Path); err == nil {
			out[real] = d.Path
		}
	}
	return out
}

func watchFanotify(ctx context.Context, fd int, paths map[string]string, report func(Access)) error {
	defer func() { _ = unix.Close(fd) }()
	self := os.Getpid()
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		if !readable(fd) {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("decoy: read fanotify events: %w", err)
		}
		for b := buf[:n]; len(b) >= unix.FAN_EVENT_METADATA_LEN; {
			length := int(binary.NativeEndian.Uint32(b[0:4]))
			if length < unix.FAN_EVENT_METADATA_LEN || length > len(b) {
				break
			}
			eventFD := int(int32(binary.NativeEndian.Uint32(b[16:20]))) // #nosec G115 -- the kernel's signed file descriptor field (CWE-190)
			pid := int(int32(binary.NativeEndian.Uint32(b[20:24])))     // #nosec G115 -- the kernel's signed process ID field (CWE-190)
			b = b[length:]
			if eventFD < 0 {
				continue
			}
			opened, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(eventFD))
			_ = unix.Close(eventFD)
			path, ok := paths[opened]
			if pid == self || !ok {
				continue
			}
			report(Access{Path: path, At: time.Now().UTC(), PID: pid, Process: processName(pid), Mechanism: "fanotify"})
		}
	}
	return nil
}

func armInotify(decoys []Decoy) (int, map[int32]string, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return -1, nil, fmt.Errorf("decoy: inotify: %w", err)
	}
	paths := map[int32]string{}
	for _, d := range decoys {
		wd, err := unix.InotifyAddWatch(fd, d.Path, unix.IN_OPEN)
		if err != nil {
			_ = unix.Close(fd)
			return -1, nil, fmt.Errorf("decoy: watch %s: %w", d.Path, err)
		}
		paths[int32(wd)] = d.Path // #nosec G115 -- a watch descriptor the kernel numbers from 1 (CWE-190)
	}
	return fd, paths, nil
}

func watchInotify(ctx context.Context, fd int, paths map[int32]string, report func(Access)) error {
	defer func() { _ = unix.Close(fd) }()
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		if !readable(fd) {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("decoy: read inotify events: %w", err)
		}
		for b := buf[:n]; len(b) >= unix.SizeofInotifyEvent; {
			wd := int32(binary.NativeEndian.Uint32(b[0:4])) // #nosec G115 -- the kernel's signed watch descriptor field (CWE-190)
			mask := binary.NativeEndian.Uint32(b[4:8])
			nameLen := int(binary.NativeEndian.Uint32(b[12:16]))
			if unix.SizeofInotifyEvent+nameLen > len(b) {
				break
			}
			b = b[unix.SizeofInotifyEvent+nameLen:]
			path, ok := paths[wd]
			if !ok || mask&unix.IN_OPEN == 0 {
				continue
			}
			access := Access{Path: path, At: time.Now().UTC(), Mechanism: "inotify"}
			// inotify does not say who opened the file; a process still
			// holding it is named.
			if pid := holder(path); pid > 0 {
				access.PID, access.Process = pid, processName(pid)
			}
			report(access)
		}
	}
	return nil
}

// readable waits up to half a second for events.
func readable(fd int) bool {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} // #nosec G115 -- a file descriptor this process opened (CWE-190)
	n, err := unix.Poll(fds, 500)
	return err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0
}

// processName names a process by its command and executable ("cat
// (/bin/busybox)" where they differ), as far as the process table still
// shows them.
func processName(pid int) string {
	exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	comm := ""
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil { // #nosec G304 -- the kernel's process table (CWE-22)
		comm = strings.TrimSpace(string(raw))
	}
	switch {
	case comm != "" && exe != "" && filepath.Base(exe) != comm:
		return comm + " (" + exe + ")"
	case exe != "":
		return exe
	}
	return comm
}

// holder finds a process other than this one with path open.
func holder(path string) int {
	self := os.Getpid()
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == self {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if target, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name())); err == nil && target == path {
				return pid
			}
		}
	}
	return 0
}
