// SPDX-License-Identifier: BUSL-1.1

package listenersessions

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// userHZ is the kernel's USER_HZ, the unit of a process's start time in
// /proc/<pid>/stat: 100 on every architecture Linux exports to user space.
const userHZ = 100

// maxProcesses bounds one scan of the process table.
const maxProcesses = 1 << 20

// tcpEstablished is the ESTABLISHED state in /proc/net/tcp.
const tcpEstablished = "01"

// observeProc reads a proc file system at root: the TCP tables for the
// established sockets on port, every process's descriptors for who holds
// them, and each holder's start time.
func observeProc(root string, port int, since, now time.Time) (Observation, error) {
	if port <= 0 || port > 65535 {
		return Observation{}, fmt.Errorf("listenersessions: port %d is out of range", port)
	}
	out := Observation{Port: port, SinceUnix: since.Unix(), CheckedAtUnix: now.Unix()}
	sockets := map[string]bool{}
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		if err := establishedOnPort(filepath.Join(root, table), port, sockets); err != nil {
			if errors.Is(err, os.ErrNotExist) && table == "net/tcp6" {
				continue // a kernel without IPv6
			}
			return Observation{}, err
		}
	}
	out.Established = len(sockets)
	if out.Established == 0 {
		return out, nil
	}
	boot, err := bootTime(filepath.Join(root, "stat"))
	if err != nil {
		return Observation{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Observation{}, err
	}
	// holder state per socket inode: attributed to a newer process, or to an
	// older one (which wins).
	const newer, older = 1, 2
	held := map[string]int{}
	scanned := 0
	for _, entry := range entries {
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil || !entry.IsDir() {
			continue
		}
		if scanned++; scanned > maxProcesses {
			return Observation{}, errors.New("listenersessions: process table exceeds the scan bound")
		}
		inodes := heldSockets(filepath.Join(root, pid, "fd"), sockets)
		if len(inodes) == 0 {
			continue
		}
		started, err := processStart(filepath.Join(root, pid, "stat"), boot)
		if err != nil {
			continue // the process ended between the two reads
		}
		state := newer
		if started.Before(since) {
			state = older
		}
		for _, inode := range inodes {
			if state > held[inode] {
				held[inode] = state
			}
		}
	}
	for inode := range sockets {
		switch held[inode] {
		case older:
			out.HeldByOlder++
		case newer:
		default:
			out.Unattributed++
		}
	}
	return out, nil
}

// establishedOnPort adds the inode of every established socket in a
// /proc/net/tcp table whose local port is port.
func establishedOnPort(path string, port int, sockets map[string]bool) error {
	f, err := os.Open(path) // #nosec G304 -- a fixed proc table under the agent's proc root
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<16)
	first := true
	for scanner.Scan() {
		if first { // the header line
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != tcpEstablished {
			continue
		}
		_, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		local, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || int(local) != port || fields[9] == "0" { // #nosec G115 -- parsed with a 16-bit bound
			continue
		}
		sockets[fields[9]] = true
	}
	return scanner.Err()
}

// heldSockets returns the inodes among sockets that a process's descriptors
// open. A directory the agent may not read yields none.
func heldSockets(fdDir string, sockets map[string]bool) []string {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		inode, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inode = strings.TrimSuffix(inode, "]")
		if sockets[inode] {
			out = append(out, inode)
		}
	}
	return out
}

// bootTime reads the boot time from /proc/stat.
func bootTime(path string) (time.Time, error) {
	f, err := os.Open(path) // #nosec G304 -- a fixed proc file under the agent's proc root
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "btime "); ok {
			secs, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || secs <= 0 {
				return time.Time{}, errors.New("listenersessions: unreadable boot time")
			}
			return time.Unix(secs, 0), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return time.Time{}, err
	}
	return time.Time{}, errors.New("listenersessions: no boot time in /proc/stat")
}

// processStart reads a process's start time from /proc/<pid>/stat: field 22,
// in clock ticks since boot. The command name (field 2) is parenthesized and
// may hold spaces or parentheses, so fields are counted after its last ')'.
func processStart(path string, boot time.Time) (time.Time, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a fixed proc file under the agent's proc root
	if err != nil {
		return time.Time{}, err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return time.Time{}, errors.New("listenersessions: unreadable process status")
	}
	fields := strings.Fields(string(raw[end+1:]))
	const startField = 22 - 3 // fields after the name start at field 3
	if len(fields) <= startField {
		return time.Time{}, errors.New("listenersessions: short process status")
	}
	ticks, err := strconv.ParseUint(fields[startField], 10, 63)
	if err != nil {
		return time.Time{}, errors.New("listenersessions: unreadable process start")
	}
	return boot.Add(time.Duration(ticks) * (time.Second / userHZ)), nil // #nosec G115 -- parsed with a 63-bit bound
}
