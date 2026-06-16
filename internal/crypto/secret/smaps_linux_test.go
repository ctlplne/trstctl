//go:build linux

package secret_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// TestBufferLockedAndNoDumpLinux verifies, via /proc/self/smaps, that a secret
// buffer's pages are locked (VmFlags "lo") and excluded from core dumps
// (VmFlags "dd") on Linux.
func TestBufferLockedAndNoDumpLinux(t *testing.T) {
	b, err := secret.New(64)
	if err != nil {
		t.Fatalf("New: %v (is RLIMIT_MEMLOCK too low?)", err)
	}
	defer b.Destroy()

	addr := uintptr(unsafe.Pointer(&b.Bytes()[0]))
	flags, err := vmFlagsFor(addr)
	runtime.KeepAlive(b)
	if err != nil {
		t.Fatalf("vmFlagsFor: %v", err)
	}
	if !hasFlag(flags, "lo") {
		t.Errorf("buffer is not locked: VmFlags = %v (want to contain 'lo')", flags)
	}
	if !hasFlag(flags, "dd") {
		t.Errorf("buffer is not excluded from core dumps: VmFlags = %v (want to contain 'dd')", flags)
	}
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// vmFlagsFor returns the VmFlags of the mapping containing addr.
func vmFlagsFor(addr uintptr) ([]string, error) {
	data, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	inRange := false
	for sc.Scan() {
		line := sc.Text()
		if start, end, ok := parseMapHeader(line); ok {
			inRange = addr >= start && addr < end
			continue
		}
		if inRange && strings.HasPrefix(line, "VmFlags:") {
			return strings.Fields(strings.TrimPrefix(line, "VmFlags:")), nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("address %#x not found in smaps", addr)
}

// parseMapHeader parses a smaps header line such as
// "7f3c0a-7f3c0b rw-p 00000000 00:00 0 [heap]" into its address range.
func parseMapHeader(line string) (start, end uintptr, ok bool) {
	dash := strings.IndexByte(line, '-')
	if dash <= 0 {
		return 0, 0, false
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 0 || sp < dash {
		return 0, 0, false
	}
	s, err1 := strconv.ParseUint(line[:dash], 16, 64)
	e, err2 := strconv.ParseUint(line[dash+1:sp], 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uintptr(s), uintptr(e), true
}
