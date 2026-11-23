// SPDX-License-Identifier: BUSL-1.1
//go:build darwin

package secret

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectedBufferDarwinDisablesCoreBeforeUse(t *testing.T) {
	buffer, err := NewProtected(32)
	if err != nil {
		t.Fatalf("allocate protected buffer: %v", err)
	}
	defer buffer.Destroy()
	var core unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &core); err != nil {
		t.Fatal(err)
	}
	if core.Cur != 0 || core.Max != 0 {
		t.Fatalf("protected buffer allowed core dump: soft=%d hard=%d", core.Cur, core.Max)
	}
	if err := buffer.Use(func(data []byte) error {
		if len(data) != 32 {
			t.Fatalf("protected buffer len=%d, want 32", len(data))
		}
		for i := range data {
			data[i] = 0x5a
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedBufferDarwinFailsClosedOnMlockError(t *testing.T) {
	const childFlag = "TRSTCTL_TEST_PROTECTED_MLOCK_REFUSAL"
	if os.Getenv(childFlag) == "1" {
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		buffer, err := NewProtected(32)
		if buffer != nil {
			buffer.Destroy()
		}
		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("unlocked protected allocation err=%v, want custody refusal", err)
		}
		return
	}
	// #nosec G204 G702 -- execute this test binary with a fixed test selector and no shell
	child := exec.Command(os.Args[0], "-test.run=^TestProtectedBufferDarwinFailsClosedOnMlockError$")
	child.Env = append(os.Environ(), childFlag+"=1")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("protected-allocation refusal subprocess: %v\n%s", err, output)
	}
}
