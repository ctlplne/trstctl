// External test package: a caller's view of the secret package. (It also keeps
// the string-using test helpers out of the //trstctl:keymaterial-marked package
// itself, where the AN-8 rule forbids string.)
package secret_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestNewIsZeroedWithRequestedSize(t *testing.T) {
	b, err := secret.New(32)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.Destroy()

	if b.Len() != 32 {
		t.Errorf("Len() = %d, want 32", b.Len())
	}
	if len(b.Bytes()) != 32 {
		t.Errorf("len(Bytes()) = %d, want 32", len(b.Bytes()))
	}
	for i, v := range b.Bytes() {
		if v != 0 {
			t.Fatalf("byte %d = %d, want a freshly zeroed buffer", i, v)
		}
	}
}

func TestNewFromCopiesAndIsIndependent(t *testing.T) {
	src := []byte("super-secret-key-material")
	b, err := secret.NewFrom(src)
	if err != nil {
		t.Fatalf("NewFrom: %v", err)
	}
	defer b.Destroy()

	if !bytes.Equal(b.Bytes(), src) {
		t.Errorf("Bytes() = %q, want %q", b.Bytes(), src)
	}
	// Mutating the buffer must not affect the source slice.
	b.Bytes()[0] = 'X'
	if src[0] == 'X' {
		t.Error("NewFrom aliased the source instead of copying it")
	}
}

func TestNewRejectsNonPositiveSize(t *testing.T) {
	if _, err := secret.New(0); err == nil {
		t.Error("New(0) should return an error")
	}
	if _, err := secret.New(-5); err == nil {
		t.Error("New(-5) should return an error")
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	b, err := secret.New(16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.Destroy()
	b.Destroy() // must not panic on a second call
	if b.Bytes() != nil {
		t.Error("Bytes() should be nil after Destroy")
	}
	if b.Len() != 0 {
		t.Error("Len() should be 0 after Destroy")
	}
}

func TestWipeZeroesEveryByte(t *testing.T) {
	b := []byte("not-zero-data-here")
	secret.Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d after Wipe, want 0", i, v)
		}
	}
}

func TestLockedBufferSourceKeepsMemoryHardening(t *testing.T) {
	bufferSrc, err := os.ReadFile("buffer.go")
	if err != nil {
		t.Fatalf("read buffer.go: %v", err)
	}
	for _, want := range []string{
		"Wipe(b.region)",
		"free(b.region)",
		"runtime.KeepAlive(b)",
	} {
		if !strings.Contains(string(bufferSrc), want) {
			t.Errorf("buffer.go no longer contains %q; locked buffer zeroization/release hardening may have regressed", want)
		}
	}

	linuxSrc, err := os.ReadFile("mem_linux.go")
	if err != nil {
		t.Fatalf("read mem_linux.go: %v", err)
	}
	for _, want := range []string{
		"unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)",
		"unix.Mlock(region)",
		"unix.Madvise(region, unix.MADV_DONTDUMP)",
		"unix.Madvise(region, unix.MADV_DODUMP)",
		"unix.Munlock(region)",
		"unix.Munmap(region)",
		"roundUpToPage(size)",
	} {
		if !strings.Contains(string(linuxSrc), want) {
			t.Errorf("mem_linux.go no longer contains %q; Linux locked/no-dump memory controls may have regressed", want)
		}
	}
}

// FuzzWipe exercises the zeroization (zero path) with arbitrary inputs.
func FuzzWipe(f *testing.F) {
	f.Add([]byte("hunter2"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 255, 128})
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		secret.Wipe(buf)
		for i, v := range buf {
			if v != 0 {
				t.Fatalf("byte %d = %d after Wipe, want 0", i, v)
			}
		}
	})
}
