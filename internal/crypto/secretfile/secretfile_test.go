package secretfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func TestLoadOrCreateCreatesPrivateFileAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.bin")
	first, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	})
	if err != nil {
		t.Fatalf("LoadOrCreate create: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created secret: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("created mode = %o, want 0600", got)
	}
	second, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		t.Fatal("generator should not run for existing file")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("LoadOrCreate reload: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("reload = %q, want %q", second, first)
	}
}

func TestLoadRejectsUnsafeExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not model Unix custody")
	}
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := secretfile.Load(path); err == nil {
		t.Fatal("Load accepted a group/world-readable secret file")
	}
}

func TestLoadRejectsUnsafeParentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not model Unix custody")
	}
	dir := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := secretfile.Load(path); err == nil {
		t.Fatal("Load accepted a secret below a group/world-writable directory")
	}
}

func TestLoadAllowsPrivateSecretBelowStickyTempRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not model Unix custody")
	}
	root := filepath.Clean(os.TempDir())
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat temp root: %v", err)
	}
	if info.Mode()&os.ModeSticky == 0 {
		t.Skipf("%s is not sticky; this platform has no Unix temp-root custody case", root)
	}
	path := filepath.Join(t.TempDir(), "secret.bin")
	if _, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	}); err != nil {
		t.Fatalf("LoadOrCreate below sticky temp root: %v", err)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink privileges vary by environment")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secret.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secretfile.Load(link); err == nil {
		t.Fatal("Load accepted a symlink secret file")
	}
}

func TestLoadRejectsNonRegularFile(t *testing.T) {
	if _, err := secretfile.Load(t.TempDir()); err == nil {
		t.Fatal("Load accepted a directory as a secret file")
	}
}

func TestSecretFileWipeKeepsBufferAlive(t *testing.T) {
	src, err := os.ReadFile("secretfile.go")
	if err != nil {
		t.Fatalf("read secretfile.go: %v", err)
	}
	for _, want := range []string{
		"func wipe(b []byte)",
		"b[i] = 0",
		"runtime.KeepAlive(b)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("secretfile.go no longer contains %q; generated secret zeroization may have regressed", want)
		}
	}
}
