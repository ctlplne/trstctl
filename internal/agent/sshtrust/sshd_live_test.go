// SPDX-License-Identifier: MPL-2.0

package sshtrust

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveLinuxSSHDIntegrationSmoke is the GA backstop for the SSH-trust rewrite:
// when explicitly enabled on a Linux runner with OpenSSH server installed, it
// applies trust against a live sshd, validates with stock sshd -t, reloads the
// daemon, and proves it is still accepting connections. It is opt-in because most
// developer machines and many unit-test runners do not run Linux sshd.
func TestLiveLinuxSSHDIntegrationSmoke(t *testing.T) {
	if !liveSSHDSmokeEnabled() {
		t.Skip("set TRSTCTL_LIVE_SSHD_SMOKE=1 or TRSTCTL_REQUIRE_LIVE_SSHD=1 to run the live Linux sshd smoke")
	}
	if runtime.GOOS != "linux" {
		t.Fatalf("live sshd smoke requires Linux, got %s", runtime.GOOS)
	}

	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatalf("live sshd smoke requires sshd on PATH: %v", err)
	}
	sshKeygenPath, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatalf("live sshd smoke requires ssh-keygen on PATH: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	runOpenSSHTool(t, ctx, sshKeygenPath, "-q", "-t", "ed25519", "-N", "", "-f", hostKeyPath)
	caKeyPath := filepath.Join(dir, "trstctl_ssh_ca")
	runOpenSSHTool(t, ctx, sshKeygenPath, "-q", "-t", "ed25519", "-N", "", "-f", caKeyPath)
	caPub, err := os.ReadFile(caKeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	port := freeTCPPort(t)
	cfgPath := filepath.Join(dir, "sshd_config")
	trustPath := filepath.Join(dir, "trusted_user_ca_keys")
	if err := os.WriteFile(cfgPath, []byte(liveSSHDConfig(port, hostKeyPath, filepath.Join(dir, "sshd.pid"))), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.CommandContext(ctx, sshdPath, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("initial sshd -t failed; live smoke runner is not usable: %v\n%s", err, out)
	}

	reloader, err := startLiveSSHD(ctx, t, sshdPath, cfgPath, port)
	if err != nil {
		t.Fatal(err)
	}

	applier, err := New("t-live-sshd", Config{
		FS:                    liveOSFS{},
		Reloader:              reloader,
		SSHDConfigPath:        cfgPath,
		TrustedUserCAKeysPath: trustPath,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := applier.AddCATrust(ctx, caPub)
	if err != nil {
		t.Fatalf("AddCATrust against live sshd failed: %v\nsshd log:\n%s", err, reloader.log())
	}
	if !changed {
		t.Fatal("first live AddCATrust reported no change")
	}
	if reloader.reloads != 1 {
		t.Fatalf("live sshd reloads = %d, want 1", reloader.reloads)
	}
	assertFileContains(t, trustPath, strings.TrimSpace(string(caPub)))
	assertFileContains(t, cfgPath, "TrustedUserCAKeys "+trustPath)
}

func liveSSHDSmokeEnabled() bool {
	return os.Getenv("TRSTCTL_LIVE_SSHD_SMOKE") != "" || os.Getenv("TRSTCTL_REQUIRE_LIVE_SSHD") != ""
}

type liveOSFS struct{}

func (liveOSFS) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func (liveOSFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}
func (liveOSFS) Remove(p string) error { return os.Remove(p) }
func (liveOSFS) Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
func (liveOSFS) WriteFileAtomic(p string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".trstctl-sshtrust-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

type liveSSHDReloader struct {
	sshdPath string
	cfgPath  string
	addr     string
	cmd      *exec.Cmd
	done     chan error
	logPath  string
	logFile  *os.File
	reloads  int
}

func startLiveSSHD(ctx context.Context, t *testing.T, sshdPath, cfgPath string, port int) (*liveSSHDReloader, error) {
	t.Helper()

	logPath := filepath.Join(filepath.Dir(cfgPath), "sshd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, sshdPath, "-D", "-e", "-f", cfgPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	r := &liveSSHDReloader{
		sshdPath: sshdPath,
		cfgPath:  cfgPath,
		addr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		cmd:      cmd,
		done:     make(chan error, 1),
		logPath:  logPath,
		logFile:  logFile,
	}
	go func() { r.done <- cmd.Wait() }()
	t.Cleanup(r.stop)

	if err := waitForTCP(ctx, r.addr, 5*time.Second); err != nil {
		return nil, fmt.Errorf("live sshd did not start on %s: %w\nsshd log:\n%s", r.addr, err, r.log())
	}
	return r, nil
}

func (r *liveSSHDReloader) Validate(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, r.sshdPath, "-t", "-f", r.cfgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sshd -t -f %s failed: %w: %s", r.cfgPath, err, out)
	}
	return nil
}

func (r *liveSSHDReloader) Reload(ctx context.Context) error {
	r.reloads++
	out, err := exec.CommandContext(ctx, "kill", "-HUP", strconv.Itoa(r.cmd.Process.Pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload live sshd with SIGHUP failed: %w: %s", err, out)
	}
	return waitForTCP(ctx, r.addr, 5*time.Second)
}

func (r *liveSSHDReloader) HealthCheck(ctx context.Context) error {
	return waitForTCP(ctx, r.addr, 5*time.Second)
}

func (r *liveSSHDReloader) stop() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		select {
		case <-r.done:
		case <-time.After(2 * time.Second):
		}
	}
	if r.logFile != nil {
		_ = r.logFile.Close()
	}
}

func (r *liveSSHDReloader) log() string {
	if r.logFile != nil {
		_ = r.logFile.Sync()
	}
	b, err := os.ReadFile(r.logPath)
	if err != nil {
		return fmt.Sprintf("read %s: %v", r.logPath, err)
	}
	return string(b)
}

func liveSSHDConfig(port int, hostKeyPath, pidPath string) string {
	return fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
StrictModes no
LogLevel ERROR
`, port, hostKeyPath, pidPath)
}

func runOpenSSHTool(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForTCP(ctx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		dialer := net.Dialer{Timeout: 100 * time.Millisecond}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for TCP %s: %w", addr, lastErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s missing %q:\n%s", path, want, b)
	}
}
