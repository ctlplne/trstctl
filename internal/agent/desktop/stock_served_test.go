// SPDX-License-Identifier: BUSL-1.1

package desktop

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/rdp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestDesktopStockViewerServed(t *testing.T) {
	helper := os.Getenv("TRSTCTL_RDP_HELPER")
	if helper == "" {
		if os.Getenv("TRSTCTL_REQUIRE_RDP_LAB") == "1" {
			t.Fatal("native desktop lab required")
		}
		t.Skip("native desktop lab not requested")
	}
	password, err := os.ReadFile("/run/rdp-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(password)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	native, err := rdp.Start(ctx, helper, rdp.Target{Address: "127.0.0.1:3389", Username: "desktop-proof", CertificateSHA256: os.Getenv("TRSTCTL_RDP_PIN"), Width: 800, Height: 600, TLSOnly: true}, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = native.Close() }()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	result := make(chan error, 1)
	var recorded atomic.Int64
	var blue atomic.Bool
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			result <- e
			return
		}
		result <- Serve(ctx, conn, native, func(_ context.Context, p rdp.Packet) error {
			recorded.Add(1)
			n := 0
			for i := 0; i < len(p.Pixels); i += 4 {
				if p.Pixels[i] == 128 && p.Pixels[i+1] == 0 && p.Pixels[i+2] == 0 {
					n++
				}
			}
			if n > 1000 {
				blue.Store(true)
			}
			return nil
		})
	}()
	display := ":93"
	xserver := exec.CommandContext(ctx, "/usr/bin/Xvfb", display, "-screen", "0", "1024x768x24", "-nolisten", "tcp", "-ac")
	if err = xserver.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = xserver.Process.Kill(); _ = xserver.Wait() }()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if _, e := os.Stat("/tmp/.X11-unix/X93"); e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	home := t.TempDir()
	viewer := exec.CommandContext(ctx, "/usr/bin/vncviewer", "-SecurityTypes=None", "-SendClipboard=0", "-AcceptClipboard=0", "-RemoteResize=0", "-PreferredEncoding=Raw", "-AutoSelect=0", "-FullColor=1", "-ReconnectOnError=0", "-AlertOnFatalError=0", fmt.Sprintf("127.0.0.1::%d", listener.Addr().(*net.TCPAddr).Port)) // #nosec G204 -- fixed viewer binary and loopback port allocated by this owned listener, no shell or credential arguments (CWE-78)
	viewer.Env = []string{"DISPLAY=" + display, "HOME=" + home, "LANG=C"}
	if err = viewer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = viewer.Process.Kill(); _ = viewer.Wait() }()
	command := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, "/usr/bin/xdotool", args...) // #nosec G204 -- test-built public keyboard/window arguments, fixed tool with no shell or upstream credential (CWE-78)
		c.Env = []string{"DISPLAY=" + display, "PATH=/usr/bin:/bin"}
		return c.Output()
	}
	var window string
	until = time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		raw, e := command("search", "--name", "trstctl approved desktop")
		if e == nil && len(strings.Fields(string(raw))) > 0 {
			window = strings.Fields(string(raw))[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if window == "" {
		t.Fatal("stock viewer did not open the desktop")
	}
	if _, e := strconv.ParseUint(window, 10, 32); e != nil {
		t.Fatal("invalid stock viewer window")
	}
	until = time.Now().Add(10 * time.Second)
	for time.Now().Before(until) && !blue.Load() {
		time.Sleep(20 * time.Millisecond)
	}
	if !blue.Load() || recorded.Load() == 0 {
		t.Fatal("native desktop pixels were not recorded before serving")
	}
	proofPath := fmt.Sprintf("/home/desktop-proof/stock-rfb-proof-%d", time.Now().UnixNano())
	defer func() {
		if e := os.Remove(proofPath); e != nil && !os.IsNotExist(e) {
			t.Error(e)
		}
	}()
	if _, err = command("windowfocus", window); err != nil {
		t.Fatal(err)
	}
	if _, err = command("type", "--window", window, "--clearmodifiers", "--delay", "10", "printf stock-viewer-proven > "+proofPath); err != nil {
		t.Fatal(err)
	}
	if _, err = command("key", "--window", window, "Return"); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(5 * time.Second)
	proven := false
	for time.Now().Before(until) {
		b, e := os.ReadFile(proofPath) // #nosec G304 -- owned unique task filename under the fixed lab account home (CWE-22)
		if e == nil && string(b) == "stock-viewer-proven" {
			proven = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !proven {
		select {
		case cause := <-result:
			t.Fatalf("stock input did not execute: %v", cause)
		default:
			t.Fatal("stock input did not execute target task")
		}
	}
	proc := fmt.Sprintf("/proc/%d", viewer.Process.Pid)
	for _, name := range []string{"cmdline", "environ"} {
		b, e := os.ReadFile(proc + "/" + name) // #nosec G304 -- exact child PID and fixed metadata filenames created by this test (CWE-22)
		if e != nil || bytes.Contains(b, password) {
			t.Fatal("upstream credential reached stock client metadata")
		}
	}
	root, e := os.OpenRoot(home)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = root.Close() }()
	if err = fs.WalkDir(root.FS(), ".", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type().IsRegular() {
			b, e := root.ReadFile(path)
			if e != nil {
				return e
			}
			if bytes.Contains(b, password) {
				return fmt.Errorf("upstream credential reached viewer file")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("desktop terminate did not close renderer and native backend")
	}
}
