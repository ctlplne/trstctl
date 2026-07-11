// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeRunnerDockerHostArgsPreserveDesktopDNS(t *testing.T) {
	got, err := runtimeRunnerDockerHostArgs("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Darwin Docker host args = %v, want Docker Desktop DNS unchanged", got)
	}
	got, err = runtimeRunnerDockerHostArgs("linux")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "--add-host host.docker.internal:host-gateway" {
		t.Fatalf("Linux Docker host args = %v", got)
	}
	if _, err := runtimeRunnerDockerHostArgs("windows"); err == nil {
		t.Fatal("unsupported Docker host routing passed")
	}
}

func TestRuntimeRunnerHostUserStaysNonRoot(t *testing.T) {
	uid, gid, spec, err := runtimeRunnerHostUser(501, 20)
	if err != nil || uid != 501 || gid != 20 || spec != "501:20" {
		t.Fatalf("host runner user = %d:%d %q err=%v", uid, gid, spec, err)
	}
	if _, _, _, err := runtimeRunnerHostUser(0, 0); err == nil {
		t.Fatal("root runtime runner user passed")
	}
	if _, _, _, err := runtimeRunnerHostUser(501, -1); err == nil {
		t.Fatal("negative runtime runner group passed")
	}
}

func TestRuntimeRunnerWritableDirRequiresPrivateHostOwnership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runner")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid())); err != nil {
		t.Fatalf("private owner directory rejected: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid())); err == nil {
		t.Fatal("world-visible runner directory passed")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid()+1)); err == nil {
		t.Fatal("foreign-owned runner directory passed")
	}
	link := filepath.Join(t.TempDir(), "runner-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(link, uint32(os.Getuid())); err == nil {
		t.Fatal("symlink runner directory passed")
	}
}

func TestHostDockerCommandBoundaryIsClosed(t *testing.T) {
	for _, command := range []string{"build", "buildx", "context", "image", "network", "run"} {
		if err := validateHostCommand("docker", []string{command, "reviewed-argument"}); err != nil {
			t.Errorf("reviewed Docker command %s rejected: %v", command, err)
		}
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "bash", args: []string{"-c", "docker run"}},
		{name: "docker", args: []string{"exec", "container", "command"}},
		{name: "docker", args: []string{"run", "unsafe\nargument"}},
		{name: "docker"},
	} {
		if err := validateHostCommand(test.name, test.args); err == nil {
			t.Errorf("unreviewed host command passed: %q %q", test.name, test.args)
		}
	}
}

func TestRuntimeRunnerPreflightCoversBothWritesAndAuthenticatedBroker(t *testing.T) {
	for _, required := range []string{
		"TRSTCTL_DOD_PREFLIGHT_CACHE",
		"TRSTCTL_DOD_PREFLIGHT_RECEIPTS",
		"TRSTCTL_DOD_PREFLIGHT_BROKER",
		"TRSTCTL_DOD_PREFLIGHT_TOKEN",
		"Authorization",
		"os.O_EXCL",
		"/var/run/docker.sock",
		"GET /_ping HTTP/1.0",
	} {
		if !strings.Contains(runtimeRunnerPreflightScript, required) {
			t.Errorf("runner preflight omits %q", required)
		}
	}
	program := runtimeRunnerPreflightProgram()
	if strings.ContainsAny(program, "\r\n") {
		t.Fatal("runner preflight command contains a line break rejected by the closed argv boundary")
	}
	if err := validateHostCommand("docker", []string{"run", "python3", "-c", program}); err != nil {
		t.Fatalf("encoded runner preflight was rejected: %v", err)
	}
}

func TestRuntimeSocketGroupUsesMountedContainerMetadata(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want uint32
	}{
		{raw: "0 660 socket\n", want: 0},
		{raw: "20 660 socket", want: 20},
		{raw: "4294967295 660 socket", want: ^uint32(0)},
	} {
		got, err := parseRuntimeSocketGID(test.raw)
		if err != nil || got != test.want {
			t.Errorf("parse socket GID %q = %d err=%v, want %d", test.raw, got, err, test.want)
		}
	}
	for _, invalid := range []string{"", "-1 660 socket", "4294967296 660 socket", "root 660 socket", "1 640 socket", "1 662 socket", "1 660 regular file"} {
		if _, err := parseRuntimeSocketGID(invalid); err == nil {
			t.Errorf("invalid mounted socket GID %q passed", invalid)
		}
	}
}

func TestRuntimeRunnerNSSFilesMapOnlyValidatedNonRootOwner(t *testing.T) {
	dir := t.TempDir()
	passwdFile, groupFile, err := runtimeRunnerNSSFiles(dir, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile(passwdFile)
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.ReadFile(groupFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(passwd) != "root:x:0:0:root:/root:/usr/sbin/nologin\ndodrunner:x:501:20:DoD runtime runner:"+dir+":/usr/sbin/nologin\n" {
		t.Fatalf("runner passwd = %q", passwd)
	}
	if string(group) != "root:x:0:\ndodrunner:x:20:\n" {
		t.Fatalf("runner group = %q", group)
	}
	for _, path := range []string{passwdFile, groupFile} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Errorf("NSS file %s: %v", path, statErr)
			continue
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("NSS file %s mode=%v", path, info.Mode().Perm())
		}
	}
	if _, _, err := runtimeRunnerNSSFiles(t.TempDir(), 0, 0); err == nil {
		t.Fatal("root NSS runner identity passed")
	}
	if _, _, err := runtimeRunnerNSSFiles("/tmp/unsafe:home", 501, 20); err == nil {
		t.Fatal("passwd-delimiter NSS home passed")
	}
}
