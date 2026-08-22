// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommittedRuntimeRunnerIdentityMatchesExactClosure(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, profile := range manifest.BuildProfiles {
		if evidence := inspectRuntimeRunnerProof(repo, profile); !evidence.OK {
			t.Errorf("build profile %s runtime runner: %s", name, evidence.Detail)
		}
	}
}

func TestRuntimeRunnerDockerHostArgsPreserveDesktopDNS(t *testing.T) {
	got, err := runtimeRunnerDockerHostArgs("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "--network bridge" {
		t.Fatalf("Darwin Docker host args = %v, want Docker Desktop bridge/DNS", got)
	}
	got, err = runtimeRunnerDockerHostArgs("linux")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "--network host --add-host host.docker.internal:127.0.0.1" {
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

func TestRuntimeRunnerRootFilesystemIsReadOnlyAndPrivilegeBootstrapIsBounded(t *testing.T) {
	want := []string{
		"--read-only",
		"--cap-drop", "ALL",
		"--cap-add", "CHECKPOINT_RESTORE",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "SETPCAP",
		"--security-opt", "no-new-privileges",
		"--user", "0:0",
	}
	if got := runtimeRunnerIsolationArgs(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("runtime runner isolation args = %v, want exact %v", got, want)
	}
	dropWant := []string{
		"--reuid=501",
		"--regid=20",
		"--groups=1234",
		"--inh-caps=+checkpoint_restore,+setgid",
		"--ambient-caps=+checkpoint_restore,+setgid",
		"--bounding-set=-all,+checkpoint_restore,+setgid",
	}
	if got := runtimeRunnerPrivilegeDropArgs(501, 20, 1234); strings.Join(got, "\n") != strings.Join(dropWant, "\n") {
		t.Fatalf("runtime runner privilege-drop args = %v, want exact %v", got, dropWant)
	}
}

func TestRuntimeRunnerScratchMountsBoundedTmpfsAndShortReceiptAlias(t *testing.T) {
	receiptDir := "/private/tmp/" + strings.Repeat("very-long-host-receipt-path-", 8)
	got := runtimeRunnerScratchArgs(receiptDir)
	want := []string{
		"--mount", "type=bind,src=" + receiptDir + ",dst=" + receiptDir,
		"--mount", "type=bind,src=" + receiptDir + ",dst=/dod-tmp",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=2g,mode=1777",
		"--env", "HOME=/dod-tmp",
		"--env", "TMPDIR=/dod-tmp",
		"--env", "TRSTCTL_DOD_HOST_RECEIPT_ROOT=" + receiptDir,
		"--env", "TRSTCTL_DOD_RUNTIME_TEMP_ROOT=/dod-tmp",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("runtime scratch argv = %v, want exact %v", got, want)
	}
	if socket := filepath.Join("/dod-tmp", "TestDODManagedKeyProductionAssembly", "001", "signer.sock"); len(socket) >= 108 {
		t.Fatalf("short-alias signer socket path is %d bytes: %s", len(socket), socket)
	}
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "HOME="+receiptDir) || strings.Contains(joined, "TMPDIR="+receiptDir) {
		t.Fatal("long host receipt path leaked back into HOME/TMPDIR")
	}
}

func TestRuntimeRunnerGoEnvironmentIsClosedAndOffline(t *testing.T) {
	profile := BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64"}
	got := runtimeRunnerGoEnvironment(profile, "/private/cache")
	want := []string{
		"--env", "CGO_ENABLED=0",
		"--env", "GOOS=linux",
		"--env", "GOARCH=amd64",
		"--env", "GOCACHE=/private/cache",
		"--env", "TRSTCTL_DOD_SHIPPED_GOCACHE=/private/cache",
		"--env", "GOMODCACHE=/go/pkg/mod",
		"--env", "GOPROXY=off",
		"--env", "GOSUMDB=off",
		"--env", "GOPRIVATE=",
		"--env", "GONOPROXY=",
		"--env", "GONOSUMDB=",
		"--env", "GOENV=off",
		"--env", "GOTELEMETRY=off",
		"--env", "GOTOOLCHAIN=local",
		"--env", "GOWORK=off",
		"--env", "GOFLAGS=-mod=readonly",
		"--env", "PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("pinned runner Go environment = %v, want exact closed environment %v", got, want)
	}
}

func TestRuntimeRunnerWritableDirRequiresPrivateHostOwnership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runner")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid())); err != nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatalf("private owner directory rejected: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid())); err == nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatal("world-visible runner directory passed")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(dir, uint32(os.Getuid()+1)); err == nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatal("foreign-owned runner directory passed")
	}
	link := filepath.Join(t.TempDir(), "runner-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeRunnerWritableDir(link, uint32(os.Getuid())); err == nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatal("symlink runner directory passed")
	}
}

func TestRuntimeRunnerCacheMountKeepsDarwinCacheBelowPrivateBoundary(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(parent, "go-build")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := runtimeRunnerCacheMountDir(cache, "darwin", uint32(os.Getuid())) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err != nil {
		t.Fatalf("private Darwin cache boundary rejected: %v", err)
	}
	if got != parent {
		t.Fatalf("Darwin cache mount = %q, want private parent %q", got, parent)
	}

	sibling := filepath.Join(parent, "unrelated")
	if err := os.WriteFile(sibling, []byte("must not be exposed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeRunnerCacheMountDir(cache, "darwin", uint32(os.Getuid())); err == nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatal("Darwin cache parent containing an unrelated sibling passed")
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if _, err := runtimeRunnerCacheMountDir(cache, "darwin", uint32(os.Getuid())); err == nil { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatal("world-visible Darwin cache parent passed")
	}
}

func TestRuntimeRunnerCacheMountUsesExactCacheOnNativeLinux(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "go-build")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := runtimeRunnerCacheMountDir(cache, "linux", uint32(os.Getuid())) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err != nil {
		t.Fatal(err)
	}
	if got != cache {
		t.Fatalf("Linux cache mount = %q, want exact cache %q", got, cache)
	}
}

func TestHostDockerCommandBoundaryIsClosed(t *testing.T) {
	for _, command := range []string{"build", "context", "image", "network", "run"} {
		if err := validateHostCommand("docker", []string{command, "reviewed-argument"}); err != nil {
			t.Errorf("reviewed Docker command %s rejected: %v", command, err)
		}
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "bash", args: []string{"-c", "docker run"}},
		{name: "docker", args: []string{"buildx", "imagetools", "inspect", "golang:latest"}},
		{name: "docker", args: []string{"exec", "container", "command"}},
		{name: "docker", args: []string{"run", "unsafe\nargument"}},
		{name: "docker"},
	} {
		if err := validateHostCommand(test.name, test.args); err == nil {
			t.Errorf("unreviewed host command passed: %q %q", test.name, test.args)
		}
	}
}

func TestRuntimeRunnerBaseReferenceIsExactAndToolchainBound(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "go.mod", "module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26.6\n", 0o600)
	valid := "golang:1.26.6-bookworm@sha256:" + strings.Repeat("a", 64) + "\n"
	writeFile(t, repo, runtimeRunnerBaseFile, valid, 0o600)
	if got, err := runtimeRunnerBaseReference(repo); err != nil || got != strings.TrimSuffix(valid, "\n") {
		t.Fatalf("valid committed runner base = %q err=%v", got, err)
	}

	invalid := []string{
		"golang:1.26.6-bookworm\n",
		"golang@sha256:" + strings.Repeat("a", 64) + "\n",
		"golang:1.26.5-bookworm@sha256:" + strings.Repeat("a", 64) + "\n",
		"golang:latest@sha256:" + strings.Repeat("a", 64) + "\n",
		"golang:1.26.6-alpine@sha256:" + strings.Repeat("a", 64) + "\n",
		"docker.io/library/golang:1.26.6-bookworm@sha256:" + strings.Repeat("a", 64) + "\n",
		"golang:1.26.6-bookworm@sha256:" + strings.Repeat("A", 64) + "\n",
		"golang:1.26.6-bookworm@sha256:" + strings.Repeat("a", 64),
		"golang:1.26.6-bookworm@sha256:" + strings.Repeat("a", 64) + "\n\n",
	}
	for index, value := range invalid {
		if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(runtimeRunnerBaseFile)), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := runtimeRunnerBaseReference(repo); err == nil {
			t.Errorf("invalid base[%d] passed as %q", index, got)
		}
	}
}

func TestRuntimeRunnerGoVersionRejectsCommentSpoofAndMalformedToolchain(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "go.mod")
	valid := "module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26.6\n"
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := runtimeRunnerGoVersion(repo); err != nil || got != "1.26.6" {
		t.Fatalf("valid toolchain version = %q err=%v", got, err)
	}
	for index, value := range []string{
		"module fixture.example/runtime\n\ngo 1.26\n// toolchain go1.26.6\n",
		"module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26.5\ntoolchain go1.26.6\n",
		"module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26\n",
		"module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26.6rc1\n",
		"module fixture.example/runtime\n\ngo 1.26\ntoolchain default\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := runtimeRunnerGoVersion(repo); err == nil {
			t.Errorf("invalid go.mod[%d] passed with version %q", index, got)
		}
	}
}

func TestRuntimeRunnerClosureRejectsMissingAndRehashedInvalidBasePin(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "missing digest", value: "golang:1.26.6-bookworm\n"},
		{name: "wrong version", value: "golang:1.26.5-bookworm@sha256:" + strings.Repeat("c", 64) + "\n"},
		{name: "moving tag", value: "golang:latest@sha256:" + strings.Repeat("c", 64) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			manifest := validManifest(t, repo, enforcementRequired)
			profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
			if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(runtimeRunnerBaseFile)), []byte(test.value), 0o600); err != nil {
				t.Fatal(err)
			}
			digest, err := commandIdentityDigest(repo, profile.RuntimeRunner.IdentityFiles)
			if err != nil {
				t.Fatal(err)
			}
			prefix, _, _ := strings.Cut(profile.RuntimeRunner.Identity, "@")
			profile.RuntimeRunner.Identity = prefix + "@" + digest
			if evidence := inspectRuntimeRunnerProof(repo, profile); evidence.OK {
				t.Fatalf("rehashed invalid base pin passed: %+v", evidence)
			}
		})
	}

	repo := t.TempDir()
	manifest := validManifest(t, repo, enforcementRequired)
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	if err := os.Remove(filepath.Join(repo, filepath.FromSlash(runtimeRunnerBaseFile))); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectRuntimeRunnerProof(repo, profile); evidence.OK {
		t.Fatalf("missing base pin passed: %+v", evidence)
	}

	repo = t.TempDir()
	manifest = validManifest(t, repo, enforcementRequired)
	profile = manifest.BuildProfiles[manifest.DefaultBuildProfile]
	basePath := filepath.Join(repo, filepath.FromSlash(runtimeRunnerBaseFile))
	raw, err := os.ReadFile(basePath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(raw), strings.Repeat("b", 64), strings.Repeat("d", 64), 1)
	if err := os.WriteFile(basePath, []byte(mutated), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
		t.Fatal(err)
	}
	if evidence := inspectRuntimeRunnerProof(repo, profile); evidence.OK {
		t.Fatalf("unrehashed base digest mutation passed: %+v", evidence)
	}
}

func TestRuntimeRunnerPrepareUsesOnlyCommittedBaseAndExactPlatform(t *testing.T) {
	raw, err := os.ReadFile("runtime_runner.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`baseReference, err := runtimeRunnerBaseReference(repo)`,
		`"docker", "build", "--platform", profile.RuntimeRunner.Platform`,
		`"BASE_IMAGE="+baseReference`,
		`"docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}"`,
		`fields[1] != profile.RuntimeRunner.Platform`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("runner prepare omits committed-base/platform binding %q", required)
		}
	}
	for _, forbidden := range []string{`"buildx"`, `"imagetools"`, `baseTag :=`} {
		if strings.Contains(source, forbidden) {
			t.Errorf("runner prepare retains mutable base resolution %q", forbidden)
		}
	}
	repo := t.TempDir()
	manifest := validManifest(t, repo, enforcementRequired)
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	profile.GOARCH = "arm64"
	profile.RuntimeRunner.Platform = "linux/arm64"
	if evidence := inspectRuntimeRunnerProof(repo, profile); evidence.OK {
		t.Fatalf("self-consistent but unsupported arm64 runner profile passed: %+v", evidence)
	}
}

func TestRuntimeRunnerPreflightCoversBothWritesAndAuthenticatedBroker(t *testing.T) {
	for _, required := range []string{
		"os.geteuid() == 0",
		`TRSTCTL_DOD_PREFLIGHT_UID`,
		`TRSTCTL_DOD_PREFLIGHT_GID`,
		`TRSTCTL_DOD_PREFLIGHT_SOCKET_UID`,
		`TRSTCTL_DOD_PREFLIGHT_SOCKET_GID`,
		`expected_socket_uid == expected_uid or expected_socket_gid == expected_gid`,
		`os.getgroups() != [expected_socket_gid]`,
		`expected_capability = "0000010000000040"`,
		`("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")`,
		`process_status.get("NoNewPrivs") != "1"`,
		`process_status.get("Seccomp") != "2"`,
		`subprocess.Popen(["/usr/bin/sleep", "10"])`,
		`map_deadline = time.monotonic() + 2`,
		`map_probe.poll() is not None`,
		`pathlib.Path("/proc/%d/map_files/%s"`,
		`os.open(map_file, os.O_RDONLY)`,
		`os.read(descriptor, 4) != b"\x7fELF"`,
		`["/usr/local/go/bin/go", "version"]`,
		`go version go1.26.6 linux/amd64`,
		`kind_digest != "eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa"`,
		`"kind v0.31.0" not in kind_version`,
		`openssl_version.startswith("OpenSSL 3.5.7 ")`,
		`os.environ.get("OPENSSL_CONF") != "/dev/null"`,
		`b"ML-DSA-65" not in openssl_signatures`,
		`module_root = pathlib.Path("/go/pkg/mod")`,
		"metadata.st_uid != 0",
		"metadata.st_mode & 0o222",
		"stat.S_ISLNK",
		"checked > 250000",
		"onerror=fail_walk",
		"os.open(write_probe, os.O_WRONLY)",
		"except PermissionError",
		"TRSTCTL_DOD_PREFLIGHT_SHORT_TMP",
		"os.path.samefile(receipt_directory, short_directory)",
		"short runtime path does not share receipt bytes",
		`system_tmp = pathlib.Path("/tmp")`,
		"stat.S_IMODE(metadata.st_mode) != 0o1777",
		"capacity != 2 * 1024 * 1024 * 1024",
		"TRSTCTL_DOD_PREFLIGHT_CACHE",
		"TRSTCTL_DOD_PREFLIGHT_RECEIPTS",
		"TRSTCTL_DOD_PREFLIGHT_BROKER",
		"TRSTCTL_DOD_PREFLIGHT_TOKEN",
		"Authorization",
		"os.O_EXCL",
		"/var/run/docker.sock",
		`stat.S_ISSOCK(socket_metadata.st_mode)`,
		`socket_metadata.st_uid != expected_socket_uid`,
		`socket_metadata.st_gid != expected_socket_gid`,
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

func TestRuntimeRunnerClosureRejectsRehashedMutableModuleCache(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "runtime owns module cache", old: "chown -R 0:0 /go", replacement: "chown -R 65532:65532 /go"},
		{name: "runtime can write module cache", old: "chmod -R a-w /go", replacement: "chmod -R u+w /go"},
		{name: "ambient Go entrypoint", old: `ENTRYPOINT ["/usr/local/go/bin/go"]`, replacement: `ENTRYPOINT ["go"]`},
		{name: "comment-spoofed module download", old: "GOFLAGS=-mod=readonly go mod download all", replacement: "true # GOFLAGS=-mod=readonly go mod download all"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			manifest := validManifest(t, repo, enforcementRequired)
			profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
			path := filepath.Join(repo, filepath.FromSlash(profile.RuntimeRunner.Dockerfile))
			raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), test.old, test.replacement, 1)
			if mutated == string(raw) {
				t.Fatalf("mutation anchor %q is absent", test.old)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
				t.Fatal(err)
			}
			digest, err := commandIdentityDigest(repo, profile.RuntimeRunner.IdentityFiles)
			if err != nil {
				t.Fatal(err)
			}
			prefix, _, ok := strings.Cut(profile.RuntimeRunner.Identity, "@")
			if !ok {
				t.Fatal("fixture runner identity has no digest separator")
			}
			profile.RuntimeRunner.Identity = prefix + "@" + digest
			if evidence := inspectRuntimeRunnerProof(repo, profile); evidence.OK {
				t.Fatalf("rehashed mutable runtime runner passed: %+v", evidence)
			}
		})
	}
}

func TestRuntimeSocketIdentityUsesMountedContainerMetadata(t *testing.T) {
	for _, test := range []struct {
		raw              string
		wantUID, wantGID uint32
	}{
		{raw: "0 0 660 socket\n", wantUID: 0, wantGID: 0},
		{raw: "501 20 660 socket", wantUID: 501, wantGID: 20},
		{raw: "4294967295 4294967295 660 socket", wantUID: ^uint32(0), wantGID: ^uint32(0)},
	} {
		uid, gid, err := parseRuntimeSocketIdentity(test.raw)
		if err != nil || uid != test.wantUID || gid != test.wantGID {
			t.Errorf("parse socket identity %q = %d:%d err=%v, want %d:%d", test.raw, uid, gid, err, test.wantUID, test.wantGID)
		}
	}
	for _, invalid := range []string{"", "-1 0 660 socket", "0 -1 660 socket", "4294967296 0 660 socket", "root 0 660 socket", "0 root 660 socket", "0 1 640 socket", "0 1 662 socket", "0 1 660 regular file"} {
		if _, _, err := parseRuntimeSocketIdentity(invalid); err == nil {
			t.Errorf("invalid mounted socket identity %q passed", invalid)
		}
	}
}

func TestRuntimeRunnerNSSFilesMapOnlyValidatedNonRootOwner(t *testing.T) {
	dir := t.TempDir()
	passwdFile, groupFile, err := runtimeRunnerNSSFiles(dir, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile(passwdFile) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.ReadFile(groupFile) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
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
