// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	dodproof "trstctl.com/trstctl/tools/dodcensus/proof"
)

var runtimeRunnerIdentityClosure = []string{
	"go.mod",
	"go.sum",
	"tools/dodcensus/Dockerfile.runtime-runner",
	"tools/dodcensus/runtime-runner-base.txt",
}

const runtimeRunnerBaseFile = "tools/dodcensus/runtime-runner-base.txt"

const (
	runtimeRunnerAuditCapabilities  = "checkpoint_restore,+setgid"
	runtimeRunnerAuditCapabilityHex = "0000010000000040"
)

func validateRuntimeRunnerProof(where string, profile BuildProfile) error {
	proof := profile.RuntimeRunner
	if proof.Dockerfile == "" || proof.Platform == "" || proof.Identity == "" {
		return fmt.Errorf("%s has no complete cross-host runtime runner", where)
	}
	if proof.Dockerfile != "tools/dodcensus/Dockerfile.runtime-runner" {
		return fmt.Errorf("%s runtime runner uses unreviewed Dockerfile %q", where, proof.Dockerfile)
	}
	if proof.Platform != profile.GOOS+"/"+profile.GOARCH || proof.Platform != "linux/amd64" {
		return fmt.Errorf("%s runtime runner platform %q does not exactly match supported shipped linux/amd64 profile", where, proof.Platform)
	}
	if !pinnedImagePattern.MatchString(proof.Identity) {
		return fmt.Errorf("%s runtime runner identity %q is not digest pinned", where, proof.Identity)
	}
	want := append([]string(nil), runtimeRunnerIdentityClosure...)
	got := append([]string(nil), proof.IdentityFiles...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		return fmt.Errorf("%s runtime runner identity_files = %v, want exact %v", where, got, want)
	}
	return nil
}

func inspectRuntimeRunnerProof(repo string, profile BuildProfile) checkEvidence {
	proof := profile.RuntimeRunner
	required := []string{
		"runtime_runner=" + proof.Identity,
		"runtime_runner_platform=" + proof.Platform,
		"runtime_runner_dockerfile=" + proof.Dockerfile,
	}
	required = append(required, proof.IdentityFiles...)
	evidence := checkEvidence{Required: required}
	if err := validateRuntimeRunnerProof("shipped build profile", profile); err != nil {
		evidence.Detail = err.Error()
		return evidence
	}
	digest, err := commandIdentityDigest(repo, proof.IdentityFiles)
	if err != nil {
		evidence.Detail = "runtime runner identity closure: " + err.Error()
		return evidence
	}
	if !strings.HasSuffix(proof.Identity, "@"+digest) {
		evidence.Detail = fmt.Sprintf("runtime runner identity does not bind closure digest %s", digest)
		return evidence
	}
	baseReference, err := runtimeRunnerBaseReference(repo)
	if err != nil {
		evidence.Detail = "runtime runner base pin: " + err.Error()
		return evidence
	}
	evidence.Required = append(evidence.Required, "runtime_runner_base="+baseReference)
	path, err := safeRepoPath(repo, proof.Dockerfile)
	if err != nil {
		evidence.Detail = err.Error()
		return evidence
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		evidence.Detail = "read runtime runner Dockerfile: " + err.Error()
		return evidence
	}
	source := string(raw)
	instructions := dockerInstructions(source)
	if err := requireNoDefaultDockerArg(source, "BASE_IMAGE"); err != nil {
		evidence.Detail = "runtime runner base: " + err.Error()
		return evidence
	}
	if err := requirePinnedAptSnapshot(source); err != nil {
		evidence.Detail = "runtime runner packages: " + err.Error()
		return evidence
	}
	for _, fragment := range []string{
		"ca-certificates docker.io git openssl python3",
		"KIND_VERSION=v0.31.0",
		"KIND_LINUX_AMD64_SHA256=eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa",
		"OPENSSL_VERSION=3.5.7",
		"OPENSSL_SOURCE_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8",
		"/usr/local/bin/openssl list -signature-algorithms",
		"OPENSSL_CONF=/dev/null",
		"COPY go.mod go.sum /runtime-modules/",
		"GOFLAGS=-mod=readonly go mod download all",
		"chown -R 0:0 /go",
		"chmod -R a-w /go",
		`ENTRYPOINT ["/usr/local/go/bin/go"]`,
	} {
		if !dockerInstructionsContain(instructions, fragment) {
			evidence.Detail = fmt.Sprintf("runtime runner omits required native proof input %q", fragment)
			return evidence
		}
	}
	for _, forbidden := range []string{
		"chown -R 65532:65532 /go",
		`ENTRYPOINT ["go"]`,
	} {
		if dockerInstructionsContain(instructions, forbidden) {
			evidence.Detail = fmt.Sprintf("runtime runner retains mutable/ambient toolchain input %q", forbidden)
			return evidence
		}
	}
	evidence.OK = true
	evidence.Found = append([]string(nil), evidence.Required...)
	evidence.Detail = "runtime runner base, package snapshot, module bytes, platform, and identity closure are pinned"
	return evidence
}

func dockerInstructionsContain(instructions []string, fragment string) bool {
	for _, instruction := range instructions {
		start := strings.Index(instruction, fragment)
		if start < 0 {
			continue
		}
		comment := strings.Index(instruction, " #")
		if comment < 0 || comment >= start {
			return true
		}
	}
	return false
}

type linuxRuntimeExecutor struct {
	mu     sync.Mutex
	images map[string]string
}

const runtimeRunnerPreflightScript = `import hashlib
import os
import pathlib
import socket
import stat
import subprocess
import time
import urllib.request

if os.geteuid() == 0:
    raise RuntimeError("runtime runner unexpectedly has root privileges")

expected_uid = int(os.environ["TRSTCTL_DOD_PREFLIGHT_UID"])
expected_gid = int(os.environ["TRSTCTL_DOD_PREFLIGHT_GID"])
expected_socket_uid = int(os.environ["TRSTCTL_DOD_PREFLIGHT_SOCKET_UID"])
expected_socket_gid = int(os.environ["TRSTCTL_DOD_PREFLIGHT_SOCKET_GID"])
if os.geteuid() != expected_uid or os.getegid() != expected_gid:
    raise RuntimeError("runtime runner identity is %d:%d, want %d:%d" % (
        os.geteuid(), os.getegid(), expected_uid, expected_gid,
    ))
if os.getgroups() != [expected_socket_gid]:
    raise RuntimeError("runtime runner supplementary groups are %r, want only Docker socket gid %d" % (
        os.getgroups(), expected_socket_gid,
    ))
if expected_socket_uid == expected_uid or expected_socket_gid == expected_gid:
    raise RuntimeError("Docker socket owner/group overlaps the shipped process primary identity")

process_status = {}
for line in pathlib.Path("/proc/self/status").read_text().splitlines():
    key, separator, value = line.partition(":")
    if separator:
        process_status[key] = value.strip().split()[0]
expected_capability = "` + runtimeRunnerAuditCapabilityHex + `"
for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if process_status.get(field) != expected_capability:
        raise RuntimeError("runtime runner %s is %r, want only CAP_CHECKPOINT_RESTORE plus SETGID (%s)" % (
            field, process_status.get(field), expected_capability,
        ))
if process_status.get("NoNewPrivs") != "1":
    raise RuntimeError("runtime runner did not preserve no-new-privileges")
if process_status.get("Seccomp") != "2":
    raise RuntimeError("runtime runner is not confined by a seccomp filter")

# Capability masks alone do not prove that this kernel assigns map_files to
# CAP_CHECKPOINT_RESTORE. Exercise the exact operation used by the launched
# binary proof and reject old kernels rather than broadening to SYS_ADMIN.
map_probe = subprocess.Popen(["/usr/bin/sleep", "10"])
try:
    map_deadline = time.monotonic() + 2
    while True:
        map_rows = [
            line.split() for line in pathlib.Path("/proc/%d/maps" % map_probe.pid).read_text().splitlines()
            if "r-xp" in line and line.endswith("/usr/bin/sleep")
        ]
        if len(map_rows) == 1:
            break
        if map_probe.poll() is not None:
            raise RuntimeError("map_files preflight child exited before its executable map appeared")
        if time.monotonic() >= map_deadline:
            raise RuntimeError("map_files preflight found %d executable sleep mappings" % len(map_rows))
        time.sleep(0.01)
    map_file = pathlib.Path("/proc/%d/map_files/%s" % (map_probe.pid, map_rows[0][0]))
    descriptor = os.open(map_file, os.O_RDONLY)
    try:
        if os.read(descriptor, 4) != b"\x7fELF":
            raise RuntimeError("map_files preflight did not open the mapped ELF object")
    finally:
        os.close(descriptor)
finally:
    map_probe.terminate()
    map_probe.wait(timeout=5)

version = subprocess.run(
    ["/usr/local/go/bin/go", "version"],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env={"PATH": "/usr/local/go/bin:/usr/bin:/bin"},
).stdout.strip()
if version != "go version go1.26.5 linux/amd64":
    raise RuntimeError("runtime runner toolchain identity is %r" % version)

kind_path = pathlib.Path("/usr/local/bin/kind")
kind_digest = hashlib.sha256(kind_path.read_bytes()).hexdigest()
if kind_digest != "eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa":
    raise RuntimeError("runtime runner kind v0.31.0 digest is %r" % kind_digest)
kind_version = subprocess.run(
    [str(kind_path), "version"], check=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, text=True,
).stdout.strip()
if "kind v0.31.0" not in kind_version:
    raise RuntimeError("runtime runner kind identity is %r" % kind_version)

openssl_version = subprocess.run(
    ["/usr/local/bin/openssl", "version"], check=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, text=True,
).stdout.strip()
if not openssl_version.startswith("OpenSSL 3.5.7 "):
    raise RuntimeError("runtime runner OpenSSL identity is %r" % openssl_version)
if os.environ.get("OPENSSL_CONF") != "/dev/null":
    raise RuntimeError("runtime runner OpenSSL uses ambient configuration")
openssl_signatures = subprocess.run(
    ["/usr/local/bin/openssl", "list", "-signature-algorithms"], check=True,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
).stdout
if b"ML-DSA-65" not in openssl_signatures:
    raise RuntimeError("runtime runner OpenSSL omits ML-DSA-65")

module_root = pathlib.Path("/go/pkg/mod")
for parent in (pathlib.Path("/go"), pathlib.Path("/go/pkg"), module_root):
    metadata = os.lstat(parent)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o222:
        raise RuntimeError("baked module-cache parent is not root-owned and non-writable: %s" % parent)

checked = 0
write_probe = None
def fail_walk(error):
    raise error

for current, directories, files in os.walk(module_root, topdown=True, onerror=fail_walk, followlinks=False):
    for name in [""] + directories + files:
        path = pathlib.Path(current) if name == "" else pathlib.Path(current) / name
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o222:
            raise RuntimeError("baked module-cache entry is mutable, foreign-owned, or a symlink: %s" % path)
        checked += 1
        if checked > 250000:
            raise RuntimeError("baked module cache exceeds the reviewed entry bound")
        if write_probe is None and stat.S_ISREG(metadata.st_mode) and path.suffix == ".go":
            write_probe = path
if checked < 2 or write_probe is None:
    raise RuntimeError("baked module cache is empty or has no Go source")
try:
    descriptor = os.open(write_probe, os.O_WRONLY)
except PermissionError:
    pass
else:
    os.close(descriptor)
    raise RuntimeError("runtime UID can mutate baked module source: %s" % write_probe)

for variable in ("TRSTCTL_DOD_PREFLIGHT_CACHE", "TRSTCTL_DOD_PREFLIGHT_RECEIPTS"):
    directory = pathlib.Path(os.environ[variable])
    probe = directory / ".trstctl-dod-runner-preflight"
    descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"trstctl-dod-runner-preflight")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        probe.unlink()

receipt_directory = pathlib.Path(os.environ["TRSTCTL_DOD_PREFLIGHT_RECEIPTS"])
short_directory = pathlib.Path(os.environ["TRSTCTL_DOD_PREFLIGHT_SHORT_TMP"])
if not os.path.samefile(receipt_directory, short_directory):
    raise RuntimeError("short runtime path is not the private receipt mount")
short_probe = short_directory / ".trstctl-dod-short-path-preflight"
descriptor = os.open(short_probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, b"short-runtime-path")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if (receipt_directory / short_probe.name).read_bytes() != b"short-runtime-path":
    raise RuntimeError("short runtime path does not share receipt bytes")
short_probe.unlink()

system_tmp = pathlib.Path("/tmp")
metadata = os.stat(system_tmp)
capacity = os.statvfs(system_tmp).f_blocks * os.statvfs(system_tmp).f_frsize
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o1777 or capacity <= 0 or capacity > 64 * 1024 * 1024:
    raise RuntimeError("/tmp is not the bounded private 01777 tmpfs")
tmp_probe = system_tmp / ".trstctl-dod-tmpfs-preflight"
descriptor = os.open(tmp_probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.close(descriptor)
tmp_probe.unlink()

socket_metadata = os.stat("/var/run/docker.sock")
if (not stat.S_ISSOCK(socket_metadata.st_mode) or
        socket_metadata.st_uid != expected_socket_uid or
        socket_metadata.st_gid != expected_socket_gid or
        socket_metadata.st_mode & 0o020 == 0 or socket_metadata.st_mode & 0o002 != 0):
    raise RuntimeError("mounted Docker socket identity/mode changed after host inspection")
daemon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
daemon.settimeout(5)
try:
    daemon.connect("/var/run/docker.sock")
    daemon.sendall(b"GET /_ping HTTP/1.0\r\n\r\n")
    reply = daemon.recv(4096)
    if b"200 OK" not in reply or not reply.rstrip().endswith(b"OK"):
        raise RuntimeError("mounted Docker daemon did not answer _ping")
finally:
    daemon.close()

request = urllib.request.Request(os.environ["TRSTCTL_DOD_PREFLIGHT_BROKER"])
request.add_header("Authorization", "Bearer " + os.environ["TRSTCTL_DOD_PREFLIGHT_TOKEN"])
with urllib.request.urlopen(request, timeout=5) as response:
    if response.status != 204:
        raise RuntimeError("parent broker health status was %d" % response.status)
`

var reviewedHostDockerCommands = map[string]bool{
	"build":   true,
	"context": true,
	"image":   true,
	"network": true,
	"run":     true,
}

func newLinuxRuntimeExecutor() *linuxRuntimeExecutor {
	return &linuxRuntimeExecutor{images: map[string]string{}}
}

func (r *linuxRuntimeExecutor) prepare(ctx context.Context, repo string, profile BuildProfile) (string, error) {
	if evidence := inspectRuntimeRunnerProof(repo, profile); !evidence.OK {
		return "", fmt.Errorf("runtime runner proof: %s", evidence.Detail)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if image := r.images[profile.RuntimeRunner.Identity]; image != "" {
		return image, nil
	}
	baseReference, err := runtimeRunnerBaseReference(repo)
	if err != nil {
		return "", err
	}
	identityDigest := strings.TrimPrefix(profile.RuntimeRunner.Identity[strings.LastIndex(profile.RuntimeRunner.Identity, "@")+1:], "sha256:")
	tag := "trstctl-dod-runtime-runner:" + identityDigest[:16]
	built := runHostCommand(ctx, repo, "docker", "build", "--platform", profile.RuntimeRunner.Platform,
		"-f", profile.RuntimeRunner.Dockerfile, "--build-arg", "BASE_IMAGE="+baseReference, "-t", tag, ".")
	if built.Err != nil {
		return "", fmt.Errorf("build pinned runtime runner: %w: %s", built.Err, strings.TrimSpace(built.Stderr+built.Stdout))
	}
	inspected := runHostCommand(ctx, repo, "docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}", tag)
	if inspected.Err != nil {
		return "", fmt.Errorf("inspect pinned runtime runner: %w: %s", inspected.Err, strings.TrimSpace(inspected.Stderr+inspected.Stdout))
	}
	fields := strings.Fields(inspected.Stdout)
	if len(fields) != 2 || fields[1] != profile.RuntimeRunner.Platform {
		return "", fmt.Errorf("runtime runner inspect = %q, want image-id %s", strings.TrimSpace(inspected.Stdout), profile.RuntimeRunner.Platform)
	}
	image, err := parseContentImageID(fields[0])
	if err != nil {
		return "", fmt.Errorf("runtime runner image: %w", err)
	}
	r.images[profile.RuntimeRunner.Identity] = image
	return image, nil
}

func (r *linuxRuntimeExecutor) run(ctx context.Context, repo, cacheDir string, profile BuildProfile, args []string) commandResult {
	if r == nil || profile.RuntimeRunnerImage == "" {
		return commandResult{Err: fmt.Errorf("pinned runtime runner was not prepared"), ExitCode: -1}
	}
	if _, err := parseContentImageID(profile.RuntimeRunnerImage); err != nil {
		return commandResult{Err: fmt.Errorf("pinned runtime runner image: %w", err), ExitCode: -1}
	}
	receiptDir := profile.RuntimeScratchDir
	if receiptDir == "" {
		return commandResult{Err: fmt.Errorf("pinned runtime has no scoped receipt directory"), ExitCode: -1}
	}
	uid, gid, userSpec, err := runtimeRunnerHostUser(os.Getuid(), os.Getgid())
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return commandResult{Err: fmt.Errorf("create pinned runtime cache: %w", err), ExitCode: -1}
	}
	for name, path := range map[string]string{"cache": cacheDir, "receipt": receiptDir} {
		if err := validateRuntimeRunnerWritableDir(path, uid); err != nil {
			return commandResult{Err: fmt.Errorf("pinned runtime %s directory: %w", name, err), ExitCode: -1}
		}
	}
	socket, _, err := runtimeDockerSocket(ctx, repo)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	for _, path := range []string{repo, cacheDir, receiptDir, socket} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\r\n\x00") {
			return commandResult{Err: fmt.Errorf("runtime runner mount path %q is unsafe", path), ExitCode: -1}
		}
	}
	hostArgs, err := runtimeRunnerDockerHostArgs(runtime.GOOS)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	socketUID, socketGID, err := runtimeDockerSocketContainerIdentity(ctx, repo, profile.RuntimeRunnerImage, profile.RuntimeRunner.Platform, socket, userSpec)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	if socketUID == uid || socketGID == gid {
		return commandResult{Err: fmt.Errorf("docker socket owner/group overlaps the shipped process primary identity"), ExitCode: -1}
	}
	passwdFile, groupFile, err := runtimeRunnerNSSFiles(receiptDir, uid, gid)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	dockerArgs := []string{
		"run", "--rm", "--pull=never", "--platform", profile.RuntimeRunner.Platform,
	}
	dockerArgs = append(dockerArgs, hostArgs...)
	dockerArgs = append(dockerArgs, runtimeRunnerIsolationArgs()...)
	dockerArgs = append(dockerArgs,
		"--workdir", repo,
		"--mount", "type=bind,src="+repo+",dst="+repo+",readonly",
		"--mount", "type=bind,src="+cacheDir+",dst="+cacheDir,
		"--mount", "type=bind,src="+socket+",dst=/var/run/docker.sock",
		"--mount", "type=bind,src="+passwdFile+",dst=/etc/passwd,readonly",
		"--mount", "type=bind,src="+groupFile+",dst=/etc/group,readonly",
	)
	dockerArgs = append(dockerArgs, runtimeRunnerScratchArgs(receiptDir)...)
	dockerArgs = append(dockerArgs, runtimeRunnerGoEnvironment(profile, cacheDir)...)
	dockerArgs = append(dockerArgs,
		"--env", "DOCKER_HOST=unix:///var/run/docker.sock",
		"--env", "TRSTCTL_RUNTIME_DOCKER_HOST=host.docker.internal",
	)
	keys := make([]string, 0, len(profile.RuntimeEnv))
	for key := range profile.RuntimeEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		dockerArgs = append(dockerArgs, "--env", key+"="+profile.RuntimeEnv[key])
	}
	if profile.RuntimeBroker == nil || profile.RuntimeBroker.clientEndpoint() == "" || profile.RuntimeBroker.token == "" {
		return commandResult{Err: fmt.Errorf("pinned runtime has no authenticated parent broker"), ExitCode: -1}
	}
	preflightArgs := append([]string(nil), dockerArgs...)
	preflightArgs = append(preflightArgs,
		"--env", "TRSTCTL_DOD_PREFLIGHT_CACHE="+cacheDir,
		"--env", "TRSTCTL_DOD_PREFLIGHT_RECEIPTS="+receiptDir,
		"--env", "TRSTCTL_DOD_PREFLIGHT_SHORT_TMP="+dodproof.RuntimeTempDir,
		"--env", "TRSTCTL_DOD_PREFLIGHT_BROKER="+profile.RuntimeBroker.clientEndpoint()+"/healthz",
		"--env", "TRSTCTL_DOD_PREFLIGHT_TOKEN="+profile.RuntimeBroker.token,
		"--env", "TRSTCTL_DOD_PREFLIGHT_UID="+strconv.FormatUint(uint64(uid), 10),
		"--env", "TRSTCTL_DOD_PREFLIGHT_GID="+strconv.FormatUint(uint64(gid), 10),
		"--env", "TRSTCTL_DOD_PREFLIGHT_SOCKET_GID="+strconv.FormatUint(uint64(socketGID), 10),
		"--env", "TRSTCTL_DOD_PREFLIGHT_SOCKET_UID="+strconv.FormatUint(uint64(socketUID), 10),
		"--entrypoint", "/usr/bin/setpriv",
		profile.RuntimeRunnerImage,
	)
	preflightArgs = append(preflightArgs, runtimeRunnerPrivilegeDropArgs(uid, gid, socketGID)...)
	preflightArgs = append(preflightArgs, "/usr/bin/python3", "-c", runtimeRunnerPreflightProgram())
	preflight := runHostCommand(ctx, repo, "docker", preflightArgs...)
	if preflight.Err != nil {
		return commandResult{
			Stdout: preflight.Stdout, Stderr: preflight.Stderr, ExitCode: preflight.ExitCode,
			Err: fmt.Errorf("pinned runtime module-cache/write/Docker/broker preflight: %w", preflight.Err),
		}
	}
	dockerArgs = append(dockerArgs, "--entrypoint", "/usr/bin/setpriv", profile.RuntimeRunnerImage)
	dockerArgs = append(dockerArgs, runtimeRunnerPrivilegeDropArgs(uid, gid, socketGID)...)
	dockerArgs = append(dockerArgs, "/usr/local/go/bin/go")
	dockerArgs = append(dockerArgs, args...)
	return runHostCommand(ctx, repo, "docker", dockerArgs...)
}

func runtimeRunnerIsolationArgs() []string {
	// Docker discards capabilities when --user selects a non-root UID. Start the
	// pinned setpriv entrypoint with only the three capabilities needed to drop
	// identity/bounds plus CHECKPOINT_RESTORE, then exec the audit itself as the
	// host UID with CHECKPOINT_RESTORE and SETGID in every capability set. SETGID
	// exists only so the audit can clear its Docker-socket supplementary group
	// from the shipped child. The preflight verifies the exact final masks.
	return []string{
		"--read-only",
		"--cap-drop", "ALL",
		"--cap-add", "CHECKPOINT_RESTORE",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "SETPCAP",
		"--security-opt", "no-new-privileges",
		"--user", "0:0",
	}
}

func runtimeRunnerPrivilegeDropArgs(uid, gid, socketGID uint32) []string {
	return []string{
		"--reuid=" + strconv.FormatUint(uint64(uid), 10),
		"--regid=" + strconv.FormatUint(uint64(gid), 10),
		"--groups=" + strconv.FormatUint(uint64(socketGID), 10),
		"--inh-caps=+" + runtimeRunnerAuditCapabilities,
		"--ambient-caps=+" + runtimeRunnerAuditCapabilities,
		"--bounding-set=-all,+" + runtimeRunnerAuditCapabilities,
	}
}

func runtimeRunnerScratchArgs(receiptDir string) []string {
	return []string{
		"--mount", "type=bind,src=" + receiptDir + ",dst=" + receiptDir,
		"--mount", "type=bind,src=" + receiptDir + ",dst=" + dodproof.RuntimeTempDir,
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
		"--env", "HOME=" + dodproof.RuntimeTempDir,
		"--env", "TMPDIR=" + dodproof.RuntimeTempDir,
		"--env", dodproof.HostReceiptRootEnv + "=" + receiptDir,
		"--env", dodproof.RuntimeTempRootEnv + "=" + dodproof.RuntimeTempDir,
	}
}

func runtimeRunnerGoEnvironment(profile BuildProfile, cacheDir string) []string {
	values := []string{
		"CGO_ENABLED=" + profile.CGOEnabled,
		"GOOS=" + profile.GOOS,
		"GOARCH=" + profile.GOARCH,
		"GOCACHE=" + cacheDir,
		"GOMODCACHE=/go/pkg/mod",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOENV=off",
		"GOTELEMETRY=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOFLAGS=-mod=readonly",
		"PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	args := make([]string, 0, len(values)*2)
	for _, value := range values {
		args = append(args, "--env", value)
	}
	return args
}

func runtimeRunnerPreflightProgram() string {
	// The closed Docker argv boundary correctly rejects literal CR/LF bytes.
	// Encode the reviewed constant, then decode it inside Python; the argv value
	// stays one line and no test/manifest-controlled text becomes executable.
	encoded := base64.StdEncoding.EncodeToString([]byte(runtimeRunnerPreflightScript))
	return "import base64;exec(base64.b64decode('" + encoded + "'))"
}

func runtimeDockerSocketContainerIdentity(ctx context.Context, repo, image, platform, socket, userSpec string) (uint32, uint32, error) {
	args := []string{
		"run", "--rm", "--pull=never", "--platform", platform, "--network", "none",
		"--security-opt", "no-new-privileges", "--user", userSpec,
		"--mount", "type=bind,src=" + socket + ",dst=/var/run/docker.sock",
		"--entrypoint", "/usr/bin/stat", image, "-c", "%u %g %a %F", "/var/run/docker.sock",
	}
	result := runHostCommand(ctx, repo, "docker", args...)
	if result.Err != nil {
		return 0, 0, fmt.Errorf("inspect mounted Docker socket identity: %w: %s", result.Err, strings.TrimSpace(result.Stderr+result.Stdout))
	}
	return parseRuntimeSocketIdentity(result.Stdout)
}

func parseRuntimeSocketIdentity(raw string) (uint32, uint32, error) {
	fields := strings.Fields(raw)
	if len(fields) != 4 || fields[3] != "socket" {
		return 0, 0, fmt.Errorf("mounted Docker endpoint metadata %q is not an exact Unix socket", strings.TrimSpace(raw))
	}
	uid, uidErr := strconv.ParseUint(fields[0], 10, 32)
	gid, gidErr := strconv.ParseUint(fields[1], 10, 32)
	mode, modeErr := strconv.ParseUint(fields[2], 8, 12)
	if uidErr != nil || gidErr != nil || modeErr != nil || mode&0o020 == 0 || mode&0o002 != 0 {
		return 0, 0, fmt.Errorf("mounted Docker socket owner/group/mode %q is not a bounded group-write boundary", strings.TrimSpace(raw))
	}
	return uint32(uid), uint32(gid), nil
}

func runtimeRunnerNSSFiles(receiptDir string, uid, gid uint32) (string, string, error) {
	if uid == 0 {
		return "", "", fmt.Errorf("runtime runner NSS identity cannot be root")
	}
	if !filepath.IsAbs(receiptDir) || strings.ContainsAny(receiptDir, ":\r\n\x00") {
		return "", "", fmt.Errorf("runtime runner NSS home %q is unsafe", receiptDir)
	}
	passwd := "root:x:0:0:root:/root:/usr/sbin/nologin\n" +
		fmt.Sprintf("dodrunner:x:%d:%d:DoD runtime runner:%s:/usr/sbin/nologin\n", uid, gid, receiptDir)
	group := "root:x:0:\n"
	if gid != 0 {
		group += fmt.Sprintf("dodrunner:x:%d:\n", gid)
	}
	write := func(name, content string) (string, error) {
		path := filepath.Join(receiptDir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		if _, err := file.WriteString(content); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		return path, nil
	}
	passwdFile, err := write("runner.passwd", passwd)
	if err != nil {
		return "", "", fmt.Errorf("create scoped runner passwd: %w", err)
	}
	groupFile, err := write("runner.group", group)
	if err != nil {
		return "", "", fmt.Errorf("create scoped runner group: %w", err)
	}
	return passwdFile, groupFile, nil
}

func runtimeRunnerDockerHostArgs(hostOS string) ([]string, error) {
	switch hostOS {
	case "darwin":
		// Docker Desktop owns the host.docker.internal DNS record. Overriding it
		// with Linux's host-gateway token can resolve it inside the VM rather than
		// back to the macOS parent broker.
		return []string{"--network", "bridge"}, nil
	case "linux":
		// Native Linux has no Desktop proxy from the bridge gateway to host
		// loopback. Host networking plus an exact hosts entry preserves the
		// broker/emulator loopback boundary while making the container use the
		// same endpoints as the parent-owned proof processes.
		return []string{"--network", "host", "--add-host", "host.docker.internal:127.0.0.1"}, nil
	default:
		return nil, fmt.Errorf("pinned runtime runner does not support Docker host routing on %s", hostOS)
	}
}

func runtimeRunnerHostUser(uid, gid int) (uint32, uint32, string, error) {
	if uid <= 0 || uint64(uid) > uint64(^uint32(0)) {
		return 0, 0, "", fmt.Errorf("cross-host runtime requires a non-root host owner UID, got %d", uid)
	}
	if gid < 0 || uint64(gid) > uint64(^uint32(0)) {
		return 0, 0, "", fmt.Errorf("cross-host runtime has invalid host owner GID %d", gid)
	}
	return uint32(uid), uint32(gid), strconv.Itoa(uid) + ":" + strconv.Itoa(gid), nil
}

func validateRuntimeRunnerWritableDir(path string, owner uint32) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\r\n\x00") {
		return fmt.Errorf("path %q is unsafe", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is not a real directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%q mode %04o exposes the runner write boundary", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner {
		return fmt.Errorf("%q is not owned by runner UID %d", path, owner)
	}
	return nil
}

func runtimeRunnerGoVersion(repo string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read runtime runner go.mod: %w", err)
	}
	toolchain := ""
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "toolchain") {
			continue
		}
		fields := strings.Fields(line)
		if rawLine != line || len(fields) != 2 || fields[0] != "toolchain" || line != "toolchain "+fields[1] || toolchain != "" {
			return "", fmt.Errorf("go.mod toolchain directive is duplicated or not one exact active line")
		}
		toolchain = fields[1]
	}
	if !strings.HasPrefix(toolchain, "go") {
		return "", fmt.Errorf("go.mod has no exact toolchain directive")
	}
	version := strings.TrimPrefix(toolchain, "go")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("toolchain %q is not an exact three-component numeric Go version", toolchain)
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return "", fmt.Errorf("toolchain %q is not an exact three-component numeric Go version", toolchain)
		}
	}
	return version, nil
}

func runtimeRunnerBaseReference(repo string) (string, error) {
	path, err := safeRepoPath(repo, runtimeRunnerBaseFile)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect committed runtime runner base: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 256 {
		return "", fmt.Errorf("committed runtime runner base is not a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read committed runtime runner base: %w", err)
	}
	version, err := runtimeRunnerGoVersion(repo)
	if err != nil {
		return "", err
	}
	prefix := "golang:" + version + "-bookworm@"
	if len(raw) <= len(prefix)+1 || raw[len(raw)-1] != '\n' {
		return "", fmt.Errorf("runtime runner base must be exactly %ssha256:<64 lowercase hex> plus one newline", prefix)
	}
	value := string(raw[:len(raw)-1])
	if !strings.HasPrefix(value, prefix) {
		return "", fmt.Errorf("runtime runner base must be exactly %ssha256:<64 lowercase hex> plus one newline", prefix)
	}
	digest := value[len(prefix):]
	if !digestPattern.MatchString(digest) || string(raw) != prefix+digest+"\n" {
		return "", fmt.Errorf("runtime runner base digest %q is not exact lowercase sha256", digest)
	}
	return value, nil
}

func parseContentImageID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%q is not sha256:<64 lowercase hex>", value)
	}
	return value, nil
}

func runtimeDockerSocket(ctx context.Context, repo string) (string, uint32, error) {
	host := strings.TrimSpace(os.Getenv("DOCKER_HOST"))
	if host == "" {
		result := runHostCommand(ctx, repo, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
		if result.Err != nil {
			return "", 0, fmt.Errorf("inspect Docker socket: %w: %s", result.Err, strings.TrimSpace(result.Stderr+result.Stdout))
		}
		host = strings.TrimSpace(result.Stdout)
	}
	if !strings.HasPrefix(host, "unix://") {
		return "", 0, fmt.Errorf("runtime runner requires a local Unix Docker socket, got %q", host)
	}
	path := strings.TrimPrefix(host, "unix://")
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return "", 0, fmt.Errorf("docker endpoint %q is not an accessible Unix socket: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", 0, fmt.Errorf("cannot read Docker socket group for %q", path)
	}
	return path, stat.Gid, nil
}

func runHostCommand(ctx context.Context, dir, name string, args ...string) commandResult {
	if err := validateHostCommand(name, args); err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), Err: err}
	if err != nil {
		result.ExitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
	}
	return result
}

// validateHostCommand is the reviewed argv boundary for the parent-side Docker
// operations required by the census runner and broker. It never accepts a shell,
// an arbitrary executable, or a new Docker command without an explicit review.
func validateHostCommand(name string, args []string) error {
	if name != "docker" || len(args) == 0 || !reviewedHostDockerCommands[args[0]] {
		return fmt.Errorf("unreviewed DoD host command %q %q", name, args)
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("DoD host command contains an unsafe argument")
		}
	}
	return nil
}
