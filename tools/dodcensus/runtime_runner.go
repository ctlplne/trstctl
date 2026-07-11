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
)

var runtimeRunnerIdentityClosure = []string{
	"go.mod",
	"go.sum",
	"tools/dodcensus/Dockerfile.runtime-runner",
}

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
		"COPY go.mod go.sum /runtime-modules/",
		"GOFLAGS=-mod=readonly go mod download",
		`ENTRYPOINT ["go"]`,
	} {
		if !strings.Contains(source, fragment) {
			evidence.Detail = fmt.Sprintf("runtime runner omits required native proof input %q", fragment)
			return evidence
		}
	}
	evidence.OK = true
	evidence.Found = append([]string(nil), required...)
	evidence.Detail = "runtime runner base, package snapshot, module bytes, platform, and identity closure are pinned"
	return evidence
}

type linuxRuntimeExecutor struct {
	mu     sync.Mutex
	images map[string]string
}

const runtimeRunnerPreflightScript = `import os
import pathlib
import socket
import urllib.request

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
	"buildx":  true,
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
	version, err := runtimeRunnerGoVersion(repo)
	if err != nil {
		return "", err
	}
	baseTag := "golang:" + version + "-bookworm"
	resolved := runHostCommand(ctx, repo, "docker", "buildx", "imagetools", "inspect", baseTag, "--format", "{{.Manifest.Digest}}")
	if resolved.Err != nil {
		return "", fmt.Errorf("resolve runtime runner base %s: %w: %s", baseTag, resolved.Err, strings.TrimSpace(resolved.Stderr+resolved.Stdout))
	}
	baseDigest, err := parseContentImageID(resolved.Stdout)
	if err != nil {
		return "", fmt.Errorf("resolve runtime runner base %s: %w", baseTag, err)
	}
	identityDigest := strings.TrimPrefix(profile.RuntimeRunner.Identity[strings.LastIndex(profile.RuntimeRunner.Identity, "@")+1:], "sha256:")
	tag := "trstctl-dod-runtime-runner:" + identityDigest[:16]
	built := runHostCommand(ctx, repo, "docker", "build", "--platform", profile.RuntimeRunner.Platform,
		"-f", profile.RuntimeRunner.Dockerfile, "--build-arg", "BASE_IMAGE=golang@"+baseDigest, "-t", tag, ".")
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
		return commandResult{Err: fmt.Errorf("cross-host runtime runner was not prepared"), ExitCode: -1}
	}
	if _, err := parseContentImageID(profile.RuntimeRunnerImage); err != nil {
		return commandResult{Err: fmt.Errorf("cross-host runtime runner image: %w", err), ExitCode: -1}
	}
	receiptDir := profile.RuntimeScratchDir
	if receiptDir == "" {
		return commandResult{Err: fmt.Errorf("cross-host runtime has no scoped receipt directory"), ExitCode: -1}
	}
	uid, gid, userSpec, err := runtimeRunnerHostUser(os.Getuid(), os.Getgid())
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return commandResult{Err: fmt.Errorf("create cross-host runtime cache: %w", err), ExitCode: -1}
	}
	for name, path := range map[string]string{"cache": cacheDir, "receipt": receiptDir} {
		if err := validateRuntimeRunnerWritableDir(path, uid); err != nil {
			return commandResult{Err: fmt.Errorf("cross-host runtime %s directory: %w", name, err), ExitCode: -1}
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
	socketGID, err := runtimeDockerSocketContainerGID(ctx, repo, profile.RuntimeRunnerImage, profile.RuntimeRunner.Platform, socket, userSpec)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	passwdFile, groupFile, err := runtimeRunnerNSSFiles(receiptDir, uid, gid)
	if err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	dockerArgs := []string{
		"run", "--rm", "--pull=never", "--platform", profile.RuntimeRunner.Platform,
		"--network", "bridge",
	}
	dockerArgs = append(dockerArgs, hostArgs...)
	dockerArgs = append(dockerArgs,
		"--security-opt", "no-new-privileges", "--group-add", strconv.FormatUint(uint64(socketGID), 10),
		"--user", userSpec,
		"--workdir", repo,
		"--mount", "type=bind,src="+repo+",dst="+repo+",readonly",
		"--mount", "type=bind,src="+cacheDir+",dst="+cacheDir,
		"--mount", "type=bind,src="+receiptDir+",dst="+receiptDir,
		"--mount", "type=bind,src="+socket+",dst=/var/run/docker.sock",
		"--mount", "type=bind,src="+passwdFile+",dst=/etc/passwd,readonly",
		"--mount", "type=bind,src="+groupFile+",dst=/etc/group,readonly",
		"--env", "CGO_ENABLED="+profile.CGOEnabled,
		"--env", "GOOS="+profile.GOOS,
		"--env", "GOARCH="+profile.GOARCH,
		"--env", "GOCACHE="+cacheDir,
		"--env", "GOFLAGS=",
		"--env", "HOME="+receiptDir,
		"--env", "TMPDIR="+receiptDir,
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
		return commandResult{Err: fmt.Errorf("cross-host runtime has no authenticated parent broker"), ExitCode: -1}
	}
	preflightArgs := append([]string(nil), dockerArgs...)
	preflightArgs = append(preflightArgs,
		"--env", "TRSTCTL_DOD_PREFLIGHT_CACHE="+cacheDir,
		"--env", "TRSTCTL_DOD_PREFLIGHT_RECEIPTS="+receiptDir,
		"--env", "TRSTCTL_DOD_PREFLIGHT_BROKER="+profile.RuntimeBroker.clientEndpoint()+"/healthz",
		"--env", "TRSTCTL_DOD_PREFLIGHT_TOKEN="+profile.RuntimeBroker.token,
		"--entrypoint", "/usr/bin/python3",
		profile.RuntimeRunnerImage, "-c", runtimeRunnerPreflightProgram(),
	)
	preflight := runHostCommand(ctx, repo, "docker", preflightArgs...)
	if preflight.Err != nil {
		return commandResult{
			Stdout: preflight.Stdout, Stderr: preflight.Stderr, ExitCode: preflight.ExitCode,
			Err: fmt.Errorf("cross-host runtime write/Docker/broker preflight: %w", preflight.Err),
		}
	}
	dockerArgs = append(dockerArgs, profile.RuntimeRunnerImage)
	dockerArgs = append(dockerArgs, args...)
	return runHostCommand(ctx, repo, "docker", dockerArgs...)
}

func runtimeRunnerPreflightProgram() string {
	// The closed Docker argv boundary correctly rejects literal CR/LF bytes.
	// Encode the reviewed constant, then decode it inside Python; the argv value
	// stays one line and no test/manifest-controlled text becomes executable.
	encoded := base64.StdEncoding.EncodeToString([]byte(runtimeRunnerPreflightScript))
	return "import base64;exec(base64.b64decode('" + encoded + "'))"
}

func runtimeDockerSocketContainerGID(ctx context.Context, repo, image, platform, socket, userSpec string) (uint32, error) {
	args := []string{
		"run", "--rm", "--pull=never", "--platform", platform, "--network", "none",
		"--security-opt", "no-new-privileges", "--user", userSpec,
		"--mount", "type=bind,src=" + socket + ",dst=/var/run/docker.sock",
		"--entrypoint", "/usr/bin/stat", image, "-c", "%g %a %F", "/var/run/docker.sock",
	}
	result := runHostCommand(ctx, repo, "docker", args...)
	if result.Err != nil {
		return 0, fmt.Errorf("inspect mounted Docker socket group: %w: %s", result.Err, strings.TrimSpace(result.Stderr+result.Stdout))
	}
	return parseRuntimeSocketGID(result.Stdout)
}

func parseRuntimeSocketGID(raw string) (uint32, error) {
	fields := strings.Fields(raw)
	if len(fields) != 3 || fields[2] != "socket" {
		return 0, fmt.Errorf("mounted Docker endpoint metadata %q is not an exact Unix socket", strings.TrimSpace(raw))
	}
	parsed, err := strconv.ParseUint(fields[0], 10, 32)
	mode, modeErr := strconv.ParseUint(fields[1], 8, 12)
	if err != nil || modeErr != nil || mode&0o020 == 0 || mode&0o002 != 0 {
		return 0, fmt.Errorf("mounted Docker socket group/mode %q is not a bounded group-write boundary", strings.TrimSpace(raw))
	}
	return uint32(parsed), nil
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
		return nil, nil
	case "linux":
		return []string{"--add-host", "host.docker.internal:host-gateway"}, nil
	default:
		return nil, fmt.Errorf("cross-host runtime runner does not support Docker host routing on %s", hostOS)
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
	fields := strings.Fields(string(raw))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "toolchain" {
			continue
		}
		version := strings.TrimPrefix(fields[index+1], "go")
		if version == "" || strings.Trim(version, "0123456789.") != "" {
			return "", fmt.Errorf("toolchain %q is not an exact numeric Go version", fields[index+1])
		}
		return version, nil
	}
	return "", fmt.Errorf("go.mod has no exact toolchain directive")
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
