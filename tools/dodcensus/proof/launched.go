// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

const maxShippedBinaryBytes = 256 << 20

type shippedBuild struct {
	binDir   string
	binary   string
	identity executableIdentity
}

type executableIdentity struct {
	Device uint64
	Inode  uint64
	Links  uint64
	UID    uint32
	Size   int64
	Mode   os.FileMode
	Digest string
}

type processExecutableWitness struct {
	Mode              string
	Target            executableIdentity
	Interpreter       executableIdentity
	ProcessStartTicks uint64
	GuestMapDevice    string
}

const (
	processModeNative = "native"
	processModeBinfmt = "binfmt"
)

var shippedBuilds = struct {
	sync.Mutex
	items map[string]shippedBuild
}{items: map[string]shippedBuild{}}

// ShippedProcess is an opaque gate-owned build and live-process witness. Tests
// can configure the process, but cannot replace its binary, HTTP transport, or
// listener-ownership check.
type ShippedProcess struct {
	t      *testing.T
	expect expectation
	build  shippedBuild

	mu      sync.Mutex
	command *exec.Cmd
	done    chan struct{}
	logs    lockedBuffer
	stopped bool
	witness processExecutableWitness
}

type lockedBuffer struct {
	sync.Mutex
	value bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.value.Write(value)
}

func (b *lockedBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.value.String()
}

// launchedResponse is deliberately unexported. The only constructor is
// ShippedProcess.Do, which verifies the executable and its PID-owned listener.
type launchedResponse struct {
	id       string
	response *http.Response
	witness  launchedProcessReceipt
}

// BuildShippedProcess builds only the gate-issued cmd/trstctl package and its
// shipped companions. The sole variable linker input is the test license public
// key; callers cannot supply a package, overlay, build flag, output, or command.
func BuildShippedProcess(t *testing.T, id string, licensePublicKey []byte) *ShippedProcess {
	t.Helper()
	expected := expectationFor(t, id)
	if expected.RuntimeMode != "launched-binary" {
		t.Fatalf("DOD-CENSUS: %s is not a launched-binary expectation", id)
	}
	if !validSHA256Digest(expected.RuntimeRunnerImage) {
		t.Fatalf("DOD-CENSUS: %s has no exact content-addressed runtime runner image", id)
	}
	if len(licensePublicKey) == 0 || len(licensePublicKey) > 4096 {
		t.Fatalf("DOD-CENSUS: launched binary license public PEM size %d is invalid", len(licensePublicKey))
	}
	if _, err := internalcrypto.ParseEd25519PublicKeyPEM(licensePublicKey); err != nil {
		t.Fatalf("DOD-CENSUS: launched binary license public key is not one Ed25519 public PEM: %v", err)
	}
	build, err := buildShippedProcess(expected, licensePublicKey)
	if err != nil {
		t.Fatalf("DOD-CENSUS: build shipped process: %v", err)
	}
	return &ShippedProcess{t: t, expect: expected, build: build}
}

func buildShippedProcess(expected expectation, publicKey []byte) (shippedBuild, error) {
	if expected.LaunchedBinaryPackage != "./cmd/trstctl" || expected.LaunchedModulePath == "" ||
		expected.LaunchedGOOS != "linux" || expected.LaunchedGOARCH != "amd64" || expected.LaunchedCGOEnabled != "0" {
		return shippedBuild{}, fmt.Errorf("gate-issued launched binary profile is not exact static linux/amd64 cmd/trstctl")
	}
	if runtime.GOOS != expected.LaunchedGOOS || runtime.GOARCH != expected.LaunchedGOARCH {
		return shippedBuild{}, fmt.Errorf("launched build host %s/%s does not match gate profile %s/%s", runtime.GOOS, runtime.GOARCH, expected.LaunchedGOOS, expected.LaunchedGOARCH)
	}
	receiptDir := filepath.Dir(expected.EvidenceFile)
	if !filepath.IsAbs(expected.Repo) || !filepath.IsAbs(receiptDir) {
		return shippedBuild{}, fmt.Errorf("launched build has non-absolute repo/receipt path")
	}
	keyMaterial := strings.Join([]string{
		expected.Repo, receiptDir, expected.LaunchedModulePath, expected.LaunchedBinaryPackage,
		expected.LaunchedGOOS, expected.LaunchedGOARCH, expected.LaunchedCGOEnabled,
		strings.Join(expected.LaunchedTags, ","), strings.Join(expected.LaunchedCompanions, ","),
		base64.StdEncoding.EncodeToString(publicKey),
	}, "\x00")
	cacheKey := internalcrypto.SHA256Hex([]byte(keyMaterial))

	shippedBuilds.Lock()
	defer shippedBuilds.Unlock()
	if cached, ok := shippedBuilds.items[cacheKey]; ok {
		identity, err := validateShippedBinary(cached.binary, expected, expected.LaunchedBinaryPackage, false)
		if err != nil || identity != cached.identity {
			return shippedBuild{}, fmt.Errorf("cached launched binary changed: %v", err)
		}
		return cached, nil
	}
	binDir := filepath.Join(receiptDir, "shipped-process-"+cacheKey[:16])
	if err := os.Mkdir(binDir, 0o700); err != nil {
		return shippedBuild{}, fmt.Errorf("create exclusive launched build directory: %w", err)
	}
	if err := validatePrivateDirectory(binDir); err != nil {
		return shippedBuild{}, err
	}
	goTool, err := validateShippedGoToolchain()
	if err != nil {
		return shippedBuild{}, err
	}
	goCache := filepath.Join(receiptDir, "shipped-gocache-"+cacheKey[:16])
	if err := os.Mkdir(goCache, 0o700); err != nil {
		return shippedBuild{}, fmt.Errorf("create exclusive launched Go cache: %w", err)
	}
	if err := validatePrivateDirectory(goCache); err != nil {
		return shippedBuild{}, err
	}
	ldflags := "-X trstctl.com/trstctl/internal/license.builtinPubKeysB64=" + base64.StdEncoding.EncodeToString(publicKey)
	packages := append([]string{expected.LaunchedBinaryPackage}, expected.LaunchedCompanions...)
	seen := map[string]bool{}
	for _, packagePath := range packages {
		if seen[packagePath] {
			return shippedBuild{}, fmt.Errorf("duplicate launched package %q", packagePath)
		}
		seen[packagePath] = true
		name, err := shippedPackageName(packagePath)
		if err != nil {
			return shippedBuild{}, err
		}
		output := filepath.Join(binDir, name)
		args := []string{"build", "-trimpath", "-buildvcs=false", "-mod=readonly"}
		if len(expected.LaunchedTags) > 0 {
			args = append(args, "-tags="+strings.Join(expected.LaunchedTags, ","))
		}
		args = append(args, "-ldflags", ldflags, "-o", output, packagePath)
		command := exec.Command(goTool, args...)
		command.Dir = expected.Repo
		command.Env = shippedBuildEnvironment(expected, goCache)
		var outputLog bytes.Buffer
		command.Stdout, command.Stderr = &outputLog, &outputLog
		if err := command.Run(); err != nil {
			return shippedBuild{}, fmt.Errorf("go build %s: %w: %s", packagePath, err, strings.TrimSpace(outputLog.String()))
		}
		if _, err := validateShippedBinary(output, expected, packagePath, false); err != nil {
			return shippedBuild{}, err
		}
	}
	binary := filepath.Join(binDir, filepath.Base(expected.LaunchedBinaryPackage))
	identity, err := validateShippedBinary(binary, expected, expected.LaunchedBinaryPackage, false)
	if err != nil {
		return shippedBuild{}, err
	}
	result := shippedBuild{binDir: binDir, binary: binary, identity: identity}
	shippedBuilds.items[cacheKey] = result
	return result, nil
}

func shippedPackageName(packagePath string) (string, error) {
	if !strings.HasPrefix(packagePath, "./cmd/") || strings.Contains(packagePath, "..") {
		return "", fmt.Errorf("launched package %q is outside the reviewed cmd tree", packagePath)
	}
	name := filepath.Base(packagePath)
	if name == "." || name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
		return "", fmt.Errorf("launched package %q has an unsafe output name", packagePath)
	}
	return name, nil
}

func shippedBuildEnvironment(expected expectation, goCache string) []string {
	values := map[string]string{
		"GOCACHE":    goCache,
		"GOMODCACHE": "/go/pkg/mod",
		"GOPROXY":    "off",
		"GOSUMDB":    "off",
		"GOPRIVATE":  "",
		"GONOSUMDB":  "",
		"PATH":       "/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	values["CGO_ENABLED"] = expected.LaunchedCGOEnabled
	values["GOOS"] = expected.LaunchedGOOS
	values["GOARCH"] = expected.LaunchedGOARCH
	values["GOFLAGS"] = "-mod=readonly"
	values["GOENV"] = "off"
	values["GOTELEMETRY"] = "off"
	values["GOTOOLCHAIN"] = "local"
	values["GOWORK"] = "off"
	values["HOME"] = filepath.Dir(expected.EvidenceFile)
	values["TMPDIR"] = filepath.Dir(expected.EvidenceFile)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private launched directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("launched directory is not a caller-owned, non-symlink 0700 directory")
	}
	return nil
}

func shippedGoToolPath() string {
	return "/usr/local/go/bin/go"
}

func validateShippedGoToolchain() (string, error) {
	path := shippedGoToolPath()
	identity, build, err := inspectExecutable(path, false, true)
	if err != nil {
		return "", fmt.Errorf("inspect pinned Go toolchain: %w", err)
	}
	if identity.UID != 0 || build.Path != "cmd/go" || build.GoVersion != runtime.Version() {
		return "", fmt.Errorf("launched build Go toolchain does not match the root-owned running toolchain")
	}
	return path, nil
}

func validateShippedBinary(path string, expected expectation, packagePath string, followSymlink bool) (executableIdentity, error) {
	identity, build, err := inspectExecutable(path, followSymlink, true)
	if err != nil {
		return executableIdentity{}, fmt.Errorf("inspect launched binary %s: %w", packagePath, err)
	}
	if identity.UID != uint32(os.Geteuid()) {
		return executableIdentity{}, fmt.Errorf("launched binary %s is not owned by the runtime UID", packagePath)
	}
	wantImport := expected.LaunchedModulePath + "/" + strings.TrimPrefix(packagePath, "./")
	if build.Path != wantImport || build.Main.Path != expected.LaunchedModulePath {
		return executableIdentity{}, fmt.Errorf("launched binary lineage = %s module=%s, want %s module=%s", build.Path, build.Main.Path, wantImport, expected.LaunchedModulePath)
	}
	if build.GoVersion != runtime.Version() {
		return executableIdentity{}, fmt.Errorf("launched binary Go version %q does not match gate toolchain %q", build.GoVersion, runtime.Version())
	}
	settings := map[string]string{}
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != expected.LaunchedGOOS || settings["GOARCH"] != expected.LaunchedGOARCH || settings["CGO_ENABLED"] != expected.LaunchedCGOEnabled {
		return executableIdentity{}, fmt.Errorf("launched binary platform settings do not match gate profile")
	}
	wantTags := strings.Join(expected.LaunchedTags, ",")
	if settings["-tags"] != wantTags {
		return executableIdentity{}, fmt.Errorf("launched binary tags %q do not match gate tags %q", settings["-tags"], wantTags)
	}
	if settings["-trimpath"] != "true" {
		return executableIdentity{}, fmt.Errorf("launched binary is missing exact trimpath build setting")
	}
	return identity, nil
}

// inspectExecutable reads build information and bytes through the same open
// file description. The pre/post fstat comparison closes pathname-swap races;
// callers additionally bind the returned device/inode to their expected file.
func inspectExecutable(path string, followSymlink, requireBuildInfo bool) (executableIdentity, *buildinfo.BuildInfo, error) {
	lstat, err := os.Lstat(path)
	if err != nil {
		return executableIdentity{}, nil, err
	}
	if !followSymlink && lstat.Mode()&os.ModeSymlink != 0 {
		return executableIdentity{}, nil, fmt.Errorf("executable path is a symlink")
	}
	var file *os.File
	if followSymlink {
		file, err = os.Open(path)
	} else {
		var descriptor int
		descriptor, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == nil {
			file = os.NewFile(uintptr(descriptor), path)
		}
	}
	if err != nil || file == nil {
		return executableIdentity{}, nil, err
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil {
		return executableIdentity{}, nil, err
	}
	if !followSymlink && !os.SameFile(lstat, before) {
		return executableIdentity{}, nil, fmt.Errorf("executable pathname changed while opening")
	}
	identity, err := executableIdentityFromInfo(before)
	if err != nil {
		return executableIdentity{}, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o022 != 0 || before.Size() <= 0 || before.Size() > maxShippedBinaryBytes || identity.Links != 1 {
		return executableIdentity{}, nil, fmt.Errorf("executable is not a bounded, singly-linked, non-writable regular file")
	}
	var build *buildinfo.BuildInfo
	if requireBuildInfo {
		build, err = buildinfo.Read(file)
		if err != nil {
			return executableIdentity{}, nil, fmt.Errorf("read executable build info: %w", err)
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableIdentity{}, nil, err
	}
	digest, size, err := internalcrypto.SHA256ReaderHex(io.LimitReader(file, maxShippedBinaryBytes+1))
	if err != nil {
		return executableIdentity{}, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return executableIdentity{}, nil, err
	}
	afterIdentity, err := executableIdentityFromInfo(after)
	if err != nil {
		return executableIdentity{}, nil, err
	}
	if size != before.Size() || size > maxShippedBinaryBytes || identity != afterIdentity {
		return executableIdentity{}, nil, fmt.Errorf("executable changed while inspecting it")
	}
	identity.Digest = "sha256:" + digest
	return identity, build, nil
}

func executableIdentityFromInfo(info os.FileInfo) (executableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return executableIdentity{}, fmt.Errorf("executable has no Unix stat identity")
	}
	return executableIdentity{
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Links: uint64(stat.Nlink),
		UID: stat.Uid, Size: info.Size(), Mode: info.Mode(),
	}, nil
}

// CreateToken runs the exact built control binary in its one reviewed CLI mode.
func (p *ShippedProcess) CreateToken(directory string, environment []string, args ...string) string {
	p.t.Helper()
	if len(args) < 2 || args[0] != "token" || args[1] != "create" {
		p.t.Fatal("DOD-CENSUS: shipped process CLI accepts only token create")
	}
	if err := validateShippedArgs(args); err != nil {
		p.t.Fatal(err)
	}
	dir, env, err := p.processInputs(directory, environment)
	if err != nil {
		p.t.Fatal(err)
	}
	command := exec.Command(p.build.binary, args...)
	command.Dir, command.Env = dir, env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped token CLI: %v stderr=%s", err, stderr.String())
	}
	if stdout.Len() == 0 || stdout.Len() > maxEvidenceBody {
		p.t.Fatalf("DOD-CENSUS: shipped token CLI output size %d is invalid", stdout.Len())
	}
	return strings.TrimSpace(stdout.String())
}

// Start launches the exact built control binary with a clean, closed
// environment. The PATH begins with the gate-built companion directory.
func (p *ShippedProcess) Start(directory string, environment []string) {
	p.t.Helper()
	dir, env, err := p.processInputs(directory, environment)
	if err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	if p.command != nil {
		p.mu.Unlock()
		p.t.Fatal("DOD-CENSUS: shipped control plane started more than once")
	}
	command := exec.Command(p.build.binary)
	command.Dir, command.Env = dir, env
	command.Stdout, command.Stderr = &p.logs, &p.logs
	if err := command.Start(); err != nil {
		p.mu.Unlock()
		p.t.Fatalf("DOD-CENSUS: start shipped control plane: %v", err)
	}
	p.command = command
	p.done = make(chan struct{})
	go func() {
		_ = command.Wait()
		close(p.done)
	}()
	p.mu.Unlock()
	witness, err := inspectLiveProcess(command.Process.Pid, p.build, p.expect)
	if err != nil {
		_ = command.Process.Kill()
		p.t.Fatalf("DOD-CENSUS: launched process executable mismatch: %v", err)
	}
	if err := requireAllProcessSocketsExclusive(command.Process.Pid); err != nil {
		_ = command.Process.Kill()
		p.t.Fatalf("DOD-CENSUS: launched process inherited a foreign-owned socket: %v", err)
	}
	p.mu.Lock()
	p.witness = witness
	p.mu.Unlock()
	p.t.Cleanup(p.Stop)
}

func (p *ShippedProcess) processInputs(directory string, environment []string) (string, []string, error) {
	receiptDir := filepath.Dir(p.expect.EvidenceFile)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || !pathInside(receiptDir, resolved) {
		return "", nil, fmt.Errorf("DOD-CENSUS: shipped process working directory is outside the receipt boundary")
	}
	values := map[string]string{
		"HOME": receiptDir, "TMPDIR": receiptDir,
		"PATH": p.build.binDir + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !strings.HasPrefix(name, "TRSTCTL_") {
			continue
		}
		if strings.HasPrefix(name, "TRSTCTL_DOD_") || strings.ContainsAny(name+value, "\x00") {
			return "", nil, fmt.Errorf("DOD-CENSUS: shipped process environment contains a reserved/unsafe value")
		}
		if _, exists := values[name]; exists {
			return "", nil, fmt.Errorf("DOD-CENSUS: shipped process environment duplicates %s", name)
		}
		values[name] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return resolved, out, nil
}

func pathInside(root, candidate string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(resolvedRoot, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateShippedArgs(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("DOD-CENSUS: shipped process argument contains a forbidden byte")
		}
	}
	return nil
}

// Do sends the exact manifest method/path through a private direct transport.
// It rejects redirects and proves the launched PID owns the literal loopback
// listener before and after the response.
func (p *ShippedProcess) Do(request *http.Request) *launchedResponse {
	p.t.Helper()
	if request == nil || request.URL == nil || request.Method != p.expect.Method || request.URL.Path != p.expect.Path ||
		request.URL.Scheme != "http" || request.URL.Hostname() != "127.0.0.1" || request.URL.User != nil || request.URL.Fragment != "" ||
		request.URL.Opaque != "" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.RequestURI != "" ||
		(request.Host != "" && request.Host != request.URL.Host) {
		p.t.Fatalf("DOD-CENSUS: launched request does not match exact literal-loopback route %s %s", p.expect.Method, p.expect.Path)
	}
	port, err := strconv.Atoi(request.URL.Port())
	if err != nil || port < 1 || port > 65535 {
		p.t.Fatal("DOD-CENSUS: launched request has no exact loopback TCP port")
	}
	p.mu.Lock()
	command := p.command
	done := p.done
	expectedWitness := p.witness
	p.mu.Unlock()
	if command == nil || command.Process == nil || !processRunning(done) {
		p.t.Fatal("DOD-CENSUS: shipped control process is not live")
	}
	liveWitness, err := inspectLiveProcess(command.Process.Pid, p.build, p.expect)
	if err != nil || liveWitness != expectedWitness {
		p.t.Fatalf("DOD-CENSUS: live executable is not the unchanged gate-built control plane: %v", err)
	}
	inode, err := processLoopbackListener(command.Process.Pid, port)
	if err != nil {
		p.t.Fatalf("DOD-CENSUS: launched listener ownership: %v", err)
	}
	if err := requireExclusiveSocketOwner(command.Process.Pid, inode); err != nil {
		p.t.Fatalf("DOD-CENSUS: launched listener is shared with another process: %v", err)
	}
	var connection struct {
		local  *net.TCPAddr
		remote *net.TCPAddr
	}
	directRequest := request.Clone(context.Background())
	directRequest.Close = false
	directRequest.Header.Del("Connection")
	directRequest = directRequest.WithContext(httptrace.WithClientTrace(directRequest.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			local, localOK := info.Conn.LocalAddr().(*net.TCPAddr)
			remote, remoteOK := info.Conn.RemoteAddr().(*net.TCPAddr)
			if localOK && remoteOK {
				connection.local = local
				connection.remote = remote
			}
		},
	}))
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: false, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 40 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(directRequest)
	if err != nil {
		p.t.Fatalf("DOD-CENSUS: direct shipped-process request: %v; logs=%s", err, p.Logs())
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: launched response attempted redirect status %d", response.StatusCode)
	}
	acceptedInode, err := processAcceptedConnection(command.Process.Pid, connection.local, connection.remote)
	if err != nil {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: launched accepted-connection ownership: %v", err)
	}
	if err := requireExclusiveSocketOwner(command.Process.Pid, acceptedInode); err != nil {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: launched accepted connection is served by another process: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEvidenceBody+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) > maxEvidenceBody {
		p.t.Fatalf("DOD-CENSUS: launched response body is invalid/beyond the bounded evidence limit: read=%v close=%v size=%d", err, closeErr, len(body))
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	afterInode, err := processLoopbackListener(command.Process.Pid, port)
	afterWitness, witnessErr := inspectLiveProcess(command.Process.Pid, p.build, p.expect)
	exclusiveErr := requireExclusiveSocketOwner(command.Process.Pid, afterInode)
	if err != nil || afterInode != inode || witnessErr != nil || afterWitness != expectedWitness || exclusiveErr != nil || !processRunning(done) {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: shipped process/executable/listener changed during response: listener=%v executable=%v exclusive=%v", err, witnessErr, exclusiveErr)
	}
	processReceipt := launchedProcessReceipt{
		PID: command.Process.Pid, ProcessStartTicks: strconv.FormatUint(expectedWitness.ProcessStartTicks, 10),
		ProcessMode: expectedWitness.Mode, BinaryPackage: p.expect.LaunchedBinaryPackage,
		BinaryDigest: expectedWitness.Target.Digest, BinaryDevice: strconv.FormatUint(expectedWitness.Target.Device, 10),
		BinaryInode: strconv.FormatUint(expectedWitness.Target.Inode, 10),
		Address:     net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), ListenerInode: inode,
		AcceptedConnectionInode: acceptedInode,
	}
	if expectedWitness.Mode == processModeBinfmt {
		processReceipt.InterpreterDigest = expectedWitness.Interpreter.Digest
		processReceipt.InterpreterDevice = strconv.FormatUint(expectedWitness.Interpreter.Device, 10)
		processReceipt.InterpreterInode = strconv.FormatUint(expectedWitness.Interpreter.Inode, 10)
	}
	return &launchedResponse{
		id: p.expect.ID, response: response, witness: processReceipt,
	}
}

func processRunning(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

func inspectLiveProcess(pid int, built shippedBuild, expected expectation) (processExecutableWitness, error) {
	if runtime.GOOS != "linux" || pid <= 0 {
		return processExecutableWitness{}, fmt.Errorf("live process proof requires a positive Linux PID")
	}
	target, err := validateShippedBinary(built.binary, expected, expected.LaunchedBinaryPackage, false)
	if err != nil || target != built.identity {
		return processExecutableWitness{}, fmt.Errorf("private launched binary changed: %w", err)
	}
	startTicks, err := processStartTime(pid)
	if err != nil {
		return processExecutableWitness{}, err
	}
	procExecutable := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	procIdentity, _, err := inspectExecutable(procExecutable, true, false)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("inspect live process executable: %w", err)
	}
	if procIdentity == target {
		native, err := validateShippedBinary(procExecutable, expected, expected.LaunchedBinaryPackage, true)
		if err != nil || native != target {
			return processExecutableWitness{}, fmt.Errorf("native process does not execute the exact private binary: %w", err)
		}
		return processExecutableWitness{Mode: processModeNative, Target: target, ProcessStartTicks: startTicks}, nil
	}

	selfInterpreter, _, err := inspectExecutable("/proc/self/exe", true, false)
	if err != nil || procIdentity != selfInterpreter || procIdentity == target {
		return processExecutableWitness{}, fmt.Errorf("non-native process executable is not the exact gate-runner interpreter: %w", err)
	}
	runnerArgs, err := processCommandLine(os.Getpid())
	if err != nil || len(runnerArgs) == 0 || !filepath.IsAbs(runnerArgs[0]) || filepath.Clean(runnerArgs[0]) != runnerArgs[0] {
		return processExecutableWitness{}, fmt.Errorf("gate test runner has no exact absolute guest executable argv: %w", err)
	}
	runnerIdentity, runnerBuild, err := inspectExecutable(runnerArgs[0], false, true)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("inspect emulated gate test runner: %w", err)
	}
	if runnerIdentity.UID != uint32(os.Geteuid()) || runnerBuild.Main.Path != expected.LaunchedModulePath ||
		!strings.HasPrefix(runnerBuild.Path, expected.LaunchedModulePath+"/") || !strings.HasSuffix(runnerBuild.Path, ".test") ||
		runnerBuild.GoVersion != runtime.Version() {
		return processExecutableWitness{}, fmt.Errorf("emulation interpreter is not hosting the gate-issued Go test runner")
	}
	runnerSettings := map[string]string{}
	for _, setting := range runnerBuild.Settings {
		runnerSettings[setting.Key] = setting.Value
	}
	wantRunnerTags := append(append([]string(nil), expected.LaunchedTags...), "trstctl_dodproof")
	if runnerSettings["GOOS"] != expected.LaunchedGOOS || runnerSettings["GOARCH"] != expected.LaunchedGOARCH ||
		runnerSettings["CGO_ENABLED"] != expected.LaunchedCGOEnabled || runnerSettings["-tags"] != strings.Join(wantRunnerTags, ",") {
		return processExecutableWitness{}, fmt.Errorf("emulated gate test runner does not match the shipped platform/proof tags")
	}
	if _, err := validateBinfmtGuestBinding(os.Getpid(), runnerArgs[0], runnerIdentity, false); err != nil {
		return processExecutableWitness{}, fmt.Errorf("bind emulated gate test runner: %w", err)
	}
	mapDevice, err := validateBinfmtGuestBinding(pid, built.binary, target, true)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("bind emulated shipped binary: %w", err)
	}
	return processExecutableWitness{
		Mode: processModeBinfmt, Target: target, Interpreter: procIdentity,
		ProcessStartTicks: startTicks, GuestMapDevice: mapDevice,
	}, nil
}

func processStartTime(pid int) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, fmt.Errorf("read process start time: %w", err)
	}
	return parseProcessStartTime(raw)
}

func parseProcessStartTime(raw []byte) (uint64, error) {
	closing := bytes.LastIndex(raw, []byte(") "))
	if closing < 0 {
		return 0, fmt.Errorf("process stat has no final command delimiter")
	}
	fields := strings.Fields(string(raw[closing+2:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("process stat has %d suffix fields, want at least 20", len(fields))
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("process stat has invalid start time %q", fields[19])
	}
	return value, nil
}

func processCommandLine(pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody || raw[len(raw)-1] != 0 {
		return nil, fmt.Errorf("read bounded NUL-terminated process command line: %w", err)
	}
	parts := bytes.Split(raw[:len(raw)-1], []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 || bytes.ContainsAny(part, "\r\n\x00") {
			return nil, fmt.Errorf("process command line contains an empty/unsafe argument")
		}
		out = append(out, string(part))
	}
	return out, nil
}

func validateBinfmtGuestBinding(pid int, path string, identity executableIdentity, exactArgv bool) (string, error) {
	args, err := processCommandLine(pid)
	if err != nil || len(args) == 0 || args[0] != path || (exactArgv && len(args) != 1) {
		return "", fmt.Errorf("guest argv does not name only the exact private binary: %w", err)
	}
	mapDevice, err := validateGuestExecutableMaps(pid, path, identity)
	if err != nil {
		return "", err
	}
	if err := validateRosettaGuestDescriptors(pid, path, identity); err != nil {
		return "", err
	}
	return mapDevice, nil
}

func validateGuestExecutableMaps(pid int, path string, identity executableIdentity) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody {
		return "", fmt.Errorf("read bounded guest executable maps: %w", err)
	}
	device := ""
	mappings := 0
	executable := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != path {
			continue
		}
		if len(fields) != 6 || strings.Contains(line, " (deleted)") {
			return "", fmt.Errorf("guest executable map has a non-exact/deleted pathname")
		}
		inode, parseErr := strconv.ParseUint(fields[4], 10, 64)
		if parseErr != nil || inode != identity.Inode || !validProcMapDevice(fields[3]) {
			return "", fmt.Errorf("guest executable map does not bind the private binary inode/device")
		}
		if device == "" {
			device = fields[3]
		} else if device != fields[3] {
			return "", fmt.Errorf("guest executable maps disagree on device identity")
		}
		start, end, ok := strings.Cut(fields[0], "-")
		startValue, startErr := strconv.ParseUint(start, 16, 64)
		endValue, endErr := strconv.ParseUint(end, 16, 64)
		if !ok || startErr != nil || endErr != nil || startValue >= endValue {
			return "", fmt.Errorf("guest executable map has an invalid address range")
		}
		mapFile := filepath.Join("/proc", strconv.Itoa(pid), "map_files", fmt.Sprintf("%x-%x", startValue, endValue))
		target, linkErr := os.Readlink(mapFile)
		if linkErr != nil || target != path {
			return "", fmt.Errorf("kernel map_files entry does not name the exact private binary: %w", linkErr)
		}
		mappings++
		if strings.Contains(fields[1], "x") && fields[2] == "00000000" {
			executable = true
		}
	}
	if mappings < 2 || !executable || device == "" {
		return "", fmt.Errorf("guest process has no complete exact executable mapping")
	}
	return device, nil
}

func validProcMapDevice(value string) bool {
	major, minor, ok := strings.Cut(value, ":")
	if !ok || major == "" || minor == "" {
		return false
	}
	_, majorErr := strconv.ParseUint(major, 16, 32)
	_, minorErr := strconv.ParseUint(minor, 16, 32)
	return majorErr == nil && minorErr == nil
}

func validateRosettaGuestDescriptors(pid int, path string, identity executableIdentity) error {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return err
	}
	positions := map[uint64]bool{}
	matches := 0
	for _, entry := range entries {
		fd := entry.Name()
		fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", fd)
		target, readErr := os.Readlink(fdPath)
		if readErr != nil || target != path {
			continue
		}
		actual, _, inspectErr := inspectExecutable(fdPath, true, false)
		if inspectErr != nil || actual != identity {
			return fmt.Errorf("translator guest descriptor bytes are not the exact private binary: %w", inspectErr)
		}
		infoRaw, infoErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "fdinfo", fd))
		if infoErr != nil {
			return infoErr
		}
		position, flags, parseErr := parseTranslatorFDInfo(infoRaw)
		if parseErr != nil || flags != "0400040" || (position != 0 && position != 64) || positions[position] {
			return fmt.Errorf("translator guest descriptor has an unexpected position/flags invariant")
		}
		positions[position] = true
		matches++
	}
	if matches < 1 || matches > 2 || !positions[64] {
		return fmt.Errorf("translator does not hold the pinned digest-bound guest executable descriptor at position 64")
	}
	return nil
}

func parseTranslatorFDInfo(raw []byte) (uint64, string, error) {
	var position uint64
	flags := ""
	positionSeen := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "pos":
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, "", err
			}
			position, positionSeen = value, true
		case "flags":
			flags = fields[1]
		}
	}
	if !positionSeen || flags == "" {
		return 0, "", fmt.Errorf("descriptor info omits position/flags")
	}
	return position, flags, nil
}

func processLoopbackListener(pid, port int) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("PID-owned listener proof requires Linux /proc")
	}
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return "", err
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if readErr != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
	}
	wantPort := strings.ToUpper(fmt.Sprintf("%04x", port))
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" || !inodes[fields[9]] {
			continue
		}
		address, rawPort, ok := strings.Cut(fields[1], ":")
		if ok && address == "0100007F" && rawPort == wantPort {
			return fields[9], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("PID %d does not own 127.0.0.1:%d LISTEN", pid, port)
}

func processAcceptedConnection(pid int, clientLocal, clientRemote *net.TCPAddr) (string, error) {
	if clientLocal == nil || clientRemote == nil || !clientLocal.IP.IsLoopback() || !clientRemote.IP.IsLoopback() ||
		clientLocal.Port < 1 || clientRemote.Port < 1 {
		return "", fmt.Errorf("direct HTTP transport did not capture an exact loopback TCP tuple")
	}
	wantLocal, err := procTCPAddress(clientRemote)
	if err != nil {
		return "", err
	}
	wantRemote, err := procTCPAddress(clientLocal)
	if err != nil {
		return "", err
	}
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	found := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[1] != wantLocal || fields[2] != wantRemote || fields[3] != "01" {
			continue
		}
		if found != "" && found != fields[9] {
			return "", fmt.Errorf("direct HTTP tuple maps to multiple established server sockets")
		}
		found = fields[9]
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("launched server has no live reversed ESTABLISHED socket for the direct HTTP connection")
	}
	if err := processOwnsSocket(pid, found); err != nil {
		return "", err
	}
	return found, nil
}

func procTCPAddress(address *net.TCPAddr) (string, error) {
	ip := address.IP.To4()
	if ip == nil || address.Port < 1 || address.Port > 65535 {
		return "", fmt.Errorf("TCP tuple is not a valid IPv4 address")
	}
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], address.Port), nil
}

func processOwnsSocket(pid int, inode string) error {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return err
	}
	want := "socket:[" + inode + "]"
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if readErr == nil && target == want {
			return nil
		}
	}
	return fmt.Errorf("PID %d does not own socket inode %s", pid, inode)
}

func requireAllProcessSocketsExclusive(pid int) error {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return err
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return readErr
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	for inode := range inodes {
		if err := requireExclusiveSocketOwner(pid, inode); err != nil {
			return err
		}
	}
	return nil
}

func requireExclusiveSocketOwner(pid int, inode string) error {
	if pid <= 0 {
		return fmt.Errorf("socket owner PID is invalid")
	}
	if _, err := strconv.ParseUint(inode, 10, 64); err != nil || inode == "0" {
		return fmt.Errorf("socket inode %q is invalid", inode)
	}
	procInfo, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return err
	}
	procStat, ok := procInfo.Sys().(*syscall.Stat_t)
	if !ok || procStat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("launched PID is not owned by the gate runtime UID")
	}
	rootEntries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	want := "socket:[" + inode + "]"
	owners := map[int]bool{}
	for _, entry := range rootEntries {
		candidate, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || candidate <= 0 {
			continue
		}
		candidateRoot := filepath.Join("/proc", entry.Name())
		info, statErr := os.Stat(candidateRoot)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return statErr
		}
		stat, statOK := info.Sys().(*syscall.Stat_t)
		if !statOK || stat.Uid != procStat.Uid {
			continue
		}
		fds, readErr := os.ReadDir(filepath.Join(candidateRoot, "fd"))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return fmt.Errorf("scan same-UID PID %d descriptors: %w", candidate, readErr)
		}
		for _, fd := range fds {
			target, linkErr := os.Readlink(filepath.Join(candidateRoot, "fd", fd.Name()))
			if linkErr != nil {
				if os.IsNotExist(linkErr) {
					continue
				}
				return linkErr
			}
			if target == want {
				owners[candidate] = true
			}
		}
	}
	if len(owners) != 1 || !owners[pid] {
		return fmt.Errorf("socket inode %s same-UID owners = %v, want only PID %d", inode, sortedPIDs(owners), pid)
	}
	return nil
}

func sortedPIDs(values map[int]bool) []int {
	out := make([]int, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

// Logs returns a bounded copy of the shipped process diagnostics.
func (p *ShippedProcess) Logs() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	value := p.logs.String()
	if len(value) > maxEvidenceBody {
		value = value[len(value)-maxEvidenceBody:]
	}
	return value
}

// Stop interrupts and reaps the exact launched process. It is idempotent so a
// test may stop explicitly while the cleanup path remains a safety net.
func (p *ShippedProcess) Stop() {
	p.mu.Lock()
	if p.stopped || p.command == nil {
		p.stopped = true
		p.mu.Unlock()
		return
	}
	p.stopped = true
	command, done := p.command, p.done
	p.mu.Unlock()
	if !processRunning(done) {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}
