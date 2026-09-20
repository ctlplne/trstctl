//go:build !windows

// SPDX-License-Identifier: BUSL-1.1

package proof

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

const (
	runtimePrivilegeDropper     = "/usr/bin/setpriv"
	runtimeAuditCapabilityMask  = uint64(1)<<40 | uint64(1)<<6 // CAP_CHECKPOINT_RESTORE | CAP_SETGID
	runtimeZeroCapabilityString = "0000000000000000"
)

var errNoStableProcessSockets = errors.New("launched process has no stable socket to audit")

type shippedBuild struct {
	binDir     string
	binary     string
	identity   executableIdentity
	dropper    executableIdentity
	companions map[string]executableIdentity
	// companionFDIsolation is set only after the exact shipped supervisor
	// source proves os/exec receives no inherited descriptors above stderr and
	// the signer RPC tree contains no Unix FD-transfer primitive.
	companionFDIsolation bool
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
	processModeNative      = "native"
	processModeBinfmt      = "binfmt"
	rosettaInterpreterPath = "/run/rosetta/rosetta"
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
	watch  *artifactMutationWatch

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
	if !runtimeProfileExpectationComplete(expected) {
		t.Fatalf("DOD-CENSUS: %s has no exact runtime test build profile", id)
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
	watch, err := newArtifactMutationWatch(build.binDir)
	if err != nil {
		t.Fatalf("DOD-CENSUS: arm shipped-artifact mutation watch: %v", err)
	}
	process := &ShippedProcess{t: t, expect: expected, build: build, watch: watch}
	if err := process.revalidateBuiltArtifacts(); err != nil {
		_ = watch.Close()
		t.Fatalf("DOD-CENSUS: bind watched shipped artifacts: %v", err)
	}
	t.Cleanup(func() { _ = watch.Close() })
	return process
}

func (p *ShippedProcess) revalidateBuiltArtifacts() error {
	identity, err := validateShippedBinary(p.build.binary, p.expect, p.expect.LaunchedBinaryPackage, false)
	if err != nil {
		return fmt.Errorf("watched control binary changed: %w", err)
	}
	if identity != p.build.identity {
		return fmt.Errorf("watched control binary identity changed")
	}
	for packagePath, expected := range p.build.companions {
		name, nameErr := shippedPackageName(packagePath)
		if nameErr != nil {
			return nameErr
		}
		actual, validateErr := validateShippedBinary(filepath.Join(p.build.binDir, name), p.expect, packagePath, false)
		if validateErr != nil {
			return fmt.Errorf("watched companion %s changed: %w", packagePath, validateErr)
		}
		if actual != expected {
			return fmt.Errorf("watched companion %s identity changed", packagePath)
		}
	}
	return p.watch.AssertQuiet()
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
	runtimeTempDir, err := validateRuntimeTempDirectory(receiptDir)
	if err != nil {
		return shippedBuild{}, err
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
		dropper, err := validateRuntimePrivilegeDropper()
		if err != nil || dropper != cached.dropper {
			return shippedBuild{}, fmt.Errorf("cached runtime privilege dropper changed: %v", err)
		}
		return cached, nil
	}
	// Compile only in the runner's private tmpfs. Docker Desktop can deliver
	// delayed VirtioFS notifications for compiler output written directly into
	// the host-backed receipt mount. A watcher armed after go build then sees
	// those old writes as if the executable changed at runtime. Publishing
	// verified bytes into a fresh directory below makes the security boundary
	// exact: the compiler never opens a watched executable, while every write
	// after publication remains observable.
	stagingDir, err := os.MkdirTemp("/tmp", "trstctl-dod-build-")
	if err != nil {
		return shippedBuild{}, fmt.Errorf("create private launched build staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	if err := validatePrivateDirectory(stagingDir); err != nil {
		return shippedBuild{}, err
	}
	goTool, err := validateShippedGoToolchain()
	if err != nil {
		return shippedBuild{}, err
	}
	goCache, err := ensureShippedGoCache(receiptDir)
	if err != nil {
		return shippedBuild{}, err
	}
	ldflags := "-X trstctl.com/trstctl/internal/license.builtinPubKeysB64=" + base64.StdEncoding.EncodeToString(publicKey)
	packages := append([]string{expected.LaunchedBinaryPackage}, expected.LaunchedCompanions...)
	seen := map[string]bool{}
	stagedIdentities := make(map[string]executableIdentity, len(packages))
	for _, packagePath := range packages {
		if seen[packagePath] {
			return shippedBuild{}, fmt.Errorf("duplicate launched package %q", packagePath)
		}
		seen[packagePath] = true
		name, err := shippedPackageName(packagePath)
		if err != nil {
			return shippedBuild{}, err
		}
		output := filepath.Join(stagingDir, name)
		args := shippedBuildArguments(expected, ldflags, output, packagePath, descriptorPackageParallelism())
		command := exec.Command(goTool, args...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
		command.Dir = expected.Repo
		command.Env = shippedBuildEnvironment(expected, goCache, runtimeTempDir)
		var outputLog bytes.Buffer
		command.Stdout, command.Stderr = &outputLog, &outputLog
		if err := command.Run(); err != nil {
			return shippedBuild{}, fmt.Errorf("go build %s: %w: %s", packagePath, err, strings.TrimSpace(outputLog.String()))
		}
		identity, err := validateShippedBinary(output, expected, packagePath, false)
		if err != nil {
			return shippedBuild{}, err
		}
		stagedIdentities[packagePath] = identity
	}
	dropper, err := validateRuntimePrivilegeDropper()
	if err != nil {
		return shippedBuild{}, err
	}
	companionFDIsolation := len(expected.LaunchedCompanions) == 0
	if len(expected.LaunchedCompanions) > 0 {
		if err := validateCompanionFDIsolationClosure(companionSourceAudit{
			repo: expected.Repo, modulePath: expected.LaunchedModulePath,
			packagePaths: packages, tags: expected.LaunchedTags,
			goTool: goTool, environment: shippedBuildEnvironment(expected, goCache, runtimeTempDir),
		}); err != nil {
			return shippedBuild{}, err
		}
		companionFDIsolation = true
	}
	execRoot, err := validateRuntimeExecDirectory(receiptDir)
	if err != nil {
		return shippedBuild{}, err
	}
	binDir, err := os.MkdirTemp(execRoot, "shipped-process-"+cacheKey[:16]+"-")
	if err != nil {
		return shippedBuild{}, fmt.Errorf("create exclusive launched execution directory: %w", err)
	}
	if err := validatePrivateDirectory(binDir); err != nil {
		return shippedBuild{}, err
	}
	identities := make(map[string]executableIdentity, len(packages))
	for _, packagePath := range packages {
		name, err := shippedPackageName(packagePath)
		if err != nil {
			return shippedBuild{}, err
		}
		staged := filepath.Join(stagingDir, name)
		published := filepath.Join(binDir, name)
		if err := publishShippedExecutable(staged, published); err != nil {
			return shippedBuild{}, fmt.Errorf("publish launched binary %s: %w", packagePath, err)
		}
		identity, err := validateShippedBinary(published, expected, packagePath, false)
		if err != nil {
			return shippedBuild{}, err
		}
		stagedIdentity := stagedIdentities[packagePath]
		if identity.Size != stagedIdentity.Size || identity.Digest != stagedIdentity.Digest {
			return shippedBuild{}, fmt.Errorf("published launched binary %s does not match verified compiler output", packagePath)
		}
		identities[packagePath] = identity
	}
	if err := syncShippedDirectory(binDir); err != nil {
		return shippedBuild{}, fmt.Errorf("sync launched execution directory: %w", err)
	}
	binary := filepath.Join(binDir, filepath.Base(expected.LaunchedBinaryPackage))
	identity := identities[expected.LaunchedBinaryPackage]
	result := shippedBuild{
		binDir: binDir, binary: binary, identity: identity, dropper: dropper, companions: identities,
		companionFDIsolation: companionFDIsolation,
	}
	shippedBuilds.items[cacheKey] = result
	return result, nil
}

func publishShippedExecutable(source, destination string) error {
	sourceDescriptor, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open verified compiler output: %w", err)
	}
	sourceFile := os.NewFile(uintptr(sourceDescriptor), source)
	if sourceFile == nil {
		_ = unix.Close(sourceDescriptor)
		return fmt.Errorf("bind verified compiler output descriptor")
	}
	defer func() { _ = sourceFile.Close() }()
	sourceBefore, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect verified compiler output: %w", err)
	}
	if !sourceBefore.Mode().IsRegular() || sourceBefore.Size() <= 0 || sourceBefore.Size() > maxShippedBinaryBytes {
		return fmt.Errorf("verified compiler output is not one bounded regular file")
	}

	destinationDescriptor, err := unix.Open(destination,
		unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, 0o500)
	if err != nil {
		return fmt.Errorf("create exclusive published executable: %w", err)
	}
	destinationFile := os.NewFile(uintptr(destinationDescriptor), destination)
	if destinationFile == nil {
		_ = unix.Close(destinationDescriptor)
		return fmt.Errorf("bind published executable descriptor")
	}
	closed := false
	defer func() {
		if !closed {
			_ = destinationFile.Close()
		}
	}()

	written, err := io.Copy(destinationFile, io.LimitReader(sourceFile, maxShippedBinaryBytes+1))
	if err != nil {
		return fmt.Errorf("copy verified compiler output: %w", err)
	}
	if written != sourceBefore.Size() || written > maxShippedBinaryBytes {
		return fmt.Errorf("published executable size %d does not match verified compiler output size %d", written, sourceBefore.Size())
	}
	sourceAfter, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("reinspect verified compiler output: %w", err)
	}
	if !os.SameFile(sourceBefore, sourceAfter) || sourceBefore.Size() != sourceAfter.Size() || sourceBefore.Mode() != sourceAfter.Mode() {
		return fmt.Errorf("verified compiler output changed while publishing")
	}
	if err := destinationFile.Sync(); err != nil {
		return fmt.Errorf("sync published executable: %w", err)
	}
	if err := destinationFile.Close(); err != nil {
		return fmt.Errorf("close published executable: %w", err)
	}
	closed = true
	return nil
}

func syncShippedDirectory(directory string) error {
	dir, err := os.Open(directory) // #nosec G304 -- gate-owned private directory created above (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func ensureShippedGoCache(receiptDir string) (string, error) {
	// The runner owns one private content-addressed cache for the entire census.
	// Receipt roots stay per execution because they contain nonce/MAC-bound
	// evidence and substrate inputs. Putting the package cache below a receipt
	// root copies thousands of files into every host bind mount; Docker Desktop's
	// VirtioFS retains those deleted handles and can exhaust the host file table.
	goCache := os.Getenv(ShippedGoCacheEnv)
	for label, path := range map[string]string{"receipt directory": receiptDir, "shipped Go cache": goCache} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
			return "", fmt.Errorf("%s is not an exact clean absolute path", label)
		}
	}
	if pathsOverlap(receiptDir, goCache) {
		return "", fmt.Errorf("shipped Go cache overlaps the nonce-bound receipt directory")
	}
	if err := validatePrivateDirectory(goCache); err != nil {
		return "", err
	}
	return goCache, nil
}

func pathsOverlap(first, second string) bool {
	inside := func(root, candidate string) bool {
		relative, err := filepath.Rel(root, candidate)
		return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
	}
	if inside(first, second) || inside(second, first) {
		return true
	}
	resolvedFirst, firstErr := filepath.EvalSymlinks(first)
	resolvedSecond, secondErr := filepath.EvalSymlinks(second)
	return firstErr == nil && secondErr == nil &&
		(inside(resolvedFirst, resolvedSecond) || inside(resolvedSecond, resolvedFirst))
}

func shippedBuildArguments(expected expectation, ldflags, output, packagePath string, parallelism int) []string {
	if parallelism < 1 {
		parallelism = 1
	}
	args := []string{"build", "-p=" + strconv.Itoa(parallelism), "-trimpath", "-buildvcs=false", "-mod=readonly"}
	if len(expected.LaunchedTags) > 0 {
		args = append(args, "-tags="+strings.Join(expected.LaunchedTags, ","))
	}
	return append(args, "-ldflags", ldflags, "-o", output, packagePath)
}

func descriptorPackageParallelism() int {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 1
	}
	return packageParallelismForDescriptorLimit(limit.Cur, runtime.NumCPU())
}

func packageParallelismForDescriptorLimit(descriptors uint64, cpus int) int {
	// Keep the closed-P0 behavior on a 256-FD shell. Each extra worker gets a
	// conservative 128-FD slice after reserving 256 descriptors for the gate,
	// Docker transport, subprocess pipes, and the Go command itself.
	const reserve, perPackage = uint64(256), uint64(128)
	if cpus < 1 || descriptors <= reserve {
		return 1
	}
	workers := (descriptors - reserve) / perPackage
	if workers < 1 {
		return 1
	}
	if workers > uint64(cpus) {
		return cpus
	}
	return int(workers) // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
}

func validateRuntimePrivilegeDropper() (executableIdentity, error) {
	identity, _, err := inspectExecutable(runtimePrivilegeDropper, false, false)
	if err != nil {
		return executableIdentity{}, fmt.Errorf("inspect pinned runtime privilege dropper: %w", err)
	}
	if identity.UID != 0 || !validSHA256Digest(identity.Digest) {
		return executableIdentity{}, fmt.Errorf("runtime privilege dropper is not exact root-owned immutable executable bytes")
	}
	return identity, nil
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

type companionSourceAudit struct {
	repo, modulePath, goTool string
	packagePaths, tags       []string
	environment              []string
}

type companionProductionFile struct {
	path, relative, importPath string
}

// validateCompanionFDIsolationSource is the test/default entry point. The
// shipped build passes its already-pinned Go tool, tags, platform, and exact
// binary roots to validateCompanionFDIsolationClosure below.
func validateCompanionFDIsolationSource(repo string) error {
	modulePath, err := sourceAuditModulePath(repo)
	if err != nil {
		return err
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("locate Go tool for companion closure audit: %w", err)
	}
	return validateCompanionFDIsolationClosure(companionSourceAudit{
		repo: repo, modulePath: modulePath, goTool: goTool,
		packagePaths: []string{"./cmd/trstctl", "./cmd/trstctl-signer"},
		environment:  companionSourceAuditEnvironment(os.Environ()),
	})
}

// validateCompanionFDIsolationClosure establishes the causal half of the
// unreadable signer exception over every module-owned production file selected
// by the exact shipped control-plane and signer builds. It retains one reviewed
// supervisor launch and rejects any alternate inheritance, FD-transfer, pidfd,
// or raw-syscall path in their linked dependency closure.
func validateCompanionFDIsolationClosure(audit companionSourceAudit) error {
	files, err := companionProductionClosure(audit)
	if err != nil {
		return err
	}
	fileSet := token.NewFileSet()
	supervisorSeen := false
	for _, source := range files {
		parsed, err := parser.ParseFile(fileSet, source.path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse production dependency %s: %w", source.relative, err)
		}
		allowedExtraFiles, err := reviewedShellCAExtraFiles(source.relative, parsed)
		if err != nil {
			return fmt.Errorf("audit production dependency %s: %w", source.relative, err)
		}
		if source.relative == filepath.Join("internal", "signing", "supervisor.go") {
			if err := validateReviewedSupervisorLaunch(parsed); err != nil {
				return fmt.Errorf("audit shipped signer supervisor: %w", err)
			}
			supervisorSeen = true
		}
		if err := auditCompanionFDPrimitives(parsed, allowedExtraFiles); err != nil {
			return fmt.Errorf("production dependency %s can bypass companion FD isolation: %w", source.relative, err)
		}
	}
	if !supervisorSeen {
		return fmt.Errorf("exact shipped dependency closure omits internal/signing/supervisor.go")
	}
	return nil
}

func sourceAuditModulePath(repo string) (string, error) {
	if !filepath.IsAbs(repo) {
		return "", fmt.Errorf("companion FD-isolation source root is not absolute")
	}
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod")) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody {
		return "", fmt.Errorf("read bounded source-audit go.mod: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" && fields[1] != "" && !strings.ContainsAny(fields[1], "\\\x00") {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("source-audit go.mod has no exact module directive")
}

func companionSourceAuditEnvironment(base []string) []string {
	overrides := map[string]string{
		"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOENV": "off",
		"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off",
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOTELEMETRY": "off",
	}
	if os.Getenv("GOCACHE") == "" {
		overrides["GOCACHE"] = filepath.Join(os.TempDir(), "trstctl-dod-source-audit-gocache")
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		name, _, ok := strings.Cut(item, "=")
		if ok {
			if _, replaced := overrides[name]; replaced {
				continue
			}
		}
		out = append(out, item)
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+overrides[key])
	}
	return out
}

func companionProductionClosure(audit companionSourceAudit) ([]companionProductionFile, error) {
	if !filepath.IsAbs(audit.repo) || audit.modulePath == "" || !filepath.IsAbs(audit.goTool) || len(audit.packagePaths) == 0 {
		return nil, fmt.Errorf("companion source audit is not bound to an absolute repo/tool and package roots")
	}
	resolvedRepo, err := filepath.EvalSymlinks(audit.repo)
	if err != nil || !filepath.IsAbs(resolvedRepo) {
		return nil, fmt.Errorf("resolve companion source-audit repository: %w", err)
	}
	audit.repo = resolvedRepo
	args := []string{"list", "-deps", "-json", "-mod=readonly"}
	if len(audit.tags) > 0 {
		args = append(args, "-tags="+strings.Join(audit.tags, ","))
	}
	args = append(args, audit.packagePaths...)
	command := exec.Command(audit.goTool, args...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
	command.Dir, command.Env = audit.repo, audit.environment
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start exact production dependency listing: %w", err)
	}
	type listedModule struct {
		Path string
		Main bool
	}
	type listedError struct{ Err string }
	type listedPackage struct {
		Dir, ImportPath                      string
		Module                               *listedModule
		Error                                *listedError
		GoFiles, CgoFiles                    []string
		CFiles, CXXFiles, MFiles, HFiles     []string
		FFiles, SFiles, SwigFiles, SysoFiles []string
	}
	decoder := json.NewDecoder(stdout)
	files := map[string]companionProductionFile{}
	roots := map[string]bool{}
	packageCount := 0
	for {
		var listed listedPackage
		if err := decoder.Decode(&listed); err != nil {
			if err == io.EOF {
				break
			}
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("decode exact production dependency listing: %w", err)
		}
		packageCount++
		if packageCount > 8192 {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("production dependency closure exceeds 8192 packages")
		}
		if listed.Error != nil && listed.Error.Err != "" {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("list production dependency %s: %s", listed.ImportPath, listed.Error.Err)
		}
		for _, packagePath := range audit.packagePaths {
			want := audit.modulePath + "/" + strings.TrimPrefix(packagePath, "./")
			if listed.ImportPath == want {
				roots[packagePath] = true
			}
		}
		if listed.Module == nil || !listed.Module.Main {
			continue
		}
		if listed.Module.Path != audit.modulePath || !filepath.IsAbs(listed.Dir) || !pathInside(audit.repo, listed.Dir) {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("production package %s escapes exact main module %s", listed.ImportPath, audit.modulePath)
		}
		if len(listed.CFiles)+len(listed.CXXFiles)+len(listed.MFiles)+len(listed.HFiles)+len(listed.FFiles)+len(listed.SFiles)+len(listed.SwigFiles)+len(listed.SysoFiles) != 0 {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("module production package %s contains a non-Go syscall-capable object", listed.ImportPath)
		}
		for _, name := range append(append([]string(nil), listed.GoFiles...), listed.CgoFiles...) {
			if name == "" || filepath.Base(name) != name || strings.HasSuffix(name, "_test.go") {
				_ = command.Process.Kill()
				_ = command.Wait()
				return nil, fmt.Errorf("production package %s returned an unsafe source name %q", listed.ImportPath, name)
			}
			path := filepath.Join(listed.Dir, name)
			if !pathInside(audit.repo, path) {
				_ = command.Process.Kill()
				_ = command.Wait()
				return nil, fmt.Errorf("production source %s escapes repository", path)
			}
			relative, err := filepath.Rel(audit.repo, path)
			if err != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
				return nil, fmt.Errorf("relativize production source %s: %w", path, err)
			}
			if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				_ = command.Process.Kill()
				_ = command.Wait()
				return nil, fmt.Errorf("production source %s is outside resolved repository %s", path, audit.repo)
			}
			files[path] = companionProductionFile{path: path, relative: relative, importPath: listed.ImportPath}
		}
	}
	if err := command.Wait(); err != nil {
		return nil, fmt.Errorf("list exact production dependency closure: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	for _, packagePath := range audit.packagePaths {
		if !roots[packagePath] {
			return nil, fmt.Errorf("production dependency closure omits root %s", packagePath)
		}
	}
	out := make([]companionProductionFile, 0, len(files))
	for _, source := range files {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].relative < out[j].relative })
	return out, nil
}

func validateReviewedSupervisorLaunch(file *ast.File) error {
	imports, err := sourceImportAliases(file)
	if err != nil {
		return err
	}
	execAlias := importAliasForPath(imports, "os/exec")
	if execAlias == "" {
		return fmt.Errorf("shipped signer supervisor has no exact os/exec import")
	}
	launches := 0
	var auditErr error
	ast.Inspect(file, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		alias, aliasOK := selectorXIdentifier(selector)
		if !ok || !aliasOK || alias != execAlias {
			return true
		}
		valid := selector.Sel.Name == "Command" && len(call.Args) >= 1 && expressionIdentifier(call.Args[0]) == "binaryPath"
		valid = valid || selector.Sel.Name == "CommandContext" && len(call.Args) >= 2 && expressionIdentifier(call.Args[0]) == "ctx" && expressionIdentifier(call.Args[1]) == "binaryPath"
		if !valid {
			auditErr = fmt.Errorf("shipped signer supervisor uses an unreviewed os/exec launch")
			return false
		}
		launches++
		return true
	})
	if auditErr != nil {
		return auditErr
	}
	if launches == 0 {
		return fmt.Errorf("shipped signer supervisor has no reviewed child launch")
	}
	return nil
}

func auditCompanionFDPrimitives(file *ast.File, allowedExtraFiles map[*ast.SelectorExpr]bool) error {
	imports, err := sourceImportAliases(file)
	if err != nil {
		return err
	}
	procAttrs := procAttrIdentifiers(file, imports)
	importDanger := map[string]map[string]bool{
		"os":                    {"StartProcess": true},
		"syscall":               {"StartProcess": true, "ForkExec": true, "UnixRights": true, "ParseUnixRights": true, "Sendmsg": true, "SendmsgN": true, "Recvmsg": true, "Dup": true, "Dup2": true, "Dup3": true, "Fcntl": true, "CloseOnExec": true, "Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true, "SYS_SENDMSG": true, "SYS_PIDFD_GETFD": true, "SCM_RIGHTS": true, "F_DUPFD": true, "F_DUPFD_CLOEXEC": true, "F_SETFD": true, "FD_CLOEXEC": true},
		"golang.org/x/sys/unix": {"ForkExec": true, "UnixRights": true, "ParseUnixRights": true, "Sendmsg": true, "SendmsgN": true, "Recvmsg": true, "PidfdGetfd": true, "Dup": true, "Dup2": true, "Dup3": true, "Fcntl": true, "FcntlInt": true, "FcntlFlock": true, "CloseOnExec": true, "Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true, "SYS_SENDMSG": true, "SYS_PIDFD_GETFD": true, "SCM_RIGHTS": true, "F_DUPFD": true, "F_DUPFD_CLOEXEC": true, "F_SETFD": true, "FD_CLOEXEC": true},
	}
	methodDanger := map[string]bool{"WriteMsgUnix": true, "ReadMsgUnix": true}
	literalDanger := map[string]bool{"ExtraFiles": true, "SCM_RIGHTS": true, "SYS_SENDMSG": true, "SYS_PIDFD_GETFD": true, "F_DUPFD": true, "F_DUPFD_CLOEXEC": true, "F_SETFD": true, "FD_CLOEXEC": true}
	var found string
	ast.Inspect(file, func(node ast.Node) bool {
		if found != "" {
			return false
		}
		switch value := node.(type) {
		case *ast.SelectorExpr:
			if value.Sel.Name == "ExtraFiles" && !allowedExtraFiles[value] {
				found = "Cmd.ExtraFiles"
				return false
			}
			if value.Sel.Name == "Files" && procAttrs[rootExpressionIdentifier(value.X)] {
				found = "ProcAttr.Files"
				return false
			}
			if methodDanger[value.Sel.Name] {
				found = value.Sel.Name
				return false
			}
			if alias, ok := value.X.(*ast.Ident); ok {
				if dangerous := importDanger[imports[alias.Name]]; dangerous[value.Sel.Name] {
					found = imports[alias.Name] + "." + value.Sel.Name
					return false
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := value.Key.(*ast.Ident); ok && key.Name == "ExtraFiles" {
				found = "Cmd literal ExtraFiles"
				return false
			}
		case *ast.CompositeLit:
			if selector, ok := value.Type.(*ast.SelectorExpr); ok {
				if alias, aliasOK := selector.X.(*ast.Ident); aliasOK && selector.Sel.Name == "ProcAttr" && (imports[alias.Name] == "os" || imports[alias.Name] == "syscall") {
					found = imports[alias.Name] + ".ProcAttr/Files"
					return false
				}
			}
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				literal, unquoteErr := strconv.Unquote(value.Value)
				if unquoteErr == nil && literalDanger[literal] {
					found = "reflective FD primitive " + literal
					return false
				}
			}
		}
		return true
	})
	if found != "" {
		return fmt.Errorf("contains FD inheritance/transfer primitive %s", found)
	}
	return nil
}

func procAttrIdentifiers(file *ast.File, imports map[string]string) map[string]bool {
	identifiers := map[string]bool{}
	isProcAttr := func(expression ast.Expr) bool {
		for {
			switch value := expression.(type) {
			case *ast.StarExpr:
				expression = value.X
				continue
			case *ast.UnaryExpr:
				expression = value.X
				continue
			case *ast.CompositeLit:
				expression = value.Type
				continue
			case *ast.ParenExpr:
				expression = value.X
				continue
			case *ast.SelectorExpr:
				alias, ok := value.X.(*ast.Ident)
				return ok && value.Sel.Name == "ProcAttr" && (imports[alias.Name] == "os" || imports[alias.Name] == "syscall")
			default:
				return false
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.Field:
			if isProcAttr(value.Type) {
				for _, name := range value.Names {
					identifiers[name.Name] = true
				}
			}
		case *ast.ValueSpec:
			if isProcAttr(value.Type) {
				for _, name := range value.Names {
					identifiers[name.Name] = true
				}
			}
			for index, expression := range value.Values {
				if index < len(value.Names) && isProcAttr(expression) {
					identifiers[value.Names[index].Name] = true
				}
			}
		case *ast.AssignStmt:
			for index, expression := range value.Rhs {
				if index >= len(value.Lhs) || !isProcAttr(expression) {
					continue
				}
				if name, ok := value.Lhs[index].(*ast.Ident); ok {
					identifiers[name.Name] = true
				}
			}
		}
		return true
	})
	return identifiers
}

func sourceImportAliases(file *ast.File) (map[string]string, error) {
	imports := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("source has invalid import path: %w", err)
		}
		alias := filepath.Base(path)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." && (path == "os" || path == "os/exec" || path == "syscall" || path == "golang.org/x/sys/unix") {
			return nil, fmt.Errorf("source dot-imports process/FD package %s", path)
		}
		if alias != "_" && alias != "." {
			imports[alias] = path
		}
	}
	return imports, nil
}

func importAliasForPath(imports map[string]string, path string) string {
	for alias, imported := range imports {
		if imported == path {
			return alias
		}
	}
	return ""
}

func selectorXIdentifier(selector *ast.SelectorExpr) (string, bool) {
	if selector == nil {
		return "", false
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return identifier.Name, true
}

// shellca legitimately passes only fresh os.Pipe read ends to its configured
// CA command. Keep that one use after proving the receiver, producer, and
// success return are a closed local dataflow; every other ExtraFiles occurrence
// in the production closure remains fatal.
func reviewedShellCAExtraFiles(relative string, file *ast.File) (map[*ast.SelectorExpr]bool, error) {
	allowed := map[*ast.SelectorExpr]bool{}
	if filepath.ToSlash(relative) != "internal/ca/shellca/shellca.go" {
		return allowed, nil
	}
	imports, err := sourceImportAliases(file)
	if err != nil {
		return nil, err
	}
	execAlias := importAliasForPath(imports, "os/exec")
	osAlias := importAliasForPath(imports, "os")
	var run, pipeHelper *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if function.Name.Name == "run" && function.Recv != nil {
			run = function
		}
		if function.Name.Name == "openSecretPipes" && function.Recv == nil {
			pipeHelper = function
		}
	}
	if run == nil || pipeHelper == nil || execAlias == "" || osAlias == "" {
		return nil, fmt.Errorf("reviewed shellca pipe/launch functions are missing")
	}
	var commandPosition, readersPosition, extraPosition token.Pos
	var auditErr error
	ast.Inspect(run.Body, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) == 0 || len(assignment.Rhs) != 1 {
			return true
		}
		if identifier, ok := assignment.Lhs[0].(*ast.Ident); ok && identifier.Name == "cmd" {
			call, callOK := assignment.Rhs[0].(*ast.CallExpr)
			selector, selectorOK := callFunctionSelector(call)
			alias, aliasOK := selectorXIdentifier(selector)
			if !callOK || !selectorOK || !aliasOK || alias != execAlias || selector.Sel.Name != "CommandContext" || len(call.Args) < 3 ||
				expressionIdentifier(call.Args[0]) != "runCtx" || expressionPath(call.Args[1]) != "b.cfg.Command" {
				auditErr = fmt.Errorf("reviewed shellca command is not the exact configured-command launch")
				return false
			}
			commandPosition = assignment.Pos()
		}
		if identifier, ok := assignment.Lhs[0].(*ast.Ident); ok && identifier.Name == "readers" {
			call, callOK := assignment.Rhs[0].(*ast.CallExpr)
			var callee *ast.Ident
			calleeOK := false
			if callOK {
				callee, calleeOK = call.Fun.(*ast.Ident)
			}
			if len(assignment.Lhs) != 4 || !callOK || !calleeOK || callee.Name != "openSecretPipes" || len(call.Args) != 1 || expressionPath(call.Args[0]) != "b.cfg.SecretFDs" {
				auditErr = fmt.Errorf("reviewed shellca ExtraFiles does not receive only openSecretPipes output")
				return false
			}
			readersPosition = assignment.Pos()
		}
		for _, lhs := range assignment.Lhs {
			selector, ok := lhs.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ExtraFiles" {
				continue
			}
			if len(assignment.Lhs) != 1 || assignment.Tok != token.ASSIGN || expressionIdentifier(selector.X) != "cmd" || expressionIdentifier(assignment.Rhs[0]) != "readers" || extraPosition != token.NoPos {
				auditErr = fmt.Errorf("reviewed shellca ExtraFiles assignment changed shape")
				return false
			}
			extraPosition = assignment.Pos()
			allowed[selector] = true
		}
		return true
	})
	if auditErr != nil {
		return nil, auditErr
	}
	if commandPosition == token.NoPos || readersPosition == token.NoPos || extraPosition == token.NoPos || commandPosition >= extraPosition || readersPosition >= extraPosition || len(allowed) != 1 {
		return nil, fmt.Errorf("reviewed shellca launch/pipe/ExtraFiles order is incomplete")
	}
	if err := validateReviewedSecretPipeProducer(pipeHelper, osAlias); err != nil {
		return nil, err
	}
	return allowed, nil
}

func validateReviewedSecretPipeProducer(function *ast.FuncDecl, osAlias string) error {
	pipeCalls := 0
	successReturns := 0
	var auditErr error
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		switch value := node.(type) {
		case *ast.FuncLit:
			auditErr = fmt.Errorf("reviewed shellca pipe producer contains a closure")
			return false
		case *ast.AssignStmt:
			for _, lhs := range value.Lhs {
				if rootExpressionIdentifier(lhs) != "readers" {
					continue
				}
				identifier, direct := lhs.(*ast.Ident)
				if !direct || identifier.Name != "readers" || len(value.Rhs) != 1 {
					auditErr = fmt.Errorf("reviewed shellca mutates its pipe reader slice indirectly")
					return false
				}
				call, ok := value.Rhs[0].(*ast.CallExpr)
				var callee *ast.Ident
				calleeOK := false
				if ok {
					callee, calleeOK = call.Fun.(*ast.Ident)
				}
				initial := value.Tok == token.DEFINE && ok && calleeOK && callee.Name == "make"
				appendPipe := value.Tok == token.ASSIGN && ok && calleeOK && callee.Name == "append" && len(call.Args) == 2 && expressionIdentifier(call.Args[0]) == "readers" && expressionIdentifier(call.Args[1]) == "reader"
				if !initial && !appendPipe {
					auditErr = fmt.Errorf("reviewed shellca pipe reader slice has a non-pipe source")
					return false
				}
			}
			for index, lhs := range value.Lhs {
				if expressionIdentifier(lhs) != "reader" {
					continue
				}
				if index != 0 || len(value.Rhs) != 1 || !isSelectorCall(value.Rhs[0], osAlias, "Pipe") {
					auditErr = fmt.Errorf("reviewed shellca reader is not produced directly by os.Pipe")
					return false
				}
			}
		case *ast.CallExpr:
			if isSelectorCall(value, osAlias, "Pipe") {
				pipeCalls++
			}
			usesReaders := false
			for _, argument := range value.Args {
				usesReaders = usesReaders || expressionContainsIdentifier(argument, "readers")
			}
			if usesReaders {
				callee, _ := value.Fun.(*ast.Ident)
				if callee == nil || (callee.Name != "append" && callee.Name != "closeFiles") {
					auditErr = fmt.Errorf("reviewed shellca exposes its pipe reader slice to another call")
					return false
				}
			}
		case *ast.ReturnStmt:
			if len(value.Results) != 4 {
				auditErr = fmt.Errorf("reviewed shellca pipe producer has a non-exact return")
				return false
			}
			first := expressionIdentifier(value.Results[0])
			if first == "nil" {
				return true
			}
			if first != "readers" || expressionIdentifier(value.Results[1]) != "writers" || expressionIdentifier(value.Results[2]) != "descriptors" || expressionIdentifier(value.Results[3]) != "nil" {
				auditErr = fmt.Errorf("reviewed shellca returns a foreign pipe reader source")
				return false
			}
			successReturns++
		}
		return true
	})
	if auditErr != nil {
		return auditErr
	}
	if pipeCalls != 1 || successReturns != 1 {
		return fmt.Errorf("reviewed shellca pipe producer has %d os.Pipe calls and %d success returns", pipeCalls, successReturns)
	}
	return nil
}

func callFunctionSelector(call *ast.CallExpr) (*ast.SelectorExpr, bool) {
	if call == nil {
		return nil, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return selector, ok
}

func isSelectorCall(expression ast.Expr, alias, name string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	identifier, identifierOK := selectorXIdentifier(selector)
	return ok && identifierOK && identifier == alias && selector.Sel.Name == name
}

func expressionPath(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := expressionPath(value.X)
		if prefix != "" {
			return prefix + "." + value.Sel.Name
		}
	}
	return ""
}

func rootExpressionIdentifier(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.IndexExpr:
		return rootExpressionIdentifier(value.X)
	case *ast.SelectorExpr:
		return rootExpressionIdentifier(value.X)
	case *ast.StarExpr:
		return rootExpressionIdentifier(value.X)
	}
	return ""
}

func expressionContainsIdentifier(expression ast.Expr, name string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func expressionIdentifier(expression ast.Expr) string {
	identifier, _ := expression.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}

func shippedBuildEnvironment(expected expectation, goCache, runtimeTempDir string) []string {
	values := map[string]string{
		"GOCACHE":    goCache,
		"GOMODCACHE": "/go/pkg/mod",
		"GOTMPDIR":   "/tmp",
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
	values["HOME"] = runtimeTempDir
	values["TMPDIR"] = runtimeTempDir
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
	info, err := os.Lstat(path) // #nosec G703 -- developer tool probing repo/toolchain paths, not a served binary (CWE-22)
	if err != nil {
		return fmt.Errorf("inspect private launched directory: %w", err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	ownerUID := "unavailable"
	ownerMatches := false
	if ok {
		ownerUID = strconv.FormatUint(uint64(metadata.Uid), 10)
		ownerMatches = metadata.Uid == uint32(os.Geteuid()) // #nosec G115 -- bounded process identity comparison (CWE-190)
	}
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !ownerMatches {
		return fmt.Errorf(
			"launched directory %q is not a caller-owned, non-symlink 0700 directory: mode=%04o owner_uid=%s effective_uid=%d directory=%t symlink=%t",
			path, info.Mode().Perm(), ownerUID, os.Geteuid(), info.IsDir(), info.Mode()&os.ModeSymlink != 0,
		)
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
	if identity.UID != uint32(os.Geteuid()) { // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
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
		file, err = os.Open(path) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
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
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Links: uint64(stat.Nlink), // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
		UID: stat.Uid, Size: info.Size(), Mode: info.Mode(),
	}, nil
}

// CreateToken runs the exact built control binary in its one reviewed CLI mode.
func (p *ShippedProcess) CreateToken(directory string, environment []string, args ...string) string {
	p.t.Helper()
	if err := p.revalidateBuiltArtifacts(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped artifacts before token CLI: %v", err)
	}
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
	commandName, commandArgs := shippedProcessCommand(p.build.binary, args...)
	command := exec.Command(commandName, commandArgs...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
	command.Dir, command.Env = dir, env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := sealInheritedDescriptorsForShippedExec(); err != nil {
		p.t.Fatalf("DOD-CENSUS: seal inherited descriptors before token CLI: %v", err)
	}
	if err := command.Run(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped token CLI: %v stderr=%s", err, stderr.String())
	}
	if stdout.Len() == 0 || stdout.Len() > maxEvidenceBody {
		p.t.Fatalf("DOD-CENSUS: shipped token CLI output size %d is invalid", stdout.Len())
	}
	if err := p.revalidateBuiltArtifacts(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped artifacts after token CLI: %v", err)
	}
	return strings.TrimSpace(stdout.String())
}

// Start launches the exact built control binary with a clean, closed
// environment. The PATH begins with the gate-built companion directory.
func (p *ShippedProcess) Start(directory string, environment []string) {
	p.t.Helper()
	if err := p.revalidateBuiltArtifacts(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped artifacts before control launch: %v", err)
	}
	dir, env, err := p.processInputs(directory, environment)
	if err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	if p.command != nil {
		p.mu.Unlock()
		p.t.Fatal("DOD-CENSUS: shipped control plane started more than once")
	}
	commandName, commandArgs := shippedProcessCommand(p.build.binary)
	command := exec.Command(commandName, commandArgs...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
	command.Dir, command.Env = dir, env
	command.Stdout, command.Stderr = &p.logs, &p.logs
	if err := sealInheritedDescriptorsForShippedExec(); err != nil {
		p.mu.Unlock()
		p.t.Fatalf("DOD-CENSUS: seal inherited descriptors before control launch: %v", err)
	}
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
	witness, err := waitForLiveProcess(command.Process.Pid, p.build, p.expect, p.done)
	if err != nil {
		_ = command.Process.Kill()
		p.t.Fatalf("DOD-CENSUS: %s launched process executable mismatch: %v", p.expect.ID, err)
	}
	if err := waitForExclusiveProcessSockets(command.Process.Pid, p.build, p.expect, p.done); err != nil {
		_ = command.Process.Kill()
		p.t.Fatalf("DOD-CENSUS: launched process inherited a foreign-owned socket: %v", err)
	}
	if err := p.revalidateBuiltArtifacts(); err != nil {
		_ = command.Process.Kill()
		p.t.Fatalf("DOD-CENSUS: shipped artifacts changed during control/companion launch: %v", err)
	}
	p.mu.Lock()
	p.witness = witness
	p.mu.Unlock()
	p.t.Cleanup(p.Stop)
}

// shippedProcessCommand keeps the audit capabilities in the gate test only.
// CHECKPOINT_RESTORE opens the kernel-owned /proc/PID/map_files objects;
// SETGID removes the Docker-socket supplementary group before exec. Granting
// either to the product would change its shipped authority. A second shell-free
// setpriv exec clears groups plus inheritable/ambient state before the exact
// private binary starts. No-new-privileges prevents residual bounding bits from
// becoming effective again.
func shippedProcessCommand(binary string, args ...string) (string, []string) {
	dropArgs := []string{
		"--clear-groups",
		"--inh-caps=-checkpoint_restore,-setgid",
		"--ambient-caps=-checkpoint_restore,-setgid",
		binary,
	}
	return runtimePrivilegeDropper, append(dropArgs, args...)
}

// sealInheritedDescriptorsForShippedExec prevents the proof runner's own open
// files from crossing either reviewed exec boundary. This is material under
// binfmt/Rosetta: the interpreter keeps the gate test executable open without
// FD_CLOEXEC, so an ordinary os/exec child otherwise retains a test executable
// descriptor even though Go did not place it in Cmd.ExtraFiles. Child-specific
// stdout/stderr pipes are created later by os/exec and are therefore unaffected.
func sealInheritedDescriptorsForShippedExec() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("descriptor sealing requires Linux /proc")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("enumerate gate-runner descriptors: %w", err)
	}
	for _, entry := range entries {
		descriptor, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || descriptor <= 2 {
			continue
		}
		if sealErr := sealDescriptorCloseOnExec(descriptor); sealErr != nil {
			if sealErr == unix.EBADF {
				continue
			}
			return fmt.Errorf("seal descriptor %d close-on-exec: %w", descriptor, sealErr)
		}
	}
	return nil
}

func sealDescriptorCloseOnExec(descriptor int) error {
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&unix.FD_CLOEXEC == 0 {
		if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
			return err
		}
	}
	verified, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if verified&unix.FD_CLOEXEC == 0 {
		return fmt.Errorf("descriptor remains inheritable")
	}
	return nil
}

func waitForLiveProcess(pid int, built shippedBuild, expected expectation, done <-chan struct{}) (processExecutableWitness, error) {
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		witness, err := inspectLiveProcess(pid, built, expected)
		if err == nil {
			return witness, nil
		}
		lastErr = err
		if !processRunning(done) || time.Now().After(deadline) {
			return processExecutableWitness{}, lastErr
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForExclusiveProcessSockets(pid int, built shippedBuild, expected expectation, done <-chan struct{}) error {
	return waitForSocketOwnershipAudit(done, time.Now().Add(5*time.Second), func() error {
		return requireAllProcessSocketsExclusive(pid, built, expected)
	})
}

func waitForSocketOwnershipAudit(done <-chan struct{}, deadline time.Time, audit func() error) error {
	for {
		err := audit()
		if err == nil {
			return nil
		}
		if err != errNoStableProcessSockets || !processRunning(done) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *ShippedProcess) processInputs(directory string, environment []string) (string, []string, error) {
	receiptDir := filepath.Dir(p.expect.EvidenceFile)
	runtimeTempDir, err := validateRuntimeTempDirectory(receiptDir)
	if err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || (!pathInside(receiptDir, resolved) && !pathInside(runtimeTempDir, resolved)) {
		return "", nil, fmt.Errorf("DOD-CENSUS: shipped process working directory is outside the receipt boundary")
	}
	values := map[string]string{
		"HOME": runtimeTempDir, "TMPDIR": runtimeTempDir,
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

func validateRuntimeTempDirectory(receiptDir string) (string, error) {
	if !filepath.IsAbs(receiptDir) || !filepath.IsAbs(RuntimeTempDir) || len(RuntimeTempDir) > 16 {
		return "", fmt.Errorf("DOD-CENSUS: runtime temporary path is not an exact short absolute alias")
	}
	receiptInfo, err := os.Stat(receiptDir)
	if err != nil {
		return "", fmt.Errorf("DOD-CENSUS: inspect private receipt directory: %w", err)
	}
	tempInfo, err := os.Lstat(RuntimeTempDir)
	if err != nil {
		return "", fmt.Errorf("DOD-CENSUS: inspect short runtime directory: %w", err)
	}
	if !receiptInfo.IsDir() || !tempInfo.IsDir() || tempInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(receiptInfo, tempInfo) {
		return "", fmt.Errorf("DOD-CENSUS: short runtime directory is not the private receipt mount")
	}
	return RuntimeTempDir, nil
}

func validateRuntimeExecDirectory(receiptDir string) (string, error) {
	execRoot := os.Getenv(RuntimeExecRootEnv)
	if execRoot != RuntimeExecDir || !filepath.IsAbs(execRoot) || filepath.Clean(execRoot) != execRoot {
		return "", fmt.Errorf("DOD-CENSUS: runtime executable root is not gate-owned %q", RuntimeExecDir)
	}
	receiptInfo, err := os.Stat(receiptDir)
	if err != nil {
		return "", fmt.Errorf("DOD-CENSUS: inspect private receipt directory: %w", err)
	}
	execInfo, err := os.Lstat(RuntimeExecDir)
	if err != nil {
		return "", fmt.Errorf("DOD-CENSUS: inspect runtime executable root: %w", err)
	}
	stat, ok := execInfo.Sys().(*syscall.Stat_t)
	if !receiptInfo.IsDir() || !execInfo.IsDir() || execInfo.Mode()&os.ModeSymlink != 0 ||
		!ok || int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) || execInfo.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("DOD-CENSUS: runtime executable root is not a private directory owned by the dropped runtime identity")
	}
	if os.SameFile(receiptInfo, execInfo) || pathsOverlap(receiptDir, execRoot) {
		return "", fmt.Errorf("DOD-CENSUS: runtime executable root overlaps the host-backed receipt mount")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(execRoot, &filesystem); err != nil {
		return "", fmt.Errorf("DOD-CENSUS: inspect runtime executable tmpfs: %w", err)
	}
	if !hasRuntimeExecCapacity(uint64(filesystem.Blocks), int64(filesystem.Bsize)) {
		return "", fmt.Errorf("DOD-CENSUS: runtime executable tmpfs is not the bounded 1 GiB mount")
	}
	return execRoot, nil
}

func hasRuntimeExecCapacity(blocks uint64, blockSize int64) bool {
	const capacity int64 = 1 << 30
	// Divide the fixed positive capacity, avoiding both signed conversion and
	// overflow of the filesystem's potentially inconsistent block count.
	return blockSize > 0 && blockSize <= capacity && capacity%blockSize == 0 &&
		blocks == uint64(capacity/blockSize)
}

func pathInside(root, candidate string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedCandidate)
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
	if err := p.revalidateBuiltArtifacts(); err != nil {
		p.t.Fatalf("DOD-CENSUS: shipped artifacts before served request: %v", err)
	}
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
	if err := requireAllProcessSocketsExclusive(command.Process.Pid, p.build, p.expect); err != nil {
		p.t.Fatalf("DOD-CENSUS: pre-request launched socket ownership: %v", err)
	}
	inode, err := processLoopbackListener(command.Process.Pid, port)
	if err != nil {
		p.t.Fatalf("DOD-CENSUS: launched listener ownership: %v", err)
	}
	if err := requireExclusiveSocketOwner(command.Process.Pid, inode, p.build, p.expect); err != nil {
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
	response, err := client.Do(directRequest) // #nosec G704 -- developer tool calling the endpoint it was pointed at (CWE-918)
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
	if err := requireExclusiveSocketOwner(command.Process.Pid, acceptedInode, p.build, p.expect); err != nil {
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
	exclusiveErr := requireExclusiveSocketOwner(command.Process.Pid, afterInode, p.build, p.expect)
	allExclusiveErr := requireAllProcessSocketsExclusive(command.Process.Pid, p.build, p.expect)
	if err != nil || afterInode != inode || witnessErr != nil || afterWitness != expectedWitness || exclusiveErr != nil || allExclusiveErr != nil || !processRunning(done) {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: shipped process/executable/listener changed during response: listener=%v executable=%v exclusive=%v all_sockets=%v", err, witnessErr, exclusiveErr, allExclusiveErr)
	}
	if err := p.revalidateBuiltArtifacts(); err != nil {
		_ = response.Body.Close()
		p.t.Fatalf("DOD-CENSUS: shipped artifacts changed during served request: %v", err)
	}
	processReceipt := launchedProcessReceipt{
		PID: command.Process.Pid, ProcessStartTicks: strconv.FormatUint(expectedWitness.ProcessStartTicks, 10),
		ProcessMode: expectedWitness.Mode, BinaryModulePath: p.expect.LaunchedModulePath,
		BinaryPackage: p.expect.LaunchedBinaryPackage, BinaryCGOEnabled: p.expect.LaunchedCGOEnabled,
		BinaryGOOS: p.expect.LaunchedGOOS, BinaryGOARCH: p.expect.LaunchedGOARCH,
		BinaryTags:   append([]string(nil), p.expect.LaunchedTags...),
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
	if err := validateShippedProcessPrivileges(pid, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil { // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
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
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("inspect gate-runner executable: %w", err)
	}
	interpreterTarget, err := os.Readlink(procExecutable)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("read non-native process interpreter: %w", err)
	}
	if err := validateReviewedBinfmtInterpreter(interpreterTarget, procIdentity, selfInterpreter, target); err != nil {
		return processExecutableWitness{}, err
	}
	runnerArgs, err := processCommandLine(os.Getpid())
	if err != nil || len(runnerArgs) == 0 || !filepath.IsAbs(runnerArgs[0]) || filepath.Clean(runnerArgs[0]) != runnerArgs[0] {
		return processExecutableWitness{}, fmt.Errorf("gate test runner has no exact absolute guest executable argv: %w", err)
	}
	runnerIdentity, runnerBuild, err := inspectExecutable(runnerArgs[0], false, true)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("inspect emulated gate test runner: %w", err)
	}
	wantRunnerPath := expected.LaunchedModulePath + "/" + strings.TrimPrefix(expected.RuntimeTestPackage, "./")
	runnerPathMatches := runnerBuild.Path == wantRunnerPath || runnerBuild.Path == wantRunnerPath+".test"
	if runnerIdentity.UID != uint32(os.Geteuid()) || runnerBuild.Main.Path != expected.LaunchedModulePath || !runnerPathMatches || runnerBuild.GoVersion != runtime.Version() { // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
		return processExecutableWitness{}, fmt.Errorf("emulation interpreter is not hosting the gate-issued Go test runner")
	}
	runnerSettings := map[string]string{}
	for _, setting := range runnerBuild.Settings {
		runnerSettings[setting.Key] = setting.Value
	}
	wantRunnerTags := append(append([]string(nil), expected.RuntimeTags...), "trstctl_dodproof")
	if runnerSettings["GOOS"] != expected.RuntimeGOOS || runnerSettings["GOARCH"] != expected.RuntimeGOARCH ||
		runnerSettings["CGO_ENABLED"] != expected.RuntimeCGOEnabled || runnerSettings["-tags"] != strings.Join(wantRunnerTags, ",") {
		return processExecutableWitness{}, fmt.Errorf("emulated gate test runner does not match the shipped platform/proof tags")
	}
	// Docker Desktop may expose the already-running Go test's guest binary
	// directly in /proc/self/exe even though a later direct exec exposes
	// Rosetta. That direct device/inode/digest equality is the stronger causal
	// binding. Ordinary binfmt, where /proc/self/exe is the interpreter, still
	// requires the guest argv/maps/descriptor witness.
	rosettaProcess := interpreterTarget == rosettaInterpreterPath
	if selfInterpreter != runnerIdentity {
		if _, err := validateBinfmtGuestBinding(os.Getpid(), runnerArgs[0], runnerIdentity, false, rosettaProcess, built.dropper, procIdentity); err != nil {
			return processExecutableWitness{}, fmt.Errorf("bind emulated gate test runner: %w", err)
		}
	}
	mapDevice, err := validateBinfmtGuestBinding(pid, built.binary, target, true, rosettaProcess, built.dropper, procIdentity)
	if err != nil {
		return processExecutableWitness{}, fmt.Errorf("bind emulated shipped binary: %w", err)
	}
	return processExecutableWitness{
		Mode: processModeBinfmt, Target: target, Interpreter: procIdentity,
		ProcessStartTicks: startTicks, GuestMapDevice: mapDevice,
	}, nil
}

func validateShippedProcessPrivileges(pid int, expectedUID, expectedGID uint32) error {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody {
		return fmt.Errorf("read bounded shipped-process status: %w", err)
	}
	return validateShippedProcessStatus(raw, expectedUID, expectedGID)
}

func validateShippedProcessStatus(raw []byte, expectedUID, expectedGID uint32) error {
	fields := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[name] = strings.Fields(value)
		}
	}
	for name, expected := range map[string]uint32{"Uid": expectedUID, "Gid": expectedGID} {
		values := fields[name]
		if len(values) != 4 {
			return fmt.Errorf("shipped process %s identity is malformed", strings.ToLower(name))
		}
		for _, value := range values {
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil || uint32(parsed) != expected {
				return fmt.Errorf("shipped process %s identity changed", strings.ToLower(name))
			}
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if values := fields[name]; len(values) != 1 || values[0] != runtimeZeroCapabilityString {
			return fmt.Errorf("shipped process retained audit authority in %s", name)
		}
	}
	if values := fields["Groups"]; len(values) != 0 {
		return fmt.Errorf("shipped process retained supplementary groups")
	}
	if values := fields["TracerPid"]; len(values) != 1 || values[0] != "0" {
		return fmt.Errorf("shipped process is attached to a tracer")
	}
	bounding := fields["CapBnd"]
	boundValue, err := strconv.ParseUint(firstField(bounding), 16, 64)
	if err != nil || boundValue&^runtimeAuditCapabilityMask != 0 {
		return fmt.Errorf("shipped process capability bounding set is broader than the audit runner")
	}
	if values := fields["NoNewPrivs"]; len(values) != 1 || values[0] != "1" {
		return fmt.Errorf("shipped process lost no-new-privileges")
	}
	if values := fields["Seccomp"]; len(values) != 1 || values[0] != "2" {
		return fmt.Errorf("shipped process lost seccomp filtering")
	}
	return nil
}

func firstField(values []string) string {
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

// validateReviewedBinfmtInterpreter accepts the ordinary binfmt shape where
// the child and gate runner expose the same interpreter identity. Docker
// Desktop's Rosetta path is different: a process launched directly by the Go
// test exposes a kernel-injected, root-owned /run/rosetta/rosetta executable,
// while the already-running gate test exposes its guest binary in /proc/self.
// The exact path and immutable executable identity keep that compatibility
// case closed; validateBinfmtGuestBinding still binds argv, maps, map_files, and
// Rosetta-held descriptors to the exact gate-built guest bytes.
func validateReviewedBinfmtInterpreter(interpreterTarget string, interpreter, gateRunner, target executableIdentity) error {
	if interpreter == target {
		return fmt.Errorf("non-native interpreter aliases the gate-built target")
	}
	if interpreter == gateRunner {
		return nil
	}
	if interpreterTarget != rosettaInterpreterPath {
		return fmt.Errorf("non-native process executable %q is not a reviewed gate-runner interpreter", interpreterTarget)
	}
	if interpreter.UID != 0 || interpreter.Links != 1 || !interpreter.Mode.IsRegular() || interpreter.Mode.Perm()&0o111 == 0 || interpreter.Mode.Perm()&0o022 != 0 ||
		interpreter.Size <= 0 || interpreter.Size > maxShippedBinaryBytes || !validSHA256Digest(interpreter.Digest) {
		return fmt.Errorf("rosetta interpreter is not a bounded root-owned immutable executable")
	}
	return nil
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

func validateBinfmtGuestBinding(pid int, path string, identity executableIdentity, exactArgv, allowRosettaBindAlias bool, dropper executableIdentity, reviewedInterpreters ...executableIdentity) (string, error) {
	args, err := processCommandLine(pid)
	if err != nil || len(args) == 0 || args[0] != path || (exactArgv && len(args) != 1) {
		return "", fmt.Errorf("guest argv does not name only the exact private binary: %w", err)
	}
	mapDevice, err := validateGuestExecutableMaps(pid, path, identity, allowRosettaBindAlias, reviewedInterpreters...)
	if err != nil {
		return "", err
	}
	if err := validateRosettaGuestDescriptors(pid, path, identity, reviewedGuestDescriptor{path: runtimePrivilegeDropper, identity: dropper}); err != nil {
		return "", err
	}
	return mapDevice, nil
}

func validateGuestExecutableMaps(pid int, path string, identity executableIdentity, allowRosettaBindAlias bool, reviewedInterpreters ...executableIdentity) (string, error) {
	return validateGuestExecutableMapsAtForUIDWithRosettaAlias(filepath.Join("/proc", strconv.Itoa(pid)), path, identity, uint32(os.Geteuid()), allowRosettaBindAlias, reviewedInterpreters...) // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
}

func validateGuestExecutableMapsAt(procDir, path string, identity executableIdentity, reviewedInterpreters ...executableIdentity) (string, error) {
	return validateGuestExecutableMapsAtForUIDWithRosettaAlias(procDir, path, identity, uint32(os.Geteuid()), false, reviewedInterpreters...) // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
}

func validateGuestExecutableMapsAtForUID(procDir, path string, identity executableIdentity, runtimeUID uint32, reviewedInterpreters ...executableIdentity) (string, error) {
	return validateGuestExecutableMapsAtForUIDWithRosettaAlias(procDir, path, identity, runtimeUID, false, reviewedInterpreters...)
}

func validateGuestExecutableMapsAtForUIDWithRosettaAlias(procDir, path string, identity executableIdentity, runtimeUID uint32, allowRosettaBindAlias bool, reviewedInterpreters ...executableIdentity) (string, error) {
	raw, err := os.ReadFile(filepath.Join(procDir, "maps")) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody {
		return "", fmt.Errorf("read bounded guest executable maps: %w", err)
	}
	device := ""
	textDevice := ""
	mappings := 0
	executable := false
	aliasUsed := false
	reviewedInterpreterMapped := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// The gate-built path contains no whitespace. Comparing the first path
		// field intentionally still recognizes "path (deleted)" so a non-exec
		// target segment cannot disappear from the exact-map checks.
		targetPath := len(fields) >= 6 && fields[5] == path
		executableMap := strings.Contains(fields[1], "x")
		inode, parseErr := strconv.ParseUint(fields[4], 10, 64)
		fileBacked := parseErr == nil && inode != 0 && validProcMapDevice(fields[3])
		if !targetPath && (!executableMap || !fileBacked) {
			continue
		}
		if !fileBacked {
			return "", fmt.Errorf("guest executable map does not bind a regular file inode/device")
		}
		start, end, ok := strings.Cut(fields[0], "-")
		startValue, startErr := strconv.ParseUint(start, 16, 64)
		endValue, endErr := strconv.ParseUint(end, 16, 64)
		if !ok || startErr != nil || endErr != nil || startValue >= endValue {
			return "", fmt.Errorf("guest executable map has an invalid address range")
		}
		mapFile := filepath.Join(procDir, "map_files", fmt.Sprintf("%x-%x", startValue, endValue))
		mapped, exactTarget, reviewedObject, mainExecutable, inspectErr := inspectGuestMapObject(mapFile, identity, reviewedInterpreters...)
		if inspectErr != nil {
			return "", fmt.Errorf("inspect kernel map_files executable object: %w", inspectErr)
		}
		// Docker Desktop's Rosetta layer gives a bind-mounted guest executable a
		// synthetic device number in /proc/PID/maps while the kernel-owned
		// map_files object and the mounted pathname expose the real device. The
		// opened object is authoritative: permit that textual device alias only
		// after its metadata and full digest match the exact gate-built target.
		// Inode disagreement, or any alias for a non-target object, still fails.
		deviceMatches := procMapDeviceMatches(fields[3], mapped.Device)
		if inode != mapped.Inode || (!deviceMatches && !exactTarget) {
			mappedPath := ""
			if len(fields) >= 6 {
				mappedPath = fields[5]
			}
			return "", fmt.Errorf("guest executable map text disagrees with its kernel map_files object: range=%s path=%q text=%s/%d object=%x:%x/%d exact_target=%t",
				fields[0], mappedPath, fields[3], inode, unix.Major(mapped.Device), unix.Minor(mapped.Device), mapped.Inode, exactTarget)
		}
		if !deviceMatches && exactTarget {
			if !allowRosettaBindAlias {
				return "", fmt.Errorf("exact target map uses a device alias outside the reviewed Rosetta boundary")
			}
			if err := validateRosettaBindDeviceAlias(procDir, path, fields[3]); err != nil {
				return "", err
			}
			aliasUsed = true
		}
		// Rosetta may map its immutable root-owned runtime and system libraries.
		// A second executable regular file owned by the runtime UID, however, is
		// another caller-controlled guest candidate and makes argv existential.
		if executableMap && !reviewedObject && mainExecutable {
			return "", fmt.Errorf("guest process maps a foreign main-executable ELF object")
		}
		if executableMap && mapped.UID == runtimeUID && !reviewedObject {
			return "", fmt.Errorf("guest process maps a foreign caller-owned executable object")
		}
		if executableMap && reviewedObject && !exactTarget {
			reviewedInterpreterMapped = true
		}
		if !targetPath {
			continue
		}
		if len(fields) != 6 || strings.Contains(line, " (deleted)") {
			return "", fmt.Errorf("guest executable map has a non-exact/deleted pathname")
		}
		linkTarget, linkErr := os.Readlink(mapFile)
		if linkErr != nil || linkTarget != path || !exactTarget {
			return "", fmt.Errorf("kernel map_files entry is not the exact private binary object: %w", linkErr)
		}
		if textDevice == "" {
			textDevice = fields[3]
		} else if textDevice != fields[3] {
			return "", fmt.Errorf("guest executable maps disagree on textual device identity")
		}
		objectDevice := fmt.Sprintf("%x:%x", unix.Major(mapped.Device), unix.Minor(mapped.Device))
		if device == "" {
			device = objectDevice
		} else if device != objectDevice {
			return "", fmt.Errorf("guest executable maps disagree on device identity")
		}
		mappings++
		if executableMap && fields[2] == "00000000" {
			executable = true
		}
	}
	if mappings < 2 || !executable || device == "" {
		return "", fmt.Errorf("guest process has no complete exact executable mapping")
	}
	if aliasUsed && !reviewedInterpreterMapped {
		return "", fmt.Errorf("rosetta bind-device alias has no exact reviewed interpreter mapping")
	}
	return device, nil
}

func validateRosettaBindDeviceAlias(procDir, targetPath, alias string) error {
	raw, err := os.ReadFile(filepath.Join(procDir, "mountinfo")) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil || len(raw) == 0 || len(raw) > maxEvidenceBody {
		return fmt.Errorf("read bounded Rosetta mount provenance: %w", err)
	}
	aliasMajor, aliasMinor, err := parseProcMapDevice(alias, 16)
	if err != nil {
		return fmt.Errorf("parse Rosetta map device alias: %w", err)
	}
	targetPath = filepath.Clean(targetPath)
	if !filepath.IsAbs(targetPath) {
		return fmt.Errorf("rosetta target path is not absolute")
	}
	type mountIdentity struct {
		major, minor       uint64
		mountpoint, fsType string
		source             string
	}
	var best mountIdentity
	bestLength := -1
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) <= separator+2 {
			continue
		}
		mountpoint, decodeErr := decodeProcMountField(fields[4])
		source, sourceErr := decodeProcMountField(fields[separator+2])
		major, minor, deviceErr := parseProcMapDevice(fields[2], 10)
		mountpoint = filepath.Clean(mountpoint)
		if decodeErr != nil || sourceErr != nil || deviceErr != nil || !filepath.IsAbs(mountpoint) || !pathLexicallyInside(mountpoint, targetPath) {
			continue
		}
		if len(mountpoint) > bestLength {
			bestLength = len(mountpoint)
			best = mountIdentity{major: major, minor: minor, mountpoint: mountpoint, fsType: fields[separator+1], source: source}
		}
	}
	if bestLength < 0 || best.major != aliasMajor || best.minor != aliasMinor || best.fsType != "fakeowner" || best.source != "/run/host_mark/private" {
		return fmt.Errorf("rosetta map device alias %s is not the most-specific fakeowner /run/host_mark/private mount for %q", alias, targetPath)
	}
	return nil
}

func parseProcMapDevice(value string, base int) (uint64, uint64, error) {
	major, minor, ok := strings.Cut(value, ":")
	if !ok || major == "" || minor == "" {
		return 0, 0, fmt.Errorf("device %q has no exact major:minor pair", value)
	}
	majorValue, majorErr := strconv.ParseUint(major, base, 32)
	minorValue, minorErr := strconv.ParseUint(minor, base, 32)
	if majorErr != nil || minorErr != nil {
		return 0, 0, fmt.Errorf("device %q is malformed", value)
	}
	return majorValue, minorValue, nil
}

func decodeProcMountField(value string) (string, error) {
	var decoded strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("mount field %q has a truncated escape", value)
		}
		escaped := value[index+1 : index+4]
		parsed, err := strconv.ParseUint(escaped, 8, 8)
		if err != nil || (escaped != "040" && escaped != "011" && escaped != "012" && escaped != "134") {
			return "", fmt.Errorf("mount field %q has an unreviewed escape", value)
		}
		decoded.WriteByte(byte(parsed))
		index += 3
	}
	return decoded.String(), nil
}

func pathLexicallyInside(root, candidate string) bool {
	if root == "/" || root == candidate {
		return true
	}
	return strings.HasPrefix(candidate, root+string(filepath.Separator))
}

// inspectGuestMapObject follows the kernel-owned map_files magic link, opens
// that mapped object, and compares the object rather than accepting the display
// pathname from /proc/PID/maps. Target objects additionally have their full
// metadata and digest rebound through the same stable open file description.
func inspectGuestMapObject(mapFile string, target executableIdentity, reviewedInterpreters ...executableIdentity) (executableIdentity, bool, bool, bool, error) {
	file, err := os.Open(mapFile) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil {
		return executableIdentity{}, false, false, false, err
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil {
		return executableIdentity{}, false, false, false, err
	}
	actual, err := executableIdentityFromInfo(before)
	if err != nil {
		return executableIdentity{}, false, false, false, err
	}
	if !before.Mode().IsRegular() {
		return executableIdentity{}, false, false, false, fmt.Errorf("mapped executable object is not a regular file")
	}
	exactObject := actual.Device == target.Device && actual.Inode == target.Inode
	reviewedObject := exactObject
	pinned := target
	if !exactObject {
		for _, interpreter := range reviewedInterpreters {
			if actual.Device == interpreter.Device && actual.Inode == interpreter.Inode {
				pinned = interpreter
				reviewedObject = true
				break
			}
		}
	}
	if reviewedObject {
		metadata := pinned
		metadata.Digest = ""
		if actual != metadata || before.Size() <= 0 || before.Size() > maxShippedBinaryBytes {
			return executableIdentity{}, false, false, false, fmt.Errorf("mapped reviewed executable metadata differs from its pinned binary")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return executableIdentity{}, false, false, false, err
		}
		digest, size, err := internalcrypto.SHA256ReaderHex(io.LimitReader(file, maxShippedBinaryBytes+1))
		if err != nil {
			return executableIdentity{}, false, false, false, err
		}
		if size != before.Size() || size > maxShippedBinaryBytes {
			return executableIdentity{}, false, false, false, fmt.Errorf("mapped reviewed executable size changed while hashing")
		}
		actual.Digest = "sha256:" + digest
		if actual != pinned {
			return executableIdentity{}, false, false, false, fmt.Errorf("mapped reviewed executable bytes differ from its pinned binary")
		}
	}
	mainExecutable := mappedELFMainExecutable(file)
	after, err := file.Stat()
	if err != nil {
		return executableIdentity{}, false, false, false, err
	}
	afterIdentity, err := executableIdentityFromInfo(after)
	if err != nil {
		return executableIdentity{}, false, false, false, err
	}
	afterIdentity.Digest = actual.Digest
	if afterIdentity != actual {
		return executableIdentity{}, false, false, false, fmt.Errorf("mapped executable object changed while inspecting it")
	}
	return actual, exactObject, reviewedObject, mainExecutable, nil
}

func mappedELFMainExecutable(file *os.File) bool {
	binary, err := elf.NewFile(file)
	if err != nil {
		return false
	}
	if binary.Type == elf.ET_EXEC {
		return true
	}
	if binary.Type != elf.ET_DYN {
		return false
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return true
		}
	}
	flags, err := binary.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return false
	}
	for _, value := range flags {
		if value&uint64(elf.DF_1_PIE) != 0 {
			return true
		}
	}
	return false
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

func procMapDeviceMatches(value string, device uint64) bool {
	major, minor, ok := strings.Cut(value, ":")
	if !ok {
		return false
	}
	majorValue, majorErr := strconv.ParseUint(major, 16, 32)
	minorValue, minorErr := strconv.ParseUint(minor, 16, 32)
	return majorErr == nil && minorErr == nil &&
		majorValue == uint64(unix.Major(device)) && minorValue == uint64(unix.Minor(device))
}

type reviewedGuestDescriptor struct {
	path     string
	identity executableIdentity
}

func validateRosettaGuestDescriptors(pid int, path string, identity executableIdentity, reviewed ...reviewedGuestDescriptor) error {
	return validateRosettaGuestDescriptorsAt(filepath.Join("/proc", strconv.Itoa(pid)), path, identity, reviewed...)
}

func validateRosettaGuestDescriptorsAt(procDir, path string, identity executableIdentity, reviewed ...reviewedGuestDescriptor) error {
	entries, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return err
	}
	positions := map[uint64]bool{}
	reviewedPositions := make(map[string]map[uint64]bool, len(reviewed))
	for _, descriptor := range reviewed {
		if descriptor.path == "" || descriptor.path == path || descriptor.identity == (executableIdentity{}) {
			return fmt.Errorf("reviewed translator descriptor is incomplete or aliases the target")
		}
		if _, exists := reviewedPositions[descriptor.path]; exists {
			return fmt.Errorf("reviewed translator descriptor path is duplicated")
		}
		reviewedPositions[descriptor.path] = map[uint64]bool{}
	}
	matches := 0
	for _, entry := range entries {
		fd := entry.Name()
		fdPath := filepath.Join(procDir, "fd", fd)
		target, readErr := os.Readlink(fdPath)
		if readErr != nil {
			continue
		}
		infoRaw, infoErr := os.ReadFile(filepath.Join(procDir, "fdinfo", fd)) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if infoErr != nil {
			return fmt.Errorf("read translator descriptor metadata: %w", infoErr)
		}
		position, flags, parseErr := parseTranslatorFDInfo(infoRaw)
		if parseErr != nil {
			return fmt.Errorf("parse translator descriptor metadata: %w", parseErr)
		}
		guestShaped := flags == "0400040" && (position == 0 || position == 64)
		if !guestShaped {
			if target == path {
				return fmt.Errorf("translator descriptor naming the private binary has unexpected position/flags")
			}
			for _, descriptor := range reviewed {
				if target == descriptor.path {
					return fmt.Errorf("translator descriptor naming the reviewed privilege dropper has unexpected position/flags")
				}
			}
			continue
		}
		actual, _, inspectErr := inspectExecutable(fdPath, true, false)
		if inspectErr != nil {
			if target == path || reviewedPositions[target] != nil {
				return fmt.Errorf("inspect expected translator guest descriptor %q: %w", target, inspectErr)
			}
			// Ordinary config/license files can share Rosetta's read-only,
			// CLOEXEC, offset-0/64 flag shape. They are not guest executable
			// candidates unless they are executable ELF main objects.
			continue
		}
		if target == path {
			if actual != identity {
				return fmt.Errorf("translator descriptor naming the private binary has foreign bytes")
			}
			if positions[position] {
				return fmt.Errorf("translator guest descriptor has an unexpected position/flags invariant")
			}
			positions[position] = true
			matches++
			continue
		}
		reviewedMatch := false
		for _, descriptor := range reviewed {
			if target != descriptor.path {
				continue
			}
			if actual != descriptor.identity {
				return fmt.Errorf("translator descriptor naming the reviewed privilege dropper has foreign bytes")
			}
			if reviewedPositions[descriptor.path][position] {
				return fmt.Errorf("translator privilege-dropper descriptor duplicates position %d", position)
			}
			reviewedPositions[descriptor.path][position] = true
			reviewedMatch = true
			break
		}
		if reviewedMatch {
			continue
		}
		mainExecutable, mainErr := descriptorELFMainExecutable(fdPath)
		if mainErr != nil {
			return fmt.Errorf("classify translator descriptor %q: %w", target, mainErr)
		}
		if mainExecutable {
			return fmt.Errorf("translator guest-shaped ELF descriptor %q at position %d is neither the exact private binary nor an exact reviewed privilege dropper", target, position)
		}
	}
	if matches < 1 || matches > 2 || !positions[64] {
		return fmt.Errorf("translator does not hold the pinned digest-bound guest executable descriptor at position 64")
	}
	for descriptorPath, found := range reviewedPositions {
		if len(found) != 2 || !found[0] || !found[64] {
			return fmt.Errorf("translator does not hold both exact privilege-dropper descriptors for %s", descriptorPath)
		}
	}
	return nil
}

func descriptorELFMainExecutable(path string) (bool, error) {
	file, err := os.Open(path) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	return mappedELFMainExecutable(file), nil
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

func requireAllProcessSocketsExclusive(pid int, built shippedBuild, expected expectation) error {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return err
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		descriptorPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name())
		target, readErr := os.Readlink(descriptorPath)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return readErr
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		descriptor, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || descriptor <= 2 {
			return fmt.Errorf("launched socket has invalid descriptor %q", entry.Name())
		}
		if flagErr := requireLinuxDescriptorCloseOnExec(pid, descriptor); flagErr != nil {
			if errors.Is(flagErr, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("launched socket descriptor %d is inheritable: %w", descriptor, flagErr)
		}
		after, afterErr := os.Readlink(descriptorPath)
		if afterErr != nil {
			if os.IsNotExist(afterErr) {
				continue
			}
			return afterErr
		}
		if after != target {
			// A short-lived connection closed and its descriptor was reused while
			// being sampled. It is no longer one stable socket object to audit.
			continue
		}
		inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
	}
	if len(inodes) == 0 {
		return errNoStableProcessSockets
	}
	for inode := range inodes {
		if err := requireExclusiveSocketOwner(pid, inode, built, expected, true); err != nil {
			return err
		}
	}
	return nil
}

func requireExclusiveSocketOwner(pid int, inode string, built shippedBuild, expected expectation, parentDescriptorSealed ...bool) error {
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
	if !ok || procStat.Uid != uint32(os.Geteuid()) { // #nosec G115 -- bounded value packing in a developer tool, not a served binary (CWE-190)
		return fmt.Errorf("launched PID is not owned by the gate runtime UID")
	}
	sealed := len(parentDescriptorSealed) == 1 && parentDescriptorSealed[0]
	if !sealed {
		descriptors, descriptorErr := processSocketDescriptorNumbers(pid, inode)
		if descriptorErr != nil {
			return descriptorErr
		}
		for _, descriptor := range descriptors {
			if descriptor <= 2 {
				return fmt.Errorf("socket inode %s occupies inherited descriptor %d", inode, descriptor)
			}
			if descriptorErr := requireLinuxDescriptorCloseOnExec(pid, descriptor); descriptorErr != nil {
				return fmt.Errorf("socket descriptor %d is inheritable: %w", descriptor, descriptorErr)
			}
		}
		sealed = true
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
			// A zombie has exited and its descriptor table has already been
			// destroyed; only the waitable PID record remains. Container PID 1
			// may retain such records between sequential full-census groups. It
			// cannot own or inherit the live socket inode being audited.
			if raw, statusErr := os.ReadFile(filepath.Join(candidateRoot, "status")); statusErr == nil && processStatusIsZombie(raw) { // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
				continue
			}
			companionErr := fmt.Errorf("not an unreadable shipped companion")
			if os.IsPermission(readErr) {
				companionErr = validateUnreadableShippedCompanion(pid, candidate, built, expected, sealed)
				if companionErr == nil {
					continue
				}
			}
			return fmt.Errorf("scan same-UID PID %d descriptors (%s; companion-proof=%v): %w", candidate, boundedProcessSummary(candidate), companionErr, readErr)
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
	if err := validateObservedSocketOwners(pid, owners); err != nil {
		return fmt.Errorf("socket inode %s: %w", inode, err)
	}
	return nil
}

func processStatusIsZombie(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "State:") {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) >= 2 && fields[1] == "Z"
	}
	return false
}

func validateObservedSocketOwners(parentPID int, owners map[int]bool) error {
	if parentPID <= 0 {
		return fmt.Errorf("socket parent PID is invalid")
	}
	for owner := range owners {
		if owner != parentPID {
			return fmt.Errorf("same-UID owners = %v, want no owner or only PID %d", sortedPIDs(owners), parentPID)
		}
	}
	if len(owners) > 1 {
		return fmt.Errorf("same-UID owners = %v, want no owner or only PID %d", sortedPIDs(owners), parentPID)
	}
	// Zero owners is valid for a connection that closed after the parent FD was
	// sampled with O_CLOEXEC. Unreadable direct companions are accepted above
	// only after the production source proves it passes no descriptors and the
	// live child is the exact hardened companion. A readable foreign owner still
	// fails above.
	return nil
}

type reviewedCompanionStatus struct {
	name         string
	state        string
	parentPID    int
	noNewPrivs   string
	seccomp      string
	requiredSeen int
}

func validateUnreadableShippedCompanion(parentPID, candidatePID int, built shippedBuild, expected expectation, parentDescriptorSealed bool) error {
	if parentPID <= 0 || candidatePID <= 0 || candidatePID == parentPID {
		return fmt.Errorf("companion process relationship is invalid")
	}
	if !built.companionFDIsolation {
		return fmt.Errorf("gate build has no causal companion FD-isolation proof")
	}
	if !parentDescriptorSealed {
		return fmt.Errorf("parent socket descriptor was not causally sampled with close-on-exec")
	}
	status, err := readReviewedCompanionStatus(candidatePID)
	if err != nil {
		return fmt.Errorf("read unreadable companion hardening status: %w", err)
	}
	if err := validateUnreadableCompanionStatus(parentPID, status); err != nil {
		return err
	}
	parentStart, err := processStartTime(parentPID)
	if err != nil {
		return err
	}
	candidateStart, err := processStartTime(candidatePID)
	if err != nil || candidateStart <= parentStart {
		return fmt.Errorf("companion start time does not follow its launched parent: %w", err)
	}
	args, err := processCommandLine(candidatePID)
	if err != nil || len(args) == 0 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		return fmt.Errorf("companion command line has no exact absolute executable: %w", err)
	}
	if err := validateShippedArgs(args); err != nil {
		return err
	}
	matchedPackage := ""
	matchedPath := ""
	expectedPaths := make([]string, 0, len(expected.LaunchedCompanions))
	for _, packagePath := range expected.LaunchedCompanions {
		name, nameErr := shippedPackageName(packagePath)
		if nameErr != nil {
			return nameErr
		}
		expectedPath := filepath.Join(built.binDir, name)
		expectedPaths = append(expectedPaths, expectedPath)
		pathMatches := samePrivateReceiptObject(filepath.Dir(expected.EvidenceFile), expectedPath, args[0]) == nil
		// PR_SET_DUMPABLE=0 deliberately hides a Rosetta guest's argv/path from
		// non-root ancestors and exposes only the reviewed interpreter. In that
		// exact case the direct parent/name/start-time and causal FD-isolation
		// checks above bind the child role, while the cached sibling path bytes
		// below remain immutable and profile-validated.
		hardenedRosetta := args[0] == rosettaInterpreterPath
		if status.name == name && (pathMatches || hardenedRosetta) {
			matchedPackage = packagePath
			matchedPath = expectedPath
			break
		}
	}
	if matchedPackage == "" {
		return fmt.Errorf("unreadable process is not an expected shipped companion: argv0=%q expected=%q", args[0], expectedPaths)
	}
	wantIdentity, ok := built.companions[matchedPackage]
	if !ok {
		return fmt.Errorf("shipped companion has no gate-build identity")
	}
	actual, err := validateShippedBinary(matchedPath, expected, matchedPackage, false)
	if err != nil || actual != wantIdentity {
		return fmt.Errorf("shipped companion path changed after gate build: %w", err)
	}
	if live, _, liveErr := inspectExecutable(filepath.Join("/proc", strconv.Itoa(candidatePID), "exe"), true, false); liveErr == nil {
		if live != wantIdentity {
			return fmt.Errorf("readable companion process executable differs from gate build")
		}
	} else if !os.IsPermission(liveErr) {
		return fmt.Errorf("inspect companion process executable: %w", liveErr)
	}
	return nil
}

func validateUnreadableCompanionStatus(parentPID int, status reviewedCompanionStatus) error {
	if status.parentPID != parentPID || status.state == "Z" || status.state == "X" ||
		status.noNewPrivs != "1" || status.seccomp != "2" {
		return fmt.Errorf("unreadable process is not a hardened live direct companion: name=%q state=%q parent=%d no_new_privs=%q seccomp=%q",
			status.name, status.state, status.parentPID, status.noNewPrivs, status.seccomp)
	}
	return nil
}

func samePrivateReceiptObject(receiptRoot, expectedPath, actualPath string) error {
	if _, err := validateRuntimeTempDirectory(receiptRoot); err != nil {
		return err
	}
	relative := func(path string) (string, error) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
			return "", fmt.Errorf("private receipt object path is not clean and absolute")
		}
		for _, root := range []string{receiptRoot, RuntimeTempDir} {
			value, err := filepath.Rel(root, path)
			if err == nil && value != "." && value != ".." && !strings.HasPrefix(value, ".."+string(filepath.Separator)) {
				return value, nil
			}
		}
		return "", fmt.Errorf("private receipt object is outside both gate-owned mount paths")
	}
	expectedRelative, err := relative(expectedPath)
	if err != nil {
		return err
	}
	actualRelative, err := relative(actualPath)
	if err != nil || actualRelative != expectedRelative {
		return fmt.Errorf("private receipt aliases do not have the same closed suffix")
	}
	expectedInfo, err := os.Lstat(expectedPath)
	if err != nil || expectedInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("inspect expected private receipt object: %w", err)
	}
	actualInfo, err := os.Lstat(actualPath)
	if err != nil || actualInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("inspect actual private receipt object: %w", err)
	}
	if !os.SameFile(expectedInfo, actualInfo) {
		return fmt.Errorf("private receipt aliases are not the same inode")
	}
	return nil
}

func processSocketDescriptorNumbers(pid int, inode string) ([]int, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("socket descriptor owner PID is invalid")
	}
	want := "socket:[" + inode + "]"
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, err
	}
	descriptors := make([]int, 0, 1)
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return nil, readErr
		}
		if target != want {
			continue
		}
		descriptor, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || descriptor < 0 {
			return nil, fmt.Errorf("socket inode %s has invalid descriptor %q", inode, entry.Name())
		}
		descriptors = append(descriptors, descriptor)
	}
	if len(descriptors) == 0 {
		return nil, fmt.Errorf("launched PID %d no longer owns socket inode %s", pid, inode)
	}
	sort.Ints(descriptors)
	return descriptors, nil
}

func requireLinuxDescriptorCloseOnExec(pid, descriptor int) error {
	if pid <= 0 || descriptor < 0 {
		return fmt.Errorf("descriptor identity is invalid")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "fdinfo", strconv.Itoa(descriptor)))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return fmt.Errorf("read bounded listener fdinfo: %w", err)
	}
	return requireLinuxDescriptorCloseOnExecFlags(raw)
}

func requireLinuxDescriptorCloseOnExecFlags(raw []byte) error {
	_, flags, err := parseTranslatorFDInfo(raw)
	if err != nil {
		return err
	}
	value, err := strconv.ParseUint(flags, 8, 64)
	if err != nil {
		return fmt.Errorf("listener fdinfo has non-octal flags %q", flags)
	}
	// Linux O_CLOEXEC is 02000000. This proof reads Linux /proc even when its
	// unit tests compile on another host, so do not use a host-specific constant.
	const linuxOCloexec = uint64(0o2000000)
	if value&linuxOCloexec == 0 {
		return fmt.Errorf("listener descriptor omits Linux O_CLOEXEC")
	}
	return nil
}

func readReviewedCompanionStatus(pid int) (reviewedCompanionStatus, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return reviewedCompanionStatus{}, fmt.Errorf("read bounded companion status: %w", err)
	}
	return parseReviewedCompanionStatus(raw)
}

func parseReviewedCompanionStatus(raw []byte) (reviewedCompanionStatus, error) {
	status := reviewedCompanionStatus{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Name":
			if len(fields) != 2 || strings.ContainsAny(fields[1], "\r\n\x00") {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has an invalid name")
			}
			status.name = fields[1]
			status.requiredSeen++
		case "State":
			if len(fields[1]) != 1 {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has an invalid state")
			}
			status.state = fields[1]
			status.requiredSeen++
		case "PPid":
			if len(fields) != 2 {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has an invalid parent")
			}
			parentPID, parseErr := strconv.Atoi(fields[1])
			if parseErr != nil || parentPID <= 0 {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has an invalid parent PID")
			}
			status.parentPID = parentPID
			status.requiredSeen++
		case "NoNewPrivs":
			if len(fields) != 2 {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has invalid no-new-privileges state")
			}
			status.noNewPrivs = fields[1]
			status.requiredSeen++
		case "Seccomp":
			if len(fields) != 2 {
				return reviewedCompanionStatus{}, fmt.Errorf("companion status has invalid seccomp state")
			}
			status.seccomp = fields[1]
			status.requiredSeen++
		}
	}
	if status.requiredSeen != 5 {
		return reviewedCompanionStatus{}, fmt.Errorf("companion status omits a required hardening field")
	}
	return status, nil
}

func boundedProcessSummary(pid int) string {
	fields := []string{"Name:", "State:", "PPid:", "NSpid:", "NoNewPrivs:", "Seccomp:"}
	values := make([]string, 0, len(fields)+1)
	if raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status")); err == nil && len(raw) <= 64<<10 {
		for _, line := range strings.Split(string(raw), "\n") {
			for _, field := range fields {
				if strings.HasPrefix(line, field) {
					values = append(values, strings.Join(strings.Fields(line), "="))
					break
				}
			}
		}
	}
	if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil && filepath.IsAbs(target) && !strings.ContainsAny(target, "\r\n\x00") {
		values = append(values, "exe="+target)
	}
	if len(values) == 0 {
		return "identity unavailable"
	}
	return strings.Join(values, ",")
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
