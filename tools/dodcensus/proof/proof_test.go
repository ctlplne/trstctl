// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

func TestSealDescriptorCloseOnExecClosesForeignInheritance(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	descriptor := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := sealDescriptorCloseOnExec(descriptor); err != nil {
		t.Fatal(err)
	}
	sealed, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sealed&unix.FD_CLOEXEC == 0 {
		t.Fatal("descriptor remains inheritable after sealing")
	}
}

func TestValidateObservedSocketOwnersAllowsOnlyParentOrClosedRace(t *testing.T) {
	const parentPID = 41
	for name, owners := range map[string]map[int]bool{
		"parent still owns socket":            {parentPID: true},
		"socket closed after sealed snapshot": {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateObservedSocketOwners(parentPID, owners); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, owners := range map[string]map[int]bool{
		"foreign owner":            {99: true},
		"parent and foreign owner": {parentPID: true, 99: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateObservedSocketOwners(parentPID, owners); err == nil {
				t.Fatal("foreign same-UID socket owner was accepted")
			}
		})
	}
	if err := validateObservedSocketOwners(0, nil); err == nil {
		t.Fatal("invalid parent PID was accepted")
	}
}

func TestSocketOwnershipReadinessRetriesOnlyEmptyStableSample(t *testing.T) {
	done := make(chan struct{})
	attempts := 0
	err := waitForSocketOwnershipAudit(done, time.Now().Add(time.Second), func() error {
		attempts++
		if attempts < 3 {
			return errNoStableProcessSockets
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("delayed stable socket audit = attempts=%d err=%v, want third-attempt success", attempts, err)
	}

	permissionErr := os.ErrPermission
	attempts = 0
	err = waitForSocketOwnershipAudit(done, time.Now().Add(time.Second), func() error {
		attempts++
		return permissionErr
	})
	if !errors.Is(err, permissionErr) || attempts != 1 {
		t.Fatalf("unreadable sibling audit = attempts=%d err=%v, want immediate permission failure", attempts, err)
	}

	close(done)
	attempts = 0
	err = waitForSocketOwnershipAudit(done, time.Now().Add(time.Second), func() error {
		attempts++
		return errNoStableProcessSockets
	})
	if !errors.Is(err, errNoStableProcessSockets) || attempts != 1 {
		t.Fatalf("stopped process audit = attempts=%d err=%v, want immediate empty-sample failure", attempts, err)
	}
}

func TestLaunchedRequestAuditsAllSocketsBeforeAndAfterResponse(t *testing.T) {
	raw, err := os.ReadFile("launched.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, anchor := range []string{
		`DOD-CENSUS: pre-request launched socket ownership`,
		`allExclusiveErr := requireAllProcessSocketsExclusive(command.Process.Pid, p.build, p.expect)`,
		`all_sockets=%v`,
	} {
		if !strings.Contains(source, anchor) {
			t.Errorf("launched request socket proof omits %q", anchor)
		}
	}
}

func TestReviewedBinfmtInterpreterIsClosedToExactImmutableRosetta(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	target := executableIdentity{Device: 1, Inode: 10, Links: 1, UID: 501, Size: 4096, Mode: 0o700, Digest: digest}
	runner := executableIdentity{Device: 1, Inode: 11, Links: 1, UID: 501, Size: 4096, Mode: 0o500, Digest: digest}
	rosetta := executableIdentity{Device: 2, Inode: 2, Links: 1, UID: 0, Size: 8192, Mode: 0o555, Digest: digest}
	if err := validateReviewedBinfmtInterpreter("/any/interpreter", runner, runner, target); err != nil {
		t.Fatalf("same gate-runner interpreter rejected: %v", err)
	}
	if err := validateReviewedBinfmtInterpreter(rosettaInterpreterPath, rosetta, runner, target); err != nil {
		t.Fatalf("exact immutable Rosetta interpreter rejected: %v", err)
	}
	for name, test := range map[string]struct {
		path     string
		identity executableIdentity
	}{
		"target alias":     {path: rosettaInterpreterPath, identity: target},
		"near path":        {path: rosettaInterpreterPath + "-fake", identity: rosetta},
		"user owned":       {path: rosettaInterpreterPath, identity: func() executableIdentity { value := rosetta; value.UID = 501; return value }()},
		"world writable":   {path: rosettaInterpreterPath, identity: func() executableIdentity { value := rosetta; value.Mode = 0o577; return value }()},
		"multiple links":   {path: rosettaInterpreterPath, identity: func() executableIdentity { value := rosetta; value.Links = 2; return value }()},
		"unbounded size":   {path: rosettaInterpreterPath, identity: func() executableIdentity { value := rosetta; value.Size = maxShippedBinaryBytes + 1; return value }()},
		"malformed digest": {path: rosettaInterpreterPath, identity: func() executableIdentity { value := rosetta; value.Digest = "sha256:no"; return value }()},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReviewedBinfmtInterpreter(test.path, test.identity, runner, target); err == nil {
				t.Fatal("unsafe interpreter identity accepted")
			}
		})
	}
}

func TestGuestExecutableMapsBindOnlyTheExactCallerExecutable(t *testing.T) {
	t.Run("exact target maps", func(t *testing.T) {
		procDir, targetPath, target, _ := guestProcessFixture(t)
		writeGuestMaps(t, procDir, targetPath, target, "", executableIdentity{})
		device, err := validateGuestExecutableMapsAt(procDir, targetPath, target)
		if err != nil {
			t.Fatalf("exact target mappings rejected: %v", err)
		}
		if device != procMapDeviceForTest(target.Device) {
			t.Fatalf("map device = %q, want %q", device, procMapDeviceForTest(target.Device))
		}
	})

	t.Run("target plus foreign caller executable", func(t *testing.T) {
		procDir, targetPath, target, foreignPath := guestProcessFixture(t)
		foreign, _, err := inspectExecutable(foreignPath, false, false)
		if err != nil {
			t.Fatal(err)
		}
		writeGuestMaps(t, procDir, targetPath, target, foreignPath, foreign)
		if _, err := validateGuestExecutableMapsAt(procDir, targetPath, target); err == nil || !strings.Contains(err.Error(), "foreign caller-owned executable") {
			t.Fatalf("foreign caller executable mapping was accepted: %v", err)
		}
	})

	t.Run("target plus foreign-owner main executable", func(t *testing.T) {
		procDir, targetPath, target, foreignPath := guestProcessFixture(t)
		if err := os.WriteFile(foreignPath, minimalELFExecutable(), 0o700); err != nil {
			t.Fatal(err)
		}
		foreign, _, err := inspectExecutable(foreignPath, false, false)
		if err != nil {
			t.Fatal(err)
		}
		writeGuestMaps(t, procDir, targetPath, target, foreignPath, foreign)
		syntheticRuntimeUID := foreign.UID + 1
		if syntheticRuntimeUID == foreign.UID {
			t.Fatal("cannot construct a distinct synthetic runtime UID")
		}
		if _, err := validateGuestExecutableMapsAtForUID(procDir, targetPath, target, syntheticRuntimeUID); err == nil || !strings.Contains(err.Error(), "foreign main-executable ELF") {
			t.Fatalf("foreign-owner main executable mapping was accepted: %v", err)
		}
	})

	t.Run("target plus exact reviewed interpreter", func(t *testing.T) {
		procDir, targetPath, target, interpreterPath := guestProcessFixture(t)
		if err := os.WriteFile(interpreterPath, minimalELFExecutable(), 0o700); err != nil {
			t.Fatal(err)
		}
		interpreter, _, err := inspectExecutable(interpreterPath, false, false)
		if err != nil {
			t.Fatal(err)
		}
		writeGuestMaps(t, procDir, targetPath, target, interpreterPath, interpreter)
		if _, err := validateGuestExecutableMapsAt(procDir, targetPath, target, interpreter); err != nil {
			t.Fatalf("exact reviewed interpreter mapping rejected: %v", err)
		}
	})

	t.Run("target pathname with foreign map_files object", func(t *testing.T) {
		procDir, targetPath, target, foreignPath := guestProcessFixture(t)
		writeGuestMaps(t, procDir, targetPath, target, "", executableIdentity{})
		mapFile := filepath.Join(procDir, "map_files", "1000-2000")
		if err := os.Remove(mapFile); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(foreignPath, mapFile); err != nil {
			t.Fatal(err)
		}
		if _, err := validateGuestExecutableMapsAt(procDir, targetPath, target); err == nil || !strings.Contains(err.Error(), "map text disagrees") {
			t.Fatalf("foreign map_files object behind target pathname was accepted: %v", err)
		}
	})

	t.Run("exact target accepts only mount-bound Rosetta device alias", func(t *testing.T) {
		procDir, targetPath, target, interpreterPath := guestProcessFixture(t)
		if err := os.WriteFile(interpreterPath, minimalELFExecutable(), 0o700); err != nil {
			t.Fatal(err)
		}
		interpreter, _, err := inspectExecutable(interpreterPath, false, false)
		if err != nil {
			t.Fatal(err)
		}
		writeGuestMaps(t, procDir, targetPath, target, interpreterPath, interpreter)
		mapsPath := filepath.Join(procDir, "maps")
		raw, err := os.ReadFile(mapsPath)
		if err != nil {
			t.Fatal(err)
		}
		aliased := strings.Replace(string(raw), procMapDeviceForTest(target.Device), "00:dead", 2)
		if err := os.WriteFile(mapsPath, []byte(aliased), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := validateGuestExecutableMapsAt(procDir, targetPath, target, interpreter); err == nil || !strings.Contains(err.Error(), "outside the reviewed Rosetta boundary") {
			t.Fatalf("arbitrary device alias passed without Rosetta provenance: %v", err)
		}
		mountInfo := fmt.Sprintf("245 233 0:57005 / %s rw,nosuid,nodev - fakeowner /run/host_mark/private rw,fakeowner\n", targetPath)
		if err := os.WriteFile(filepath.Join(procDir, "mountinfo"), []byte(mountInfo), 0o600); err != nil {
			t.Fatal(err)
		}
		device, err := validateGuestExecutableMapsAtForUIDWithRosettaAlias(procDir, targetPath, target, target.UID, true, interpreter)
		if err != nil {
			t.Fatalf("exact kernel object behind Rosetta device alias rejected: %v", err)
		}
		if device != procMapDeviceForTest(target.Device) {
			t.Fatalf("canonical map_files device = %q, want %q", device, procMapDeviceForTest(target.Device))
		}
	})
}

func TestRosettaGuestDescriptorsBindEveryGuestShapeToTheExactTarget(t *testing.T) {
	t.Run("exact target plus unrelated descriptor", func(t *testing.T) {
		procDir, targetPath, target, foreignPath := guestProcessFixture(t)
		writeGuestDescriptor(t, procDir, "7", targetPath, 64, "0400040")
		writeGuestDescriptor(t, procDir, "8", foreignPath, 0, "0100000")
		if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target); err != nil {
			t.Fatalf("exact target descriptor rejected: %v", err)
		}
	})

	t.Run("ordinary read-only data at translator offsets is not a guest executable", func(t *testing.T) {
		procDir, targetPath, target, dataPath := guestProcessFixture(t)
		if err := os.Chmod(dataPath, 0o600); err != nil {
			t.Fatal(err)
		}
		writeGuestDescriptor(t, procDir, "7", targetPath, 64, "0400040")
		writeGuestDescriptor(t, procDir, "8", dataPath, 0, "0400040")
		if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target); err != nil {
			t.Fatalf("ordinary data descriptor was misclassified as a guest executable: %v", err)
		}
	})

	t.Run("exact target plus exact reviewed privilege dropper", func(t *testing.T) {
		procDir, targetPath, target, dropperPath := guestProcessFixture(t)
		dropper, _, err := inspectExecutable(dropperPath, false, false)
		if err != nil {
			t.Fatal(err)
		}
		writeGuestDescriptor(t, procDir, "3", dropperPath, 0, "0400040")
		writeGuestDescriptor(t, procDir, "4", dropperPath, 64, "0400040")
		writeGuestDescriptor(t, procDir, "6", targetPath, 0, "0400040")
		writeGuestDescriptor(t, procDir, "7", targetPath, 64, "0400040")
		reviewed := reviewedGuestDescriptor{path: dropperPath, identity: dropper}
		if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target, reviewed); err != nil {
			t.Fatalf("exact target/dropper descriptor pairs rejected: %v", err)
		}
		if err := os.Remove(filepath.Join(procDir, "fd", "3")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(procDir, "fdinfo", "3")); err != nil {
			t.Fatal(err)
		}
		if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target, reviewed); err == nil || !strings.Contains(err.Error(), "both exact privilege-dropper descriptors") {
			t.Fatalf("incomplete privilege-dropper descriptor pair passed: %v", err)
		}
	})

	for _, position := range []uint64{0, 64} {
		position := position
		t.Run(fmt.Sprintf("target plus foreign shaped position %d", position), func(t *testing.T) {
			procDir, targetPath, target, foreignPath := guestProcessFixture(t)
			if err := os.WriteFile(foreignPath, minimalELFExecutable(), 0o700); err != nil {
				t.Fatal(err)
			}
			writeGuestDescriptor(t, procDir, "7", targetPath, 64, "0400040")
			writeGuestDescriptor(t, procDir, "8", foreignPath, position, "0400040")
			if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target); err == nil || !strings.Contains(err.Error(), "neither the exact private binary nor an exact reviewed privilege dropper") {
				t.Fatalf("foreign Rosetta-shaped descriptor was accepted: %v", err)
			}
		})
	}

	t.Run("target pathname replaced with foreign bytes", func(t *testing.T) {
		procDir, targetPath, target, _ := guestProcessFixture(t)
		if err := os.WriteFile(targetPath, []byte("foreign replacement executable bytes"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeGuestDescriptor(t, procDir, "7", targetPath, 64, "0400040")
		if err := validateRosettaGuestDescriptorsAt(procDir, targetPath, target); err == nil || !strings.Contains(err.Error(), "private binary has foreign bytes") {
			t.Fatalf("foreign object behind exact descriptor pathname was accepted: %v", err)
		}
	})
}

func guestProcessFixture(t *testing.T) (string, string, executableIdentity, string) {
	t.Helper()
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	for _, directory := range []string{"map_files", "fd", "fdinfo"} {
		if err := os.MkdirAll(filepath.Join(procDir, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	targetPath := filepath.Join(root, "target")
	foreignPath := filepath.Join(root, "foreign")
	if err := os.WriteFile(targetPath, []byte("gate-built target executable bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignPath, []byte("caller-owned foreign executable bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	target, _, err := inspectExecutable(targetPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return procDir, targetPath, target, foreignPath
}

func writeGuestMaps(t *testing.T, procDir, targetPath string, target executableIdentity, foreignPath string, foreign executableIdentity) {
	t.Helper()
	targetDevice := procMapDeviceForTest(target.Device)
	lines := []string{
		fmt.Sprintf("1000-2000 r-xp 00000000 %s %d %s", targetDevice, target.Inode, targetPath),
		fmt.Sprintf("2000-3000 r--p 00001000 %s %d %s", targetDevice, target.Inode, targetPath),
	}
	links := map[string]string{"1000-2000": targetPath, "2000-3000": targetPath}
	if foreignPath != "" {
		lines = append(lines, fmt.Sprintf("3000-4000 r-xp 00000000 %s %d %s", procMapDeviceForTest(foreign.Device), foreign.Inode, foreignPath))
		links["3000-4000"] = foreignPath
	}
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, targetPath := range links {
		if err := os.Symlink(targetPath, filepath.Join(procDir, "map_files", name)); err != nil {
			t.Fatal(err)
		}
	}
}

func writeGuestDescriptor(t *testing.T, procDir, fd, target string, position uint64, flags string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(procDir, "fd", fd)); err != nil {
		t.Fatal(err)
	}
	info := fmt.Sprintf("pos:\t%d\nflags:\t%s\n", position, flags)
	if err := os.WriteFile(filepath.Join(procDir, "fdinfo", fd), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
}

func procMapDeviceForTest(device uint64) string {
	return fmt.Sprintf("%x:%x", unix.Major(device), unix.Minor(device))
}

func minimalELFExecutable() []byte {
	// A complete ELF64 header with no program/section table is sufficient for
	// debug/elf to classify ET_EXEC. The fixture intentionally has no owner
	// relationship to the synthetic runtime UID used by the adversarial test.
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1 // ELFCLASS64, little endian, v1.
	header[16], header[18], header[20] = 2, 0x3e, 1
	header[52] = 64
	return header
}

func TestReviewedCompanionStatusRequiresDirectHardenedSignerShape(t *testing.T) {
	valid := []byte("Name:\ttrstctl-signer\nState:\tS (sleeping)\nPPid:\t42\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	status, err := parseReviewedCompanionStatus(valid)
	if err != nil || status.name != "trstctl-signer" || status.state != "S" || status.parentPID != 42 || status.noNewPrivs != "1" || status.seccomp != "2" {
		t.Fatalf("valid hardened signer status rejected: %+v err=%v", status, err)
	}
	for name, replacement := range map[string]string{
		"missing parent":  "PPid:\t42\n",
		"missing nnp":     "NoNewPrivs:\t1\n",
		"missing seccomp": "Seccomp:\t2\n",
		"invalid state":   "State:\tS (sleeping)\n",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := strings.Replace(string(valid), replacement, "", 1)
			if name == "invalid state" {
				candidate += "State:\tinvalid\n"
			}
			if _, err := parseReviewedCompanionStatus([]byte(candidate)); err == nil {
				t.Fatal("incomplete/invalid companion status accepted")
			}
		})
	}
	invalid := status
	invalid.parentPID++
	err = validateUnreadableCompanionStatus(42, invalid)
	if err == nil || strings.Contains(err.Error(), "%!w") {
		t.Fatalf("invalid unreadable companion diagnostic = %v", err)
	}
}

func TestProcessStatusZombieClassificationIsExact(t *testing.T) {
	if !processStatusIsZombie([]byte("Name:\tpostgres\nState:\tZ (zombie)\nPPid:\t1\n")) {
		t.Fatal("Linux zombie process status was not recognized")
	}
	for _, raw := range [][]byte{
		[]byte("Name:\tpostgres\nState:\tS (sleeping)\n"),
		[]byte("Name:\tpostgres\nState:\tR (running)\n"),
		[]byte("Name:\tpostgres\n"),
		[]byte("State:\tinvalid\n"),
	} {
		if processStatusIsZombie(raw) {
			t.Fatalf("live/malformed process status classified as zombie: %q", raw)
		}
	}
}

func TestUnreadableCompanionRequiresPreExecListenerCloseOnExec(t *testing.T) {
	if err := requireLinuxDescriptorCloseOnExecFlags([]byte("pos:\t0\nflags:\t02000002\n")); err != nil {
		t.Fatalf("Linux O_CLOEXEC listener flags rejected: %v", err)
	}
	for _, raw := range [][]byte{
		[]byte("pos:\t0\nflags:\t00000002\n"),
		[]byte("pos:\t0\nflags:\tnot-octal\n"),
		[]byte("pos:\t0\n"),
	} {
		if err := requireLinuxDescriptorCloseOnExecFlags(raw); err == nil {
			t.Fatalf("inheritable/malformed listener flags accepted: %q", raw)
		}
	}
}

func TestCompanionFDIsolationSourceRejectsInheritanceAndTransfer(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCompanionFDIsolationSource(repo); err != nil {
		t.Fatalf("committed signer supervisor FD isolation is red: %v", err)
	}
	writeFixture := func(t *testing.T, extra string) string {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, "internal", "signing")
		for _, path := range []string{dir, filepath.Join(root, "cmd", "trstctl"), filepath.Join(root, "cmd", "trstctl-signer")} {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture.example\n\ngo 1.22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		source := `package signing
import (
    "context"
    "os/exec"
)
func run(ctx context.Context, binaryPath string, extraArgs []string) {
    cmd := exec.CommandContext(ctx, binaryPath, extraArgs...)
    _ = cmd
` + extra + "\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "supervisor.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "cmd", "trstctl", "main.go"), []byte("package main\nimport _ \"fixture.example/internal/signing\"\nfunc main() {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "cmd", "trstctl-signer", "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return root
	}
	t.Run("closed launch", func(t *testing.T) {
		if err := validateCompanionFDIsolationSource(writeFixture(t, "")); err != nil {
			t.Fatalf("closed os/exec launch rejected: %v", err)
		}
	})
	t.Run("extra files", func(t *testing.T) {
		if err := validateCompanionFDIsolationSource(writeFixture(t, "cmd.ExtraFiles = nil")); err == nil {
			t.Fatal("Cmd.ExtraFiles inheritance was accepted")
		}
	})
	t.Run("descriptor transfer", func(t *testing.T) {
		root := writeFixture(t, "")
		path := filepath.Join(root, "internal", "signing", "transfer.go")
		if err := os.WriteFile(path, []byte("package signing\nfunc transfer(conn interface{ WriteMsgUnix([]byte, []byte, any) (int, int, error) }) { _, _, _ = conn.WriteMsgUnix(nil, nil, nil) }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateCompanionFDIsolationSource(root); err == nil {
			t.Fatal("Unix descriptor-transfer primitive was accepted")
		}
	})
	t.Run("alternate production signer launch with inherited listener", func(t *testing.T) {
		root := writeFixture(t, "")
		dir := filepath.Join(root, "internal", "alternate")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		source := `package alternate
import (
    "os"
    "os/exec"
)
// Spawn can create the same direct hardened signer child shape as the reviewed
// supervisor, but explicitly hands it the control-plane listener descriptor.
func Spawn(binaryPath string, listener *os.File) error {
    cmd := exec.Command(binaryPath)
    cmd.ExtraFiles = []*os.File{listener}
    return cmd.Start()
}
`
		if err := os.WriteFile(filepath.Join(dir, "alternate.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		mainPath := filepath.Join(root, "cmd", "trstctl", "main.go")
		mainSource := "package main\nimport (\n_ \"fixture.example/internal/signing\"\n_ \"fixture.example/internal/alternate\"\n)\nfunc main() {}\n"
		if err := os.WriteFile(mainPath, []byte(mainSource), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateCompanionFDIsolationSource(root); err == nil || !strings.Contains(err.Error(), "internal/alternate/alternate.go") || !strings.Contains(err.Error(), "ExtraFiles") {
			t.Fatalf("alternate production signer inheritance escaped exact closure audit: %v", err)
		}
	})
}

func TestCompanionFDPrimitiveAuditRejectsEveryBypassFamily(t *testing.T) {
	tests := map[string]string{
		"extra files":          "package p\nfunc f(cmd interface{ Start() error }) { _ = cmd; cmd.ExtraFiles = nil }\n",
		"proc attr files":      "package p\nimport \"os\"\nvar _ = os.ProcAttr{Files: []*os.File{}}\n",
		"proc attr assignment": "package p\nimport \"os\"\nfunc f() { var attr os.ProcAttr; attr.Files = nil }\n",
		"start process":        "package p\nimport \"os\"\nvar _ = os.StartProcess\n",
		"fork exec":            "package p\nimport \"syscall\"\nvar _ = syscall.ForkExec\n",
		"unix rights":          "package p\nimport \"syscall\"\nvar _ = syscall.UnixRights\n",
		"socket method":        "package p\nfunc f(conn interface{ WriteMsgUnix([]byte, []byte, any) (int, int, error) }) { _, _, _ = conn.WriteMsgUnix(nil, nil, nil) }\n",
		"pidfd":                "package p\nimport unix \"golang.org/x/sys/unix\"\nvar _ = unix.PidfdGetfd\n",
		"raw syscall":          "package p\nimport \"syscall\"\nvar _ = syscall.RawSyscall\n",
		"descriptor dup":       "package p\nimport unix \"golang.org/x/sys/unix\"\nvar _ = unix.Dup3\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), name+".go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := auditCompanionFDPrimitives(parsed, map[*ast.SelectorExpr]bool{}); err == nil {
				t.Fatal("FD inheritance/transfer bypass primitive was accepted")
			}
		})
	}
}

func TestBoundedResponseDiagnosticIsSanitizedAndBounded(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"type":   "urn:trstctl:test\nproblem",
		"title":  "provider failed",
		"status": 500,
		"code":   "provider_error",
		"detail": "with detail\x00" + strings.Repeat("x", 4096),
	})
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := boundedResponseDiagnostic(body)
	if !strings.Contains(diagnostic, `title="provider failed"`) ||
		!strings.Contains(diagnostic, `status=500`) ||
		!strings.Contains(diagnostic, `code="provider_error"`) ||
		!strings.Contains(diagnostic, `detail="with detail`) ||
		strings.ContainsAny(diagnostic, "\r\n\x00") {
		t.Fatalf("response diagnostic was not useful/sanitized: %q", diagnostic)
	}
	if len(diagnostic) > 2048 {
		t.Fatalf("response diagnostic length = %d, want <= 2048", len(diagnostic))
	}

	nonProblem := []byte("provider secret must not appear")
	nonProblemDiagnostic := boundedResponseDiagnostic(nonProblem)
	if strings.Contains(nonProblemDiagnostic, "provider secret") ||
		!strings.Contains(nonProblemDiagnostic, fmt.Sprintf("size=%d", len(nonProblem))) ||
		!strings.Contains(nonProblemDiagnostic, internalcrypto.SHA256Hex(nonProblem)) {
		t.Fatalf("non-problem diagnostic exposed content or omitted its identity: %q", nonProblemDiagnostic)
	}
}

func TestLaunchedResponseStatusCodeExposesOnlyGateOwnedStatus(t *testing.T) {
	response := &launchedResponse{id: "hsm_kms.tpm2", response: &http.Response{StatusCode: http.StatusServiceUnavailable}}
	if got := LaunchedResponseStatusCode(t, "hsm_kms.tpm2", response); got != http.StatusServiceUnavailable {
		t.Fatalf("launched response status = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

func TestShippedBuildEnvironmentUsesPrivateContainerWorkDirectory(t *testing.T) {
	expected := expectation{LaunchedCGOEnabled: "0", LaunchedGOOS: "linux", LaunchedGOARCH: "amd64"}
	environment := shippedBuildEnvironment(expected, "/long/host/receipt/shipped-cache", RuntimeTempDir)
	values := map[string]string{}
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if ok {
			values[name] = value
		}
	}
	if values["HOME"] != "/dod-tmp" || values["TMPDIR"] != "/dod-tmp" {
		t.Fatalf("shipped build HOME/TMPDIR = %q/%q", values["HOME"], values["TMPDIR"])
	}
	if values["GOTMPDIR"] != "/tmp" {
		t.Fatalf("shipped build GOTMPDIR = %q, want private container tmpfs", values["GOTMPDIR"])
	}
	if values["GOCACHE"] != "/long/host/receipt/shipped-cache" {
		t.Fatalf("shipped build GOCACHE = %q", values["GOCACHE"])
	}
	if len(filepath.Join(values["GOTMPDIR"], "go-build1234567890", "b001", "importcfg.link")) >= 108 {
		t.Fatal("private shipped-build temporary path no longer leaves Unix-socket headroom")
	}
}

func TestShippedBuildArgumentsBoundPackageParallelism(t *testing.T) {
	expected := expectation{LaunchedTags: []string{"integration", "trstctl_test_signer"}}
	got := shippedBuildArguments(expected, "linker flags", "/receipt/trstctl", "./cmd/trstctl")
	want := []string{
		"build",
		"-p=1",
		"-trimpath",
		"-buildvcs=false",
		"-mod=readonly",
		"-tags=integration,trstctl_test_signer",
		"-ldflags",
		"linker flags",
		"-o",
		"/receipt/trstctl",
		"./cmd/trstctl",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("shipped build arguments = %#v, want %#v", got, want)
	}
}

func TestShippedBuildsReuseOneGatePrivateGoCache(t *testing.T) {
	receiptDir := t.TempDir()
	first, err := ensureShippedGoCache(receiptDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ensureShippedGoCache(receiptDir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("shipped builds use separate gate-private caches %q and %q", first, second)
	}
	if err := os.Chmod(first, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureShippedGoCache(receiptDir); err == nil {
		t.Fatal("shared shipped-build cache accepted a non-private existing directory")
	}
}

func TestTranslateMountSuffixIsClosedToShortRuntimeTree(t *testing.T) {
	hostRoot := "/private/tmp/trstctl-dod-receipts-123"
	aliasRoot := RuntimeTempDir
	candidate := filepath.Join(aliasRoot, "TestDODManagedKeyProductionAssembly", "002")
	want := filepath.Join(hostRoot, "TestDODManagedKeyProductionAssembly", "002")
	if got, err := translateMountSuffix(hostRoot, aliasRoot, candidate); err != nil || got != want {
		t.Fatalf("translated mount = %q err=%v, want %q", got, err, want)
	}
	for _, invalid := range []struct {
		hostRoot string
		alias    string
		path     string
	}{
		{hostRoot: hostRoot, alias: aliasRoot, path: aliasRoot},
		{hostRoot: hostRoot, alias: aliasRoot, path: "/dod-tmp-other/002"},
		{hostRoot: hostRoot, alias: aliasRoot, path: "/dod-tmp/../etc"},
		{hostRoot: hostRoot, alias: aliasRoot, path: "relative/path"},
		{hostRoot: "relative/root", alias: aliasRoot, path: candidate},
		{hostRoot: hostRoot + ",forged", alias: aliasRoot, path: candidate},
	} {
		if got, err := translateMountSuffix(invalid.hostRoot, invalid.alias, invalid.path); err == nil {
			t.Errorf("unsafe mount translation passed as %q: %+v", got, invalid)
		}
	}
}

func TestMountTranslationIdentityRejectsSymlinkAndForeignObject(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateMountTranslationIdentity(root, root, first, first); err != nil {
		t.Fatalf("same private object rejected: %v", err)
	}
	if err := validateMountTranslationIdentity(root, root, first, second); err == nil {
		t.Fatal("foreign object passed translated mount identity")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	if err := validateMountTranslationIdentity(root, root, link, link); err == nil {
		t.Fatal("symlink object passed translated mount identity")
	}
	rootLink := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-link")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(rootLink) })
	if err := validateMountTranslationIdentity(root, rootLink, first, filepath.Join(rootLink, "first")); err == nil {
		t.Fatal("symlink runtime root passed translated mount identity")
	}
}

const proofCleanupModeEnv = "TRSTCTL_PROOF_CLEANUP_MODE"
const proofCleanupMarkerEnv = "TRSTCTL_PROOF_CLEANUP_MARKER"
const proofMissingExpectationModeEnv = "TRSTCTL_PROOF_MISSING_EXPECTATION_MODE"

func TestBrokerDynamicEnvironmentNamesAreExact(t *testing.T) {
	tests := []struct {
		expected expectation
		want     string
	}{
		{expectation{ID: "external_ca.entrust"}, "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE,TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE,TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"},
		{expectation{ID: "code_signing.default"}, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"},
		{expectation{ID: "hsm_kms.tpm2", SubstrateID: "managed_key_custody"}, "TRSTCTL_HSM_PROOF_IMAGE,TRSTCTL_HSM_PROOF_NETWORK"},
		{expectation{ID: "connector.nginx"}, ""},
	}
	for _, test := range tests {
		if got := strings.Join(brokerDynamicEnvironmentNames(test.expected), ","); got != test.want {
			t.Errorf("broker dynamic environment for %s = %q, want %q", test.expected.ID, got, test.want)
		}
	}
}

func TestStartCompleteWritesUnsignedEvidenceForParentGate(t *testing.T) {
	dir := t.TempDir()
	receiptFile := filepath.Join(dir, "receipt.json")
	evidenceFile := filepath.Join(dir, "evidence.json")
	expected := expectation{
		SchemaVersion: 1, Nonce: strings.Repeat("a", 64), ID: "connector.example",
		BuildProfile: "static", Method: http.MethodPost, Path: "/api/v1/connectors/example", RuntimeMode: "assembled-handler",
		SubstrateID: "vendor_example", SubstrateKind: "vendor-emulator",
		SubstrateIdentity: "vendor/example@sha256:" + strings.Repeat("b", 64),
		ContractDigest:    "sha256:" + internalcrypto.SHA256Hex([]byte("contract")),
		Verifier:          "external-write", ReceiptFile: receiptFile, EvidenceFile: evidenceFile,
		RuntimeRunnerIdentity: "runner@sha256:" + strings.Repeat("c", 64),
		RuntimeRunnerImage:    "sha256:" + strings.Repeat("d", 64),
		RuntimeTestPackage:    "./internal/server", RuntimeCGOEnabled: "0", RuntimeGOOS: "linux", RuntimeGOARCH: "amd64",
		BrokerEndpoint: "http://127.0.0.1:1", BrokerToken: "parent-broker-token",
	}
	payload, err := json.Marshal([]expectation{expected})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_DOD_EXPECTATIONS", string(payload))
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != expected.Path {
			t.Fatalf("handler path = %q", request.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"delivered"}`))
	})
	request, err := http.NewRequest(expected.Method, expected.Path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	session := Start(t, expected.ID, handler, request)
	written := []byte("high-fidelity external payload")
	execution, err := json.Marshal(substrateExecutionReceipt{
		SchemaVersion: 1, Challenge: expected.Nonce, EntryID: expected.ID, Identity: expected.SubstrateIdentity,
		ContractDigest: expected.ContractDigest, PID: os.Getpid() + 1000, Passed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.Complete(ExternalWrite(ExternalWriteProbe{
		Destination: []byte("external-system/item/42"), Written: written, ReadBack: append([]byte(nil), written...),
		ExecutionReceipt: execution,
	}))
	data, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	var got receipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Passed || got.Skipped || got.Nonce != expected.Nonce || got.ID != expected.ID || got.SubstrateIdentity != expected.SubstrateIdentity || got.MAC != "" || len(got.ExecutionReceipt) == 0 {
		t.Fatalf("unsigned evidence lost parent-bound identity: %+v", got)
	}
	if _, err := os.Stat(receiptFile); !os.IsNotExist(err) {
		t.Fatal("proof child created the final parent-only receipt")
	}
	if got.Observations["write_digest"] != got.Observations["readback_digest"] {
		t.Fatalf("external write/readback were not bound: %+v", got.Observations)
	}
}

func TestManagedKeyExecutionReceiptRequiresContentAddressedRuntimeIdentity(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if !runtimeIdentityMatches("managed_key_custody", valid) {
		t.Fatal("content-addressed managed-key runtime identity was rejected")
	}
	for _, invalid := range []string{"", "trstctl-managed-key-runtime:dod", "sha256:abc", "sha256:" + strings.Repeat("A", 64)} {
		if runtimeIdentityMatches("managed_key_custody", invalid) {
			t.Errorf("mutable/invalid managed-key runtime identity %q was accepted", invalid)
		}
	}
	if runtimeIdentityMatches("connector_universal", valid) {
		t.Fatal("unrequested runtime identity was accepted for an ordinary command substrate")
	}
}

func TestResponseValidationRejectsStatusAndSentinels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusNotImplemented, `{}`},
		{http.StatusServiceUnavailable, `{}`},
		{http.StatusOK, `{"status":"unrouted"}`},
		{http.StatusOK, `{"detail":"not configured"}`},
	} {
		if err := responseIsServed(tc.status, []byte(tc.body)); err == nil {
			t.Errorf("accepted sentinel status/body %d %q", tc.status, tc.body)
		}
	}
}

func TestFixedProbesRejectMissingLifecycleObservationsAndLiteralBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		evidence Evidence
	}{
		{"external missing readback", ExternalWrite(ExternalWriteProbe{Destination: []byte("destination long enough"), Written: []byte("written bytes long enough")})},
		{"external literal x", ExternalWrite(ExternalWriteProbe{Destination: []byte("x"), Written: []byte("x"), ReadBack: []byte("x")})},
		{"lifecycle missing revoke", CredentialLifecycle(CredentialLifecycleProbe{Issued: []byte("issued credential bytes"), Rotated: []byte("rotated credential bytes"), Exported: []byte("exported public bytes")})},
		{"lifecycle missing export", CredentialLifecycle(CredentialLifecycleProbe{Issued: []byte("issued credential bytes"), Rotated: []byte("rotated credential bytes"), RevocationReceipt: []byte("revocation receipt bytes")})},
		{"TLS missing readback", TLSDeploy(TLSDeployProbe{Deployed: []byte("deployed certificate bytes"), Config: []byte("configuration bytes"), ReloadReceipt: []byte("reload receipt bytes")})},
		{"HSM literal x", HSMSign(HSMSignProbe{Signature: []byte("x"), PublicKey: []byte("x"), ExportDenial: []byte("x")})},
	}
	for _, tc := range tests {
		if payload := tc.evidence.dodEvidence(); payload.err == nil {
			t.Errorf("%s produced valid sealed evidence: %+v", tc.name, payload)
		}
	}
}

// TestStartFailsClosedWithoutGateExpectations uses a nested test process because
// the expected behavior is testing.T.Fatal. This protects the isolation tag from
// accidentally turning direct, ordinary invocations into self-authorizing proof.
func TestStartFailsClosedWithoutGateExpectations(t *testing.T) {
	if os.Getenv(proofMissingExpectationModeEnv) == "driver" {
		_ = os.Unsetenv("TRSTCTL_DOD_EXPECTATIONS")
		request, err := http.NewRequest(http.MethodGet, "/api/v1/missing-proof", nil)
		if err != nil {
			t.Fatal(err)
		}
		Start(t, "missing.expectation", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), request)
		t.Fatal("proof.Start returned without gate-issued expectations")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartFailsClosedWithoutGateExpectations$")
	cmd.Env = proofMissingExpectationEnvironment(os.Environ())
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("missing-expectation driver timed out: %v output=%s", ctx.Err(), output)
	}
	if err == nil {
		t.Fatalf("proof.Start accepted missing gate expectations: %s", output)
	}
	if !strings.Contains(string(output), "gate-issued TRSTCTL_DOD_EXPECTATIONS is missing") {
		t.Fatalf("missing expectations failed for the wrong reason: %s", output)
	}
}

func proofMissingExpectationEnvironment(base []string) []string {
	out := make([]string, 0, len(base)+1)
	for _, item := range base {
		if strings.HasPrefix(item, proofMissingExpectationModeEnv+"=") || strings.HasPrefix(item, "TRSTCTL_DOD_EXPECTATIONS=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, proofMissingExpectationModeEnv+"=driver")
}

// TestExternalSubstrateCleanupAfterFatal uses a nested test process so the
// middle process can intentionally call t.Fatal without making this outer test
// fail. The registered cleanup must interrupt and reap its READY substrate even
// though StopAndReceipt was never reached.
func TestExternalSubstrateCleanupAfterFatal(t *testing.T) {
	switch os.Getenv(proofCleanupModeEnv) {
	case "substrate":
		runProofCleanupSubstrate(t)
		return
	case "fatal-driver":
		runProofCleanupFatalDriver(t)
		return
	}

	marker := filepath.Join(t.TempDir(), "interrupted.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExternalSubstrateCleanupAfterFatal$")
	cmd.Env = proofCleanupEnvironment(os.Environ(), "fatal-driver", marker)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("fatal-driver cleanup timed out: %v output=%s", ctx.Err(), output)
	}
	if err == nil {
		t.Fatalf("fatal-driver unexpectedly passed; intentional t.Fatal did not run: %s", output)
	}
	rawPID, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("substrate cleanup marker is missing after t.Fatal: %v; output=%s", err, output)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid cleaned substrate pid %q: %v", rawPID, err)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("substrate process %d survived fatal-driver cleanup", pid)
	} else if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("probe cleaned substrate pid %d: %v", pid, err)
	}
}

func TestShippedProcessCommandDropsRunnerAuditCapability(t *testing.T) {
	name, args := shippedProcessCommand("/private/dod-bin/trstctl", "serve")
	if name != "/usr/bin/setpriv" {
		t.Fatalf("shipped process dropper = %q", name)
	}
	want := []string{
		"--clear-groups",
		"--inh-caps=-checkpoint_restore,-setgid",
		"--ambient-caps=-checkpoint_restore,-setgid",
		"/private/dod-bin/trstctl",
		"serve",
	}
	if strings.Join(args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("shipped process argv = %v, want %v", args, want)
	}
}

func TestValidateShippedProcessStatusRejectsAuditCapabilityLeak(t *testing.T) {
	status := func(capEff, capBnd, noNewPrivs, seccomp string) []byte {
		return []byte(strings.Join([]string{
			"Uid:\t501\t501\t501\t501",
			"Gid:\t20\t20\t20\t20",
			"Groups:\t",
			"TracerPid:\t0",
			"CapInh:\t0000000000000000",
			"CapPrm:\t0000000000000000",
			"CapEff:\t" + capEff,
			"CapBnd:\t" + capBnd,
			"CapAmb:\t0000000000000000",
			"NoNewPrivs:\t" + noNewPrivs,
			"Seccomp:\t" + seccomp,
		}, "\n"))
	}
	if err := validateShippedProcessStatus(status("0000000000000000", "0000010000000040", "1", "2"), 501, 20); err != nil {
		t.Fatalf("bounded unprivileged shipped status rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"effective audit capability":  status("0000010000000000", "0000010000000040", "1", "2"),
		"foreign bounding capability": status("0000000000000000", "0000010000080040", "1", "2"),
		"new privileges enabled":      status("0000000000000000", "0000010000000040", "0", "2"),
		"seccomp disabled":            status("0000000000000000", "0000010000000040", "1", "0"),
		"Docker group retained":       bytes.Replace(status("0000000000000000", "0000010000000040", "1", "2"), []byte("Groups:\t\n"), []byte("Groups:\t20\n"), 1),
		"tracer attached":             bytes.Replace(status("0000000000000000", "0000010000000040", "1", "2"), []byte("TracerPid:\t0"), []byte("TracerPid:\t99"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateShippedProcessStatus(raw, 501, 20); err == nil {
				t.Fatal("unsafe shipped-process privilege status passed")
			}
		})
	}
}

func runProofCleanupFatalDriver(t *testing.T) {
	marker := os.Getenv(proofCleanupMarkerEnv)
	expected := expectation{
		SchemaVersion: 1, Nonce: strings.Repeat("c", 64), ID: "cleanup.substrate",
		SubstrateID: "cleanup_substrate", SubstrateKind: "vendor-emulator",
		SubstrateIdentity: "cleanup/substrate@sha256:" + strings.Repeat("d", 64),
		ContractDigest:    "sha256:" + strings.Repeat("e", 64), Verifier: "external-write",
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExternalSubstrateCleanupAfterFatal$")
	cmd.Env = proofCleanupEnvironment(substrateEnvironment(expected), "substrate", marker)
	_ = startExternal(t, expected, cmd, true)
	t.Fatal("intentional fatal after READY before StopAndReceipt")
}

func runProofCleanupSubstrate(t *testing.T) {
	ready := substrateReady{
		SchemaVersion:  1,
		Challenge:      os.Getenv("TRSTCTL_DOD_CHALLENGE"),
		EntryID:        os.Getenv("TRSTCTL_DOD_ENTRY_ID"),
		Identity:       os.Getenv("TRSTCTL_DOD_SUBSTRATE_IDENTITY"),
		ContractDigest: os.Getenv("TRSTCTL_DOD_CONTRACT_DIGEST"),
		PID:            os.Getpid(), Ready: true, Endpoint: "http://127.0.0.1:1",
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		t.Fatal(err)
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	select {
	case <-interrupt:
	case <-time.After(20 * time.Second):
		t.Fatal("cleanup substrate was never interrupted")
	}
	if err := os.WriteFile(os.Getenv(proofCleanupMarkerEnv), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
}

func proofCleanupEnvironment(base []string, mode, marker string) []string {
	out := make([]string, 0, len(base)+2)
	for _, item := range base {
		if strings.HasPrefix(item, proofCleanupModeEnv+"=") || strings.HasPrefix(item, proofCleanupMarkerEnv+"=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, proofCleanupModeEnv+"="+mode, proofCleanupMarkerEnv+"="+marker)
}
