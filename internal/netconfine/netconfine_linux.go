// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package netconfine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// Supported reports whether this platform can confine a command's network.
const Supported = true

// Isolate makes cmd start in a new user namespace, mapped to the caller's own
// user and group, and a new network namespace, with only the capability it
// needs to bring that network's loopback up; the helper drops it before it
// runs the command. The child is killed if its launcher dies.
func Isolate(cmd *exec.Cmd) error {
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
		Pdeathsig:   syscall.SIGKILL,
	}
	return nil
}

// RunHelper is the helper inside the new namespaces: it brings loopback up,
// listens on each forward's address and carries its connections out, drops
// its capabilities, then runs the command with the environment it was given
// and returns its exit status (125 when it could not get that far).
func RunHelper(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		_, _ = fmt.Fprintf(stderr, "netconfine: %v\n", err)
		return 125
	}
	forwards, argv, err := parseHelperArgs(args)
	if err != nil {
		return fail(err)
	}
	if err := loopbackUp(); err != nil {
		return fail(fmt.Errorf("bring loopback up: %w", err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, f := range forwards {
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			return fail(fmt.Errorf("listen on %s: %w", f.Listen, err))
		}
		go forward(ctx, ln, f.Socket)
	}
	// The command gets no capability: clear the ambient set, so its execve
	// keeps none of this process's.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail(fmt.Errorf("drop capabilities: %w", err))
	}
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 G702 -- runs the launcher's own command line verbatim, without a shell, inside the confined network (CWE-78)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range signals {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(signals)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.ExitCode()
	default:
		return fail(err)
	}
}

// loopbackUp sets the namespace's lo interface up.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
