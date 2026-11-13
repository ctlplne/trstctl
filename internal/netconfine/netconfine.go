// SPDX-License-Identifier: BUSL-1.1

// Package netconfine runs a command in a network of its own (A257-L2): inside
// it the command can reach only the loopback TCP addresses it was given, each
// carried to a Unix socket its launcher serves outside, and nothing else — no
// other address of the host, of the local network or of the internet. On
// Linux the network is a new network namespace, created with a new user
// namespace so an unprivileged launcher can make it; elsewhere it is not
// supported and the caller refuses to run unconfined.
//
// The launcher starts its own binary as a helper (Wrap, HelperArg) in the new
// namespaces (Isolate). The helper brings the namespace's loopback up, listens
// on each given address, carries each connection to its socket, drops the
// capability that let it configure the network, and runs the command, whose
// exit status it returns.
package netconfine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
)

// HelperArg, as the first argument, runs a binary as the confinement helper.
const HelperArg = "__trstctl-netconfine"

// ErrUnsupported is returned where a command cannot be confined.
var ErrUnsupported = errors.New("netconfine: confining a command's network needs Linux user and network namespaces")

// Forward is one address the confined command may reach: the loopback TCP
// address it dials inside its network, and the Unix socket outside it that
// each connection is carried to.
type Forward struct {
	Listen string
	Socket string
}

// Wrap returns the argv that runs argv confined, through the helper binary
// self.
func Wrap(self string, forwards []Forward, argv []string) []string {
	out := []string{self, HelperArg}
	for _, f := range forwards {
		out = append(out, "--forward", f.Listen+"="+f.Socket)
	}
	out = append(out, "--")
	return append(out, argv...)
}

// parseHelperArgs reads the helper's arguments (after HelperArg): each
// forward must be a loopback IPv4 address and an absolute socket path.
func parseHelperArgs(args []string) ([]Forward, []string, error) {
	var forwards []Forward
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--":
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, nil, errors.New("netconfine: no command to run")
			}
			return forwards, args[i+1:], nil
		case "--forward":
			if i+1 >= len(args) {
				return nil, nil, errors.New("netconfine: --forward needs ADDRESS=SOCKET")
			}
			i++
			listen, socket, ok := strings.Cut(args[i], "=")
			host, _, err := net.SplitHostPort(listen)
			if !ok || err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !filepath.IsAbs(socket) {
				return nil, nil, fmt.Errorf("netconfine: forward %q is not a loopback address and an absolute socket path", args[i])
			}
			forwards = append(forwards, Forward{Listen: listen, Socket: socket})
		default:
			return nil, nil, fmt.Errorf("netconfine: unexpected argument %q", args[i])
		}
	}
	return nil, nil, errors.New("netconfine: no command to run")
}

// forward accepts connections on ln until ctx ends and carries each to the
// Unix socket at path.
func forward(ctx context.Context, ln net.Listener, path string) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		local, err := ln.Accept()
		if err != nil {
			return
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer func() { _ = local.Close() }()
			var dialer net.Dialer
			remote, err := dialer.DialContext(ctx, "unix", path)
			if err != nil {
				return
			}
			defer func() { _ = remote.Close() }()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(remote, local); closeWrite(remote); done <- struct{}{} }()
			go func() { _, _ = io.Copy(local, remote); closeWrite(local); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}

// closeWrite half-closes a connection, so the other side reads the end of
// what was sent while its own reply can still arrive.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
