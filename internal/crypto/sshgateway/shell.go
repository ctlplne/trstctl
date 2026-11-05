// SPDX-License-Identifier: BUSL-1.1

package sshgateway

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Shell is an interactive shell on a gateway session that the control plane
// opens for a browser terminal (A259). The gateway has admitted the
// connection by the session's ticket and serves SSH with no client
// authentication; the shell's server is verified by the host key the gateway
// named over the same mTLS-verified connection. The control plane is only the
// client: the gateway still signs in to the target, records and masks.
type Shell struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	done    chan struct{}
	exit    error
}

// OpenShell starts a shell with a pseudo-terminal of cols x rows over conn,
// accepting only the gateway host key hostKey (an authorized_keys line).
func OpenShell(conn net.Conn, hostKey string, cols, rows int) (*Shell, error) {
	if cols < 1 || rows < 1 || cols > 1000 || rows > 1000 {
		return nil, errors.New("sshgateway: terminal size must be 1-1000 columns and rows")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(hostKey)))
	if err != nil {
		return nil, fmt.Errorf("sshgateway: the gateway named no valid host key: %w", err)
	}
	cfg := &ssh.ClientConfig{User: "browser", HostKeyCallback: ssh.FixedHostKey(key), Timeout: 30 * time.Second}
	c, chans, reqs, err := ssh.NewClientConn(conn, "trstctl-access-gateway", cfg)
	if err != nil {
		return nil, fmt.Errorf("sshgateway: shell handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("sshgateway: shell session: %w", err)
	}
	shell := &Shell{client: client, session: session, done: make(chan struct{})}
	fail := func(err error) (*Shell, error) {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return fail(fmt.Errorf("sshgateway: pseudo-terminal: %w", err))
	}
	if shell.stdin, err = session.StdinPipe(); err != nil {
		return fail(err)
	}
	if shell.stdout, err = session.StdoutPipe(); err != nil {
		return fail(err)
	}
	// With a pseudo-terminal the target merges standard error into the
	// terminal's output; anything sent on the session's stderr is dropped.
	session.Stderr = io.Discard
	if err := session.Shell(); err != nil {
		return fail(fmt.Errorf("sshgateway: shell: %w", err))
	}
	go func() {
		shell.exit = session.Wait()
		close(shell.done)
	}()
	return shell, nil
}

// Read reads the terminal's output.
func (s *Shell) Read(p []byte) (int, error) { return s.stdout.Read(p) }

// Write types into the terminal.
func (s *Shell) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Resize changes the terminal's size.
func (s *Shell) Resize(cols, rows int) error {
	if cols < 1 || rows < 1 || cols > 1000 || rows > 1000 {
		return errors.New("sshgateway: terminal size must be 1-1000 columns and rows")
	}
	return s.session.WindowChange(rows, cols)
}

// Done is closed when the shell exits or its connection ends.
func (s *Shell) Done() <-chan struct{} { return s.done }

// ExitStatus is the shell's exit status once Done is closed, or -1 when the
// shell ended without one (a closed connection, a termination).
func (s *Shell) ExitStatus() int {
	var exit *ssh.ExitError
	switch {
	case s.exit == nil:
		return 0
	case errors.As(s.exit, &exit):
		return exit.ExitStatus()
	}
	return -1
}

// Close ends the shell and its connection.
func (s *Shell) Close() error {
	_ = s.session.Close()
	return s.client.Close()
}
