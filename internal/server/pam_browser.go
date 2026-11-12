// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
	"trstctl.com/trstctl/internal/accessrules"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/sshgateway"
)

// A259: browser sessions. The control plane is the browser's client side: a
// session opened for the browser leaves its ticket here, in locked memory
// bound to the person who opened it, and never in the browser. A terminal is
// an SSH shell the control plane opens through the session's gateway, which
// still signs in to the target, records and masks; the browser reads the
// terminal's output by long-polling and types into it. Ending the session at
// the gateway (revocation, termination, its deadline) ends the terminal.

const (
	// pamTerminalRing bounds the output a terminal keeps for its reader.
	pamTerminalRing = 1 << 20
	// pamTerminalPage bounds one read of a terminal's output.
	pamTerminalPage = 256 << 10
	// pamTerminalsPerSession bounds the terminals one session serves.
	pamTerminalsPerSession = 2
	// pamTerminalWaitMax bounds a long-poll for output.
	pamTerminalWaitMax = 25 * time.Second
	// pamTerminalInputMax bounds one input batch.
	pamTerminalInputMax = 64 << 10
)

// kubeName is a Kubernetes object name a terminal request may name.
var kubeName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

type pamBrowserKey struct {
	tenantID, sessionID string
}

// pamBrowserTicket is a browser session's ticket and how to reach its
// gateway, held for the person who opened it until the session's deadline.
type pamBrowserTicket struct {
	opener   string
	ticket   *secret.Buffer
	address  string
	spiffeID string
	caPEM    []byte
	expires  time.Time
}

// pamShell is what a terminal drives: an SSH shell, or a Kubernetes exec
// (part 3).
type pamShell interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Done() <-chan struct{}
	ExitStatus() int
	Close() error
}

// pamTerminal is one shell and the output its reader has not passed.
type pamTerminal struct {
	id, tenantID, sessionID, opener string
	shell                           pamShell

	mu     sync.Mutex
	ring   []byte // the output from offset start up to end
	start  int64
	end    int64
	signal chan struct{} // closed and replaced when output arrives or the shell ends
	closed bool
	exit   *int
}

type pamBrowser struct {
	mu        sync.Mutex
	tickets   map[pamBrowserKey]*pamBrowserTicket
	terminals map[string]*pamTerminal
	opening   map[pamBrowserKey]int
	consoles  map[pamBrowserKey]*pamConsole
	dial      func(ctx context.Context, addr string, caPEM []byte, spiffeID string) (net.Conn, error)
}

func newPAMBrowser() *pamBrowser {
	return &pamBrowser{tickets: map[pamBrowserKey]*pamBrowserTicket{}, terminals: map[string]*pamTerminal{}, opening: map[pamBrowserKey]int{},
		consoles: map[pamBrowserKey]*pamConsole{}, dial: mtls.GatewayDial}
}

// HoldBrowserTicket keeps a browser session's ticket for its opener.
func (s *pamService) HoldBrowserTicket(tenantID, sessionID, opener string, delivery api.PAMGatewayDelivery, ticket []byte, expires time.Time) error {
	if opener == "" || len(ticket) == 0 || delivery.Address == "" || delivery.SPIFFEID == "" || delivery.CAPEM == "" {
		return fmt.Errorf("%w: a browser session needs a gateway and its ticket", api.ErrPAMInvalid)
	}
	held, err := secret.NewFrom(ticket)
	if err != nil {
		return err
	}
	s.browser.mu.Lock()
	defer s.browser.mu.Unlock()
	key := pamBrowserKey{tenantID, sessionID}
	if old := s.browser.tickets[key]; old != nil {
		old.ticket.Destroy()
	}
	s.browser.tickets[key] = &pamBrowserTicket{opener: opener, ticket: held, address: delivery.Address, spiffeID: delivery.SPIFFEID,
		caPEM: []byte(delivery.CAPEM), expires: expires}
	return nil
}

// OpenPAMTerminal opens a terminal on an active browser session for its
// opener: a shell on an SSH session, or an exec in a pod for a Kubernetes
// session (part 3).
func (s *pamService) OpenPAMTerminal(ctx context.Context, tenantID, sessionID, principal string, req api.PAMTerminalRequest) (api.PAMTerminal, error) {
	cols, rows := req.Cols, req.Rows
	rec, err := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMTerminal{}, err
	}
	if (rec.TargetType != pamTargetSSH && rec.TargetType != pamTargetK8s) || rec.Delivery != "gateway" || rec.Status != api.PAMSessionStatusActive ||
		!s.clock().Before(rec.ExpiresAt) {
		return api.PAMTerminal{}, fmt.Errorf("%w: a terminal needs an active SSH or Kubernetes session through a gateway", api.ErrPAMRejected)
	}
	if req.SSHCommand != "" && (rec.TargetType != pamTargetSSH || len(req.SSHCommand) > accessrules.MaxSSHCommandBytes || !utf8.ValidString(req.SSHCommand) || strings.IndexByte(req.SSHCommand, 0) >= 0) {
		return api.PAMTerminal{}, fmt.Errorf("%w: SSH command must be valid text of at most 65536 bytes on an SSH session", api.ErrPAMInvalid)
	}
	if rec.TargetType == pamTargetSSH && rec.CommandPolicy != nil && strings.TrimSpace(req.SSHCommand) == "" {
		return api.PAMTerminal{}, fmt.Errorf("%w: this session requires a complete SSH exec command; interactive shell and subsystem requests are refused", api.ErrPAMInvalid)
	}
	if rec.TargetType == pamTargetK8s {
		if !kubeName.MatchString(req.Namespace) || !kubeName.MatchString(req.Pod) || (req.Container != "" && !kubeName.MatchString(req.Container)) {
			return api.PAMTerminal{}, fmt.Errorf("%w: a Kubernetes terminal names a namespace, a pod and optionally a container", api.ErrPAMInvalid)
		}
		if len(req.Command) == 0 {
			req.Command = []string{"sh"}
		}
		if len(req.Command) > 16 {
			return api.PAMTerminal{}, fmt.Errorf("%w: a command has at most 16 arguments", api.ErrPAMInvalid)
		}
	}
	s.browser.mu.Lock()
	held := s.browser.tickets[pamBrowserKey{tenantID, sessionID}]
	browserKey := pamBrowserKey{tenantID, sessionID}
	open := s.browser.opening[browserKey]
	for _, t := range s.browser.terminals {
		if t.tenantID == tenantID && t.sessionID == sessionID {
			open++
		}
	}
	admitted := held != nil && held.opener == principal && open < pamTerminalsPerSession
	if admitted {
		s.browser.opening[browserKey]++
	}
	s.browser.mu.Unlock()
	if admitted {
		defer func() {
			s.browser.mu.Lock()
			s.browser.opening[browserKey]--
			if s.browser.opening[browserKey] == 0 {
				delete(s.browser.opening, browserKey)
			}
			s.browser.mu.Unlock()
		}()
	}
	switch {
	case held == nil:
		return api.PAMTerminal{}, fmt.Errorf("%w: the session was not opened for the browser", api.ErrPAMRejected)
	case held.opener != principal:
		return api.PAMTerminal{}, fmt.Errorf("%w: only the person who opened the session can use it in the browser", api.ErrPAMRejected)
	case open >= pamTerminalsPerSession:
		return api.PAMTerminal{}, fmt.Errorf("%w: the session already has %d terminals", api.ErrPAMRejected, pamTerminalsPerSession)
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := s.browser.dial(dctx, held.address, held.caPEM, held.spiffeID)
	if err != nil {
		return api.PAMTerminal{}, fmt.Errorf("%w: the session's gateway: %v", api.ErrPAMRejected, err)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	hostKey, err := admitAtGateway(conn, sessionID, held.ticket)
	if err != nil {
		_ = conn.Close()
		return api.PAMTerminal{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	var shell pamShell
	if rec.TargetType == pamTargetK8s {
		shell, err = openKubeExec(conn, req.Namespace, req.Pod, req.Container, req.Command, cols, rows)
	} else if req.SSHCommand != "" {
		command := []byte(req.SSHCommand)
		shell, err = sshgateway.OpenCommand(conn, hostKey, cols, rows, command)
		secret.Wipe(command)
	} else {
		shell, err = sshgateway.OpenShell(conn, hostKey, cols, rows)
	}
	if err != nil {
		_ = conn.Close()
		return api.PAMTerminal{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	if !stopClose() || ctx.Err() != nil {
		_ = shell.Close()
		return api.PAMTerminal{}, ctx.Err()
	}
	t := &pamTerminal{id: uuid.NewString(), tenantID: tenantID, sessionID: sessionID, opener: principal, shell: shell, signal: make(chan struct{})}
	s.browser.mu.Lock()
	s.browser.terminals[t.id] = t
	s.browser.mu.Unlock()
	go t.pump()
	return api.PAMTerminal{ID: t.id, SessionID: sessionID, Cols: cols, Rows: rows}, nil
}

// admitAtGateway presents the session's ticket on a verified connection to
// its gateway and returns the SSH host key the gateway serves it with (none
// for a database session).
func admitAtGateway(conn net.Conn, sessionID string, ticket *secret.Buffer) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return "", err
	}
	err := ticket.Use(func(b []byte) error {
		line := make([]byte, 0, len("TRSTCTL-GATEWAY/1 ")+len(sessionID)+len(b)+2)
		line = append(append(append(append(line, "TRSTCTL-GATEWAY/1 "...), sessionID...), ' '), b...)
		line = append(line, '\n')
		_, err := conn.Write(line)
		secret.Wipe(line)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("the session's gateway: %w", err)
	}
	// One byte at a time, so nothing after the answer line is consumed.
	answer, err := bufio.NewReaderSize(oneByteConn{conn}, 16).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("the session's gateway did not answer: %w", err)
	}
	answer = strings.TrimSpace(answer)
	// An SSH session's gateway names its host key after OK; a database
	// session's answers OK alone.
	key, ok := strings.CutPrefix(answer, "OK ")
	if !ok && answer != "OK" {
		return "", fmt.Errorf("the session's gateway refused the connection: %s", strings.TrimPrefix(answer, "DENY "))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return "", err
	}
	return key, nil
}

type oneByteConn struct{ c net.Conn }

func (o oneByteConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.c.Read(p[:1])
}

// pump copies the shell's output into the ring until the shell ends.
func (t *pamTerminal) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := t.shell.Read(buf)
		if n > 0 {
			t.mu.Lock()
			t.ring = append(t.ring, buf[:n]...)
			t.end += int64(n)
			if over := len(t.ring) - pamTerminalRing; over > 0 {
				t.ring = append(t.ring[:0], t.ring[over:]...)
				t.start += int64(over)
			}
			t.notifyLocked()
			t.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	<-t.shell.Done()
	exit := t.shell.ExitStatus()
	t.mu.Lock()
	t.closed, t.exit = true, &exit
	t.notifyLocked()
	t.mu.Unlock()
}

func (t *pamTerminal) notifyLocked() {
	close(t.signal)
	t.signal = make(chan struct{})
}

func (s *pamService) terminal(tenantID, sessionID, terminalID, principal string) (*pamTerminal, error) {
	s.browser.mu.Lock()
	t := s.browser.terminals[terminalID]
	s.browser.mu.Unlock()
	if t == nil || t.tenantID != tenantID || t.sessionID != sessionID {
		return nil, fmt.Errorf("%w: no such terminal", api.ErrPAMInvalid)
	}
	if t.opener != principal {
		return nil, fmt.Errorf("%w: only the person who opened the session can use its terminal", api.ErrPAMRejected)
	}
	return t, nil
}

// ReadPAMTerminal returns the output from offset from, waiting up to wait for
// some when there is none yet. A reader behind the kept output starts at its
// oldest byte, marked truncated.
func (s *pamService) ReadPAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, from int64, wait time.Duration) (api.PAMTerminalOutput, error) {
	t, err := s.terminal(tenantID, sessionID, terminalID, principal)
	if err != nil {
		return api.PAMTerminalOutput{}, err
	}
	wait = min(max(wait, 0), pamTerminalWaitMax)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		t.mu.Lock()
		if from < 0 || from > t.end {
			from = t.end
		}
		if from < t.end || t.closed {
			out := api.PAMTerminalOutput{Next: t.end, Closed: t.closed && from >= t.end}
			if from < t.start {
				from, out.Truncated = t.start, true
			}
			stop := min(t.end, from+pamTerminalPage)
			out.Data = append([]byte(nil), t.ring[int(from-t.start):int(stop-t.start)]...) // #nosec G115 -- offsets within the ring, at most 1 MiB apart (CWE-190)
			out.Next = stop
			if out.Closed {
				out.ExitStatus = t.exit
			}
			t.mu.Unlock()
			return out, nil
		}
		signal := t.signal
		t.mu.Unlock()
		select {
		case <-signal:
		case <-deadline.C:
			return api.PAMTerminalOutput{Next: from}, nil
		case <-ctx.Done():
			return api.PAMTerminalOutput{}, ctx.Err()
		}
	}
}

// WritePAMTerminal types into a terminal.
func (s *pamService) WritePAMTerminal(_ context.Context, tenantID, sessionID, terminalID, principal string, data []byte) error {
	t, err := s.terminal(tenantID, sessionID, terminalID, principal)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > pamTerminalInputMax {
		return fmt.Errorf("%w: input is 1-%d bytes", api.ErrPAMInvalid, pamTerminalInputMax)
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return fmt.Errorf("%w: the terminal has ended", api.ErrPAMTerminal)
	}
	if _, err := t.shell.Write(data); err != nil {
		return fmt.Errorf("%w: the terminal has ended", api.ErrPAMTerminal)
	}
	return nil
}

// ResizePAMTerminal changes a terminal's size.
func (s *pamService) ResizePAMTerminal(_ context.Context, tenantID, sessionID, terminalID, principal string, cols, rows int) error {
	t, err := s.terminal(tenantID, sessionID, terminalID, principal)
	if err != nil {
		return err
	}
	if err := t.shell.Resize(cols, rows); err != nil {
		return fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
	}
	return nil
}

// ClosePAMTerminal ends a terminal; the session stays open.
func (s *pamService) ClosePAMTerminal(_ context.Context, tenantID, sessionID, terminalID, principal string) error {
	t, err := s.terminal(tenantID, sessionID, terminalID, principal)
	if err != nil {
		return err
	}
	s.browser.mu.Lock()
	delete(s.browser.terminals, terminalID)
	s.browser.mu.Unlock()
	return t.shell.Close()
}

// sweepBrowser forgets the tickets of sessions past their deadline and ends
// their terminals, and drops terminals whose shells ended long ago.
func (s *pamService) sweepBrowser(now time.Time) {
	s.browser.mu.Lock()
	defer s.browser.mu.Unlock()
	for key, held := range s.browser.tickets {
		if now.Before(held.expires) {
			continue
		}
		held.ticket.Destroy()
		delete(s.browser.tickets, key)
		for id, t := range s.browser.terminals {
			if t.tenantID == key.tenantID && t.sessionID == key.sessionID {
				_ = t.shell.Close()
				delete(s.browser.terminals, id)
			}
		}
		if console := s.browser.consoles[key]; console != nil {
			console.client.close()
			delete(s.browser.consoles, key)
		}
	}
}

// The served broker's browser sessions.

func (s *Server) HoldBrowserTicket(tenantID, sessionID, opener string, delivery api.PAMGatewayDelivery, ticket []byte, expires time.Time) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.HoldBrowserTicket(tenantID, sessionID, opener, delivery, ticket, expires)
}

func (s *Server) OpenPAMTerminal(ctx context.Context, tenantID, sessionID, principal string, req api.PAMTerminalRequest) (api.PAMTerminal, error) {
	if s.pam == nil {
		return api.PAMTerminal{}, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMTerminal(ctx, tenantID, sessionID, principal, req)
}

func (s *Server) ReadPAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, from int64, wait time.Duration) (api.PAMTerminalOutput, error) {
	if s.pam == nil {
		return api.PAMTerminalOutput{}, api.ErrPAMUnavailable
	}
	return s.pam.ReadPAMTerminal(ctx, tenantID, sessionID, terminalID, principal, from, wait)
}

func (s *Server) WritePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, data []byte) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.WritePAMTerminal(ctx, tenantID, sessionID, terminalID, principal, data)
}

func (s *Server) ResizePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, cols, rows int) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.ResizePAMTerminal(ctx, tenantID, sessionID, terminalID, principal, cols, rows)
}

func (s *Server) ClosePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.ClosePAMTerminal(ctx, tenantID, sessionID, terminalID, principal)
}

func (s *Server) ListPAMSessionPods(ctx context.Context, tenantID, sessionID, principal, namespace string) (api.PAMSessionPods, error) {
	if s.pam == nil {
		return api.PAMSessionPods{}, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMSessionPods(ctx, tenantID, sessionID, principal, namespace)
}

func (s *Server) RunPAMQuery(ctx context.Context, tenantID, sessionID, principal string, req api.PAMQueryRequest) (api.PAMQueryResult, error) {
	if s.pam == nil {
		return api.PAMQueryResult{}, api.ErrPAMUnavailable
	}
	return s.pam.RunPAMQuery(ctx, tenantID, sessionID, principal, req)
}
