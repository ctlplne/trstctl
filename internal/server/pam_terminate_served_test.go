// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func decodeJSONMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// liveShell starts a stock ssh session that answers each line it is sent;
// it is the long-running SSH session a termination must stop.
type liveShell struct {
	t     *testing.T
	stdin io.WriteCloser
	lines *bufio.Scanner
	done  chan error
}

// liveShellScript answers each line it reads.
const liveShellScript = `while read line; do echo "got $line"; done`

func startLiveShell(t *testing.T, cmd *exec.Cmd) *liveShell {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &liveShell{t: t, stdin: stdin, lines: bufio.NewScanner(stdout), done: make(chan error, 1)}
	go func() { s.done <- cmd.Wait() }()
	return s
}

func (s *liveShell) echo(word string) {
	s.t.Helper()
	if _, err := io.WriteString(s.stdin, word+"\n"); err != nil {
		s.t.Fatalf("write to the live session: %v", err)
	}
	got := make(chan string, 1)
	go func() {
		if s.lines.Scan() {
			got <- s.lines.Text()
		}
		close(got)
	}()
	select {
	case line := <-got:
		if line != "got "+word {
			s.t.Fatalf("live session answered %q", line)
		}
	case <-time.After(30 * time.Second):
		s.t.Fatalf("live session did not answer %q", word)
	}
}

func (s *liveShell) ended(within time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(within):
		return false
	}
}

// TestServedOperatorTerminatesLiveSessionsWithBoundedUncertaintyA255: an
// operator with access:terminate ends a long-running SSH session and a
// database session; both connections stop and the gateway's report
// acknowledges it. A gateway cut off from the control plane leaves a
// termination uncertain until the session's native deadline, then
// acknowledged when it reconnects. A session's maximum length ends it at its
// deadline. The requester, holding access:write, cannot terminate.
func TestServedOperatorTerminatesLiveSessionsWithBoundedUncertaintyA255(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h

	// A long-running SSH session and an open database session.
	sshSession := f.openSSH("a255-term-ssh", 120)
	sshCommand, stopSSH := f.sshTunnel(sshSession)
	defer stopSSH()
	shell := startLiveShell(t, sshCommand(liveShellScript))
	shell.echo("before")
	pgSession := f.openPostgres("a255-term-pg", 50)
	local, stopPG := f.postgresTunnel(pgSession)
	defer stopPG()
	pgCtx, pgCancel := context.WithTimeout(f.ctx, 30*time.Second)
	conn, err := pgconn.Connect(pgCtx, "postgres://client@"+local+"/postgres?sslmode=disable")
	pgCancel()
	if err != nil {
		t.Fatalf("database session through the gateway: %v", err)
	}
	if r := conn.ExecParams(f.ctx, "SELECT 1", nil, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}

	terminate := func(token, key, id string) (int, map[string]any) {
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/terminate", token, key,
			map[string]any{"reason": "operator saw a destructive command"})
		if status == http.StatusAccepted {
			return status, decodeJSONMap(t, body)
		}
		return status, nil
	}
	if status, _ := terminate(f.requester, "a255-term-requester", sshSession.ID); status != http.StatusForbidden {
		t.Fatalf("the requester terminated a session: %d", status)
	}
	for _, id := range []string{sshSession.ID, pgSession.ID} {
		if status, _ := terminate(f.operator, "a255-term-"+id, id); status != http.StatusAccepted {
			t.Fatalf("terminate %s = %d", id, status)
		}
	}
	if !shell.ended(30 * time.Second) {
		t.Fatalf("the terminated SSH session is still running (gateway: %s)", f.gatewayLog.String())
	}
	a201Await(t, "the terminated database connection is closed", func() bool {
		return conn.ExecParams(f.ctx, "SELECT 1", nil, nil, nil, nil).Read().Err != nil
	})
	for _, id := range []string{sshSession.ID, pgSession.ID} {
		a201Await(t, "the gateway acknowledges terminating "+id, func() bool {
			end, _ := f.sessionRead(id)["gateway_end"].(map[string]any)
			return end != nil && end["ended"] == "recalled"
		})
		if _, uncertain := f.sessionRead(id)["uncertain_until"]; uncertain {
			t.Fatalf("an acknowledged termination is still uncertain: %v", f.sessionRead(id))
		}
	}

	// A gateway cut off from the control plane: the termination is
	// uncertain up to the session's deadline, then acknowledged once it
	// reconnects.
	cutOff := f.openSSH("a255-term-cutoff", 120)
	cutCommand, stopCut := f.sshTunnel(cutOff)
	defer stopCut()
	cutShell := startLiveShell(t, cutCommand(liveShellScript))
	cutShell.echo("before the partition")
	h.stopChannel()
	if status, _ := terminate(f.operator, "a255-term-cutoff-terminate", cutOff.ID); status != http.StatusAccepted {
		t.Fatalf("terminate during the partition = %d", status)
	}
	read := f.sessionRead(cutOff.ID)
	deadline, _ := time.Parse(time.RFC3339Nano, read["expires_at"].(string))
	uncertain, _ := time.Parse(time.RFC3339Nano, read["uncertain_until"].(string))
	if read["gateway_end"] != nil || !uncertain.Equal(deadline) {
		t.Fatalf("a termination the gateway cannot hear = %v, want uncertain until %s", read, deadline)
	}
	cutShell.echo("during the partition") // the gateway has not heard yet
	channel, err := net.Listen("tcp", h.channelAddr)
	for start := time.Now(); err != nil && time.Since(start) < 10*time.Second; time.Sleep(50 * time.Millisecond) {
		channel, err = net.Listen("tcp", h.channelAddr)
	}
	if err != nil {
		t.Fatalf("serve the agent channel again: %v", err)
	}
	channelCtx, stopChannel := context.WithCancel(f.ctx)
	channelDone := make(chan struct{})
	go func() { defer close(channelDone); h.srv.serveAgentChannel(channelCtx, channel) }()
	t.Cleanup(func() { stopChannel(); <-channelDone })
	if !cutShell.ended(60 * time.Second) {
		t.Fatal("the cut-off gateway kept the terminated session after it reconnected")
	}
	a201Await(t, "the reconnected gateway acknowledges the termination", func() bool {
		end, _ := f.sessionRead(cutOff.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})

	// A session's maximum length: the gateway ends it at its deadline.
	short := f.openSSH("a255-term-deadline", 6)
	shortCommand, stopShort := f.sshTunnel(short)
	defer stopShort()
	shortShell := startLiveShell(t, shortCommand(liveShellScript))
	shortShell.echo("inside the window")
	if !shortShell.ended(30 * time.Second) {
		t.Fatal("a session outlived its maximum length")
	}
	a201Await(t, "the gateway reports the deadline", func() bool {
		end, _ := f.sessionRead(short.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "deadline"
	})
	if slices.Contains(f.gw.Sessions(), short.ID) || !strings.Contains(f.gatewayLog.String(), "ended: deadline") {
		t.Fatalf("gateway log = %s", f.gatewayLog.String())
	}
}
