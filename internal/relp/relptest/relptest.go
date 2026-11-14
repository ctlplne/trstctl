// SPDX-License-Identifier: BUSL-1.1

// Package relptest is a RELP receiver stand-in for tests, written from the
// protocol description (doc/relp.md in librelp): it checks every frame a
// client sends, answers each command in order and records the syslog
// messages it acknowledged. It is a test double, not a receiver to deploy.
package relptest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Receiver serves RELP sessions. Answer, when set, gives the status for the
// n-th syslog message of a session (both counted from 1): 200 acknowledges
// it, another status refuses it, and 0 sends a serverclose hint and ends the
// session without an answer. Nil acknowledges every message. Hold, when set,
// holds the answers to syslog commands until no command has arrived for that
// long, then answers them all in order (with Hold, Answer never returns 0);
// MaxOutstanding is the most commands held at once.
type Receiver struct {
	Answer func(session, n int, msg []byte) int
	Hold   time.Duration

	mu             sync.Mutex
	sessions       int
	messages       [][]byte
	violations     []string
	maxOutstanding int
}

type held struct {
	txnr, code int
	msg        []byte
}

// Serve runs one session on conn and closes conn when it ends.
func (r *Receiver) Serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r.mu.Lock()
	r.sessions++
	session := r.sessions
	r.mu.Unlock()
	br := bufio.NewReader(conn)
	opened, n := false, 0
	var pending []held
	for want := 1; ; want++ {
		if len(pending) > 0 {
			// Answer what is held once the client stops sending.
			_ = conn.SetReadDeadline(time.Now().Add(r.Hold))
			_, err := br.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				if r.answerHeld(conn, pending) != nil {
					return
				}
				pending = pending[:0]
			}
		}
		txnr, command, data, err := readCommand(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.violate("session %d: %v", session, err)
			}
			return
		}
		if txnr != want {
			r.violate("session %d: command %q has transaction number %d, want %d", session, command, txnr, want)
			return
		}
		switch {
		case command == "open" && !opened:
			offers := map[string]string{}
			for _, line := range strings.Split(string(data), "\n") {
				name, value, _ := strings.Cut(line, "=")
				offers[name] = value
			}
			if offers["relp_version"] != "0" || offers["commands"] != "syslog" || offers["relp_software"] == "" {
				r.violate("session %d: open offers %q, want relp_version=0, relp_software and commands=syslog", session, data)
				_ = answer(conn, txnr, "500 unsupported offers")
				return
			}
			if answer(conn, txnr, "200 OK\nrelp_version=0\nrelp_software=relptest\ncommands=syslog") != nil {
				return
			}
			opened = true
		case command == "syslog" && opened:
			n++
			code := 200
			if r.Answer != nil {
				code = r.Answer(session, n, data)
			}
			if r.Hold > 0 {
				pending = append(pending, held{txnr: txnr, code: code, msg: data})
				r.mu.Lock()
				r.maxOutstanding = max(r.maxOutstanding, len(pending))
				r.mu.Unlock()
				continue
			}
			if code == 0 {
				_, _ = io.WriteString(conn, "0 serverclose 0\n")
				return
			}
			if code == 200 {
				r.mu.Lock()
				r.messages = append(r.messages, data)
				r.mu.Unlock()
			}
			if answer(conn, txnr, statusText(code)) != nil {
				return
			}
		case command == "close" && opened:
			if len(pending) > 0 {
				r.violate("session %d: close with %d commands unanswered", session, len(pending))
				return
			}
			_ = answer(conn, txnr, "")
			_, _ = io.WriteString(conn, "0 serverclose 0\n")
			return
		default:
			r.violate("session %d: command %q out of place (opened %v)", session, command, opened)
			return
		}
	}
}

// answerHeld answers the held commands in order.
func (r *Receiver) answerHeld(conn net.Conn, pending []held) error {
	for _, h := range pending {
		if h.code == 200 {
			r.mu.Lock()
			r.messages = append(r.messages, h.msg)
			r.mu.Unlock()
		}
		if err := answer(conn, h.txnr, statusText(h.code)); err != nil {
			return err
		}
	}
	return nil
}

// statusText is an answer's status line; a refusal carries a text a client
// should not repeat.
func statusText(code int) string {
	if code == 200 {
		return "200 OK"
	}
	return strconv.Itoa(code) + " not taken by relptest"
}

// MaxOutstanding is the most commands held at once (with Hold).
func (r *Receiver) MaxOutstanding() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxOutstanding
}

// Sessions is how many sessions were served.
func (r *Receiver) Sessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions
}

// Messages are the syslog messages acknowledged, in order, across sessions.
func (r *Receiver) Messages() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.messages...)
}

// Violations are the ways a client broke RELP, if any.
func (r *Receiver) Violations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.violations...)
}

func (r *Receiver) violate(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.violations = append(r.violations, fmt.Sprintf(format, args...))
}

// answer writes an rsp frame for txnr carrying data.
func answer(w io.Writer, txnr int, data string) error {
	frame := strconv.Itoa(txnr) + " rsp " + strconv.Itoa(len(data))
	if data != "" {
		frame += " " + data
	}
	_, err := io.WriteString(w, frame+"\n")
	return err
}

// readCommand reads one client frame strictly: TXNR SP COMMAND SP DATALEN
// [SP DATA] LF, with no data when DATALEN is 0 and at most 128 KiB of it.
func readCommand(br *bufio.Reader) (int, string, []byte, error) {
	head, err := br.ReadString(' ')
	if err != nil {
		if head == "" && errors.Is(err, io.EOF) {
			return 0, "", nil, io.EOF
		}
		return 0, "", nil, fmt.Errorf("a frame ends inside its transaction number: %w", err)
	}
	txnr, err := strconv.Atoi(strings.TrimSuffix(head, " "))
	if err != nil || txnr < 1 || txnr > 999_999_999 || len(head) > 10 {
		return 0, "", nil, fmt.Errorf("transaction number %q", head)
	}
	command, err := br.ReadString(' ')
	command = strings.TrimSuffix(command, " ")
	if err != nil || command == "" || len(command) > 32 || strings.Trim(command, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return 0, "", nil, fmt.Errorf("command %q", command)
	}
	var digits []byte
	for {
		c, err := br.ReadByte()
		if err != nil {
			return 0, "", nil, fmt.Errorf("a frame ends inside its data length: %w", err)
		}
		if c == ' ' || c == '\n' {
			size, err := strconv.Atoi(string(digits))
			if err != nil || len(digits) > 9 || size > 128<<10 || (c == '\n') != (size == 0) {
				return 0, "", nil, fmt.Errorf("data length %q followed by %q", digits, c)
			}
			if size == 0 {
				return txnr, command, nil, nil
			}
			data := make([]byte, size+1)
			if _, err := io.ReadFull(br, data); err != nil {
				return 0, "", nil, fmt.Errorf("a frame ends inside its data: %w", err)
			}
			if data[size] != '\n' {
				return 0, "", nil, errors.New("a frame's data is not followed by a line feed")
			}
			return txnr, command, data[:size], nil
		}
		digits = append(digits, c)
	}
}
