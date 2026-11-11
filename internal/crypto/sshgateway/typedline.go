// SPDX-License-Identifier: BUSL-1.1

package sshgateway

import (
	"bytes"
	"context"
	"io"
	"unicode/utf8"
)

// Typed lines in an interactive device shell (A270-L1).
//
// A network device's command line is a line editor: the device echoes each key,
// edits the line, and runs it on Enter. The gateway forwards every key as it is
// typed, so the device's own editing and echo work as they always do, and keeps
// its own copy of the line. Only the line's submission waits for the guard: an
// allowed line's Enter is forwarded; a refused line is killed at the device
// (Ctrl-U, then an empty Enter, which shows a fresh prompt) and never runs.
//
// The copy follows the keys the IOS-XE, Junos, EOS, FortiOS and tmsh editors
// share: printable input, erase (Backspace, Delete), kill line (Ctrl-U, and
// Ctrl-C, which abandons it) and erase word (Ctrl-W). "?" asks the device for
// help and is not part of the line. Any other control key or escape sequence
// (history recall, completion, cursor movement) can change the line in ways the
// gateway cannot follow, so the line becomes unreadable until it is submitted or
// killed, and an unreadable line is refused on submission.

const (
	keyCtrlC     = 0x03
	keyBackspace = 0x08
	keyCtrlU     = 0x15
	keyCtrlW     = 0x17
	keyCtrlZ     = 0x1a
	keyDelete    = 0x7f
)

// refusedLineNotice is what the client sees in place of a refused line's output.
const refusedLineNotice = "\r\n% trstctl: the gateway refused this line under the session's command rules\r\n"

// typedLine is the gateway's copy of the line the device's editor holds.
type typedLine struct {
	buf      []byte
	readable bool
}

func (l *typedLine) reset() {
	clear(l.buf)
	l.buf = l.buf[:0]
	l.readable = true
}

func (l *typedLine) add(b byte) {
	if len(l.buf) >= MaxExecCommandBytes {
		l.readable = false
		return
	}
	l.buf = append(l.buf, b)
}

func (l *typedLine) erase() {
	if len(l.buf) == 0 {
		return
	}
	_, size := utf8.DecodeLastRune(l.buf)
	clear(l.buf[len(l.buf)-size:])
	l.buf = l.buf[:len(l.buf)-size]
}

func (l *typedLine) eraseWord() {
	end := len(l.buf)
	for end > 0 && l.buf[end-1] == ' ' {
		end--
	}
	for end > 0 && l.buf[end-1] != ' ' {
		end--
	}
	clear(l.buf[end:])
	l.buf = l.buf[:end]
}

// pumpTypedLines forwards from (the client's typed input) to to (the device) as
// it is typed, holding each line's submission until check allows the line. A
// line submits on Enter (CR or LF) or Ctrl-Z, which on IOS-XE runs the line and
// leaves configuration mode. check receives the line and whether the gateway
// could follow it; refused is called once for each refused line. The client
// writer receives the notice for a refused line.
func pumpTypedLines(ctx context.Context, from io.Reader, to, client io.Writer, check func(context.Context, []byte, bool) bool, refused func()) error {
	line := typedLine{readable: true}
	defer line.reset()
	in := make([]byte, 4096)
	out := make([]byte, 0, 4096)
	defer func() { clear(in); clear(out[:cap(out)]) }()
	flush := func() error {
		if len(out) == 0 {
			return nil
		}
		_, err := to.Write(out)
		clear(out)
		out = out[:0]
		return err
	}
	for {
		n, readErr := from.Read(in)
		for _, b := range in[:n] {
			switch {
			case b == '\r' || b == '\n' || b == keyCtrlZ:
				if line.readable && len(bytes.TrimSpace(line.buf)) == 0 {
					out = append(out, b)
					line.reset()
					continue
				}
				// Everything typed so far reaches the device before the
				// decision, so the device's line is the one judged.
				if err := flush(); err != nil {
					return err
				}
				if check(ctx, line.buf, line.readable) {
					out = append(out, b)
				} else {
					out = append(out, keyCtrlU, '\r')
					refused()
					_, _ = io.WriteString(client, refusedLineNotice)
				}
				line.reset()
			case b == keyBackspace || b == keyDelete:
				line.erase()
				out = append(out, b)
			case b == keyCtrlU || b == keyCtrlC:
				line.reset()
				out = append(out, b)
			case b == keyCtrlW:
				line.eraseWord()
				out = append(out, b)
			case b == '?':
				out = append(out, b)
			case b < 0x20:
				line.readable = false
				out = append(out, b)
			default:
				line.add(b)
				out = append(out, b)
			}
		}
		if err := flush(); err != nil {
			return err
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
