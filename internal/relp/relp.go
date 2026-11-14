// SPDX-License-Identifier: BUSL-1.1

// Package relp is a client for RELP, the Reliable Event Logging Protocol
// (doc/relp.md in librelp, its reference implementation). Each syslog message
// is a command the receiver answers, so the sender learns that every message
// was taken, not only written to a socket (P5-L3). Send opens a session, sends
// the messages with at most Window commands outstanding, reads each answer in
// order and closes the session. It speaks over any stream; audit feeds run it
// over a verified TLS connection.
package relp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall"
)

const (
	// Window is the most commands outstanding at once (librelp's default).
	Window = 128
	// MaxMessage is RELP's limit on one command's data, 128 KiB.
	MaxMessage = 128 << 10
	// maxAnswer bounds the data of an answer: a status line and the offers.
	maxAnswer = 64 << 10
	// maxHints bounds the hints (transaction number 0) read before an answer.
	maxHints = 16
	// maxTxnr is the last transaction number; the next one is 1 again.
	maxTxnr = 999_999_999
	// offeredVersion is the relp_version offered: 0, which deployed receivers
	// speak (librelp answers a higher version as incompatible).
	offeredVersion = "0"
)

var (
	// ErrRefused reports a session or a message the receiver answered with an
	// error status.
	ErrRefused = errors.New("relp: the receiver refused")
	// ErrClosed reports a session the receiver closed with commands
	// unanswered.
	ErrClosed = errors.New("relp: the receiver closed the session")
	// ErrProtocol reports a frame that breaks RELP's framing or an answer that
	// does not match its command.
	ErrProtocol = errors.New("relp: protocol error")
)

type frame struct {
	txnr    int
	command string
	data    []byte
}

type session struct {
	conn io.Writer
	r    *bufio.Reader
	out  []byte
	txnr int
}

// Send opens a RELP session on conn, sends each message as a syslog command
// and returns once the receiver has acknowledged every one, closing the
// session. acked is how many messages, from the first, the receiver
// acknowledged. A refused session or message, a frame that breaks the
// framing, an answer out of order or a session the receiver closes ends the
// send with an error that names the message and the status, never the
// receiver's own text. The caller bounds the exchange with a deadline on conn.
func Send(conn io.ReadWriter, software string, messages [][]byte) (acked int, err error) {
	for i, msg := range messages {
		if len(msg) == 0 || len(msg) > MaxMessage {
			return 0, fmt.Errorf("relp: message %d is %d bytes; a message is 1 to %d bytes", i+1, len(msg), MaxMessage)
		}
	}
	if software == "" || strings.ContainsAny(software, "\n\r") {
		return 0, errors.New("relp: the software name is empty or spans lines")
	}
	s := &session{conn: conn, r: bufio.NewReaderSize(conn, 4096)}
	// The batch's bytes pass through out; clear it however the send ends.
	defer func() { clear(s.out[:cap(s.out)]) }()
	if err := s.open(software); err != nil {
		return 0, err
	}
	pending := make([]int, len(messages))
	sent := 0
	for acked < len(messages) {
		for sent < len(messages) && sent-acked < Window {
			pending[sent] = s.queue("syslog", messages[sent])
			sent++
		}
		if err := s.flush(); err != nil {
			return acked, err
		}
		answer, err := s.answer()
		if err != nil {
			return acked, fmt.Errorf("%w (message %d of %d unanswered)", err, acked+1, len(messages))
		}
		if answer.txnr != pending[acked] {
			return acked, fmt.Errorf("%w: answer %d for message %d of %d, which was command %d", ErrProtocol, answer.txnr, acked+1, len(messages), pending[acked])
		}
		if code, _ := status(answer.data); code != 200 {
			return acked, fmt.Errorf("%w message %d of %d (status %d)", ErrRefused, acked+1, len(messages), code)
		}
		acked++
	}
	// Every message is acknowledged; the close is a courtesy whose failure
	// takes nothing back.
	s.queue("close", nil)
	if s.flush() == nil {
		_, _ = s.answer()
	}
	return acked, nil
}

// open sends the session's offers and checks the receiver's: a status of
// 200, a relp_version and the syslog command.
func (s *session) open(software string) error {
	txnr := s.queue("open", []byte("relp_version="+offeredVersion+"\nrelp_software="+software+"\ncommands=syslog"))
	if err := s.flush(); err != nil {
		return err
	}
	answer, err := s.answer()
	if err != nil {
		return fmt.Errorf("%w (opening the session)", err)
	}
	if answer.txnr != txnr {
		return fmt.Errorf("%w: answer %d to the open, which was command %d", ErrProtocol, answer.txnr, txnr)
	}
	code, offers := status(answer.data)
	if code != 200 {
		return fmt.Errorf("%w the session (status %d)", ErrRefused, code)
	}
	version, commands := false, false
	for _, line := range strings.Split(string(offers), "\n") {
		name, value, _ := strings.Cut(strings.TrimRight(line, "\r"), "=")
		switch name {
		case "relp_version":
			if _, err := strconv.Atoi(value); err == nil {
				version = true
			}
		case "commands":
			for _, command := range strings.Split(value, ",") {
				commands = commands || command == "syslog"
			}
		}
	}
	if !version || !commands {
		return fmt.Errorf("%w: the receiver's offers name no relp_version or no syslog command", ErrProtocol)
	}
	return nil
}

// queue appends one command frame (TXNR SP COMMAND SP DATALEN [SP DATA] LF)
// and returns its transaction number.
func (s *session) queue(command string, data []byte) int {
	s.txnr++
	if s.txnr > maxTxnr {
		s.txnr = 1
	}
	s.out = strconv.AppendInt(s.out, int64(s.txnr), 10)
	s.out = append(s.out, ' ')
	s.out = append(s.out, command...)
	s.out = append(s.out, ' ')
	s.out = strconv.AppendInt(s.out, int64(len(data)), 10)
	if len(data) > 0 {
		s.out = append(s.out, ' ')
		s.out = append(s.out, data...)
	}
	s.out = append(s.out, '\n')
	return s.txnr
}

func (s *session) flush() error {
	_, err := s.conn.Write(s.out)
	clear(s.out)
	s.out = s.out[:0]
	if err != nil {
		return fmt.Errorf("relp: send: %w", err)
	}
	return nil
}

// answer reads the next answer, passing over hints; a serverclose hint ends
// the session.
func (s *session) answer() (frame, error) {
	for range maxHints + 1 {
		f, err := readFrame(s.r)
		if err != nil {
			return frame{}, err
		}
		if f.txnr == 0 {
			if f.command == "serverclose" {
				return frame{}, ErrClosed
			}
			continue
		}
		if f.command != "rsp" {
			return frame{}, fmt.Errorf("%w: the receiver sent a %q command", ErrProtocol, f.command)
		}
		return f, nil
	}
	return frame{}, fmt.Errorf("%w: more than %d hints without an answer", ErrProtocol, maxHints)
}

// readFrame reads one frame: TXNR SP COMMAND SP DATALEN [SP DATA] LF, with
// TXNR and DATALEN at most nine digits, COMMAND one to 32 letters and DATA at
// most maxAnswer bytes.
func readFrame(r *bufio.Reader) (frame, error) {
	txnr, sep, err := readNumber(r)
	if err != nil {
		return frame{}, err
	}
	if sep != ' ' {
		return frame{}, fmt.Errorf("%w: no space after the transaction number", ErrProtocol)
	}
	var command []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return frame{}, readError(err)
		}
		if c == ' ' && len(command) > 0 {
			break
		}
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter || len(command) == 32 {
			return frame{}, fmt.Errorf("%w: a command is one to 32 letters", ErrProtocol)
		}
		command = append(command, c)
	}
	size, sep, err := readNumber(r)
	if err != nil {
		return frame{}, err
	}
	if size > maxAnswer {
		return frame{}, fmt.Errorf("%w: a %d-byte frame is over the %d-byte limit", ErrProtocol, size, maxAnswer)
	}
	var data []byte
	switch {
	case sep == '\n' && size == 0:
		return frame{txnr: txnr, command: string(command)}, nil
	case sep != ' ':
		return frame{}, fmt.Errorf("%w: no space after the data length", ErrProtocol)
	case size > 0:
		data = make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return frame{}, readError(err)
		}
	}
	trailer, err := r.ReadByte()
	if err != nil {
		return frame{}, readError(err)
	}
	if trailer != '\n' {
		return frame{}, fmt.Errorf("%w: the frame does not end its data with a line feed", ErrProtocol)
	}
	return frame{txnr: txnr, command: string(command), data: data}, nil
}

// readNumber reads one to nine digits and the byte after them.
func readNumber(r *bufio.Reader) (int, byte, error) {
	n, digits := 0, 0
	for {
		c, err := r.ReadByte()
		if err != nil {
			return 0, 0, readError(err)
		}
		if c < '0' || c > '9' {
			if digits == 0 {
				return 0, 0, fmt.Errorf("%w: a number is one to nine digits", ErrProtocol)
			}
			return n, c, nil
		}
		if digits == 9 {
			return 0, 0, fmt.Errorf("%w: a number is one to nine digits", ErrProtocol)
		}
		n, digits = n*10+int(c-'0'), digits+1
	}
}

// readError is a read that ended early: the receiver closed or reset the
// session, or the read failed.
func readError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return ErrClosed
	}
	return fmt.Errorf("relp: receive: %w", err)
}

// status reads an answer's data: a three-digit status, an optional text, and
// after the first line feed the command's own data (an open's offers).
func status(data []byte) (int, []byte) {
	line, rest, _ := bytes.Cut(data, []byte("\n"))
	if len(line) < 3 || (len(line) > 3 && line[3] != ' ') {
		return 0, nil
	}
	code, err := strconv.Atoi(string(line[:3]))
	if err != nil {
		return 0, nil
	}
	return code, rest
}
