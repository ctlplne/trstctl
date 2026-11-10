// SPDX-License-Identifier: BUSL-1.1

package email

import (
	"encoding/base64"
	"errors"
	"net"
	"net/textproto"
	"strings"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// smtpSession is the SMTP exchange the email channel needs (RFC 5321, with
// STARTTLS from RFC 3207 and AUTH PLAIN from RFC 4954 and RFC 4616) over a
// connection it owns (P15-L5). It replaces net/smtp's client, whose Client.Auth
// base64-encodes the PLAIN response — the password — into a command string and
// its writer's buffer, copies nothing here can wipe. Here the response is built
// in one buffer, written straight to the connection (after TLS, sealed in
// place) and wiped. Every other command and the wire it puts down are
// net/smtp's.
type smtpSession struct {
	conn net.Conn
	text *textproto.Conn
	host string
	tls  bool
	ext  map[string]string
}

// plainLineWritten is a test seam: it sees the AUTH line's buffer after the
// write and before the wipe, so a test can hold it and check it is zeroed.
var plainLineWritten = func([]byte) {}

func newSMTPSession(conn net.Conn, host string) (*smtpSession, error) {
	s := &smtpSession{conn: conn, text: textproto.NewConn(conn), host: host}
	if _, _, err := s.text.ReadResponse(220); err != nil {
		_ = s.text.Close()
		return nil, err
	}
	return s, nil
}

func (s *smtpSession) cmd(expect int, format string, args ...any) (int, string, error) {
	id, err := s.text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	s.text.StartResponse(id)
	defer s.text.EndResponse(id)
	return s.text.ReadResponse(expect)
}

// ehlo greets with EHLO and records the extensions the server offers.
func (s *smtpSession) ehlo() error {
	_, msg, err := s.cmd(250, "EHLO localhost")
	if err != nil {
		return err
	}
	ext := map[string]string{}
	if lines := strings.Split(msg, "\n"); len(lines) > 1 {
		for _, line := range lines[1:] {
			k, v, _ := strings.Cut(line, " ")
			ext[k] = v
		}
	}
	s.ext = ext
	return nil
}

// hello is EHLO, falling back to HELO as net/smtp does.
func (s *smtpSession) hello() error {
	if err := s.ehlo(); err != nil {
		s.ext = nil
		_, _, herr := s.cmd(250, "HELO localhost")
		return herr
	}
	return nil
}

func (s *smtpSession) extension(name string) bool {
	if s.ext == nil {
		return false
	}
	_, ok := s.ext[strings.ToUpper(name)]
	return ok
}

// startTLS upgrades the session and greets again over TLS.
func (s *smtpSession) startTLS() error {
	if _, _, err := s.cmd(220, "STARTTLS"); err != nil {
		return err
	}
	conn, err := mtls.SMTPStartTLS(s.conn, s.host)
	if err != nil {
		return err
	}
	s.conn, s.text, s.tls = conn, textproto.NewConn(conn), true
	return s.ehlo()
}

// authPlain authenticates with PLAIN and its initial response. Credentials go
// only over TLS or to localhost, net/smtp's PlainAuth rule. The response
// "\x00user\x00password", its base64 and the command line around it live in
// buffers this function owns; the line is written to the connection directly
// (not through the buffered writer) and every buffer is wiped before return.
func (s *smtpSession) authPlain(username string, password []byte) error {
	if !s.tls && !isLocalhost(s.host) {
		return errors.New("email: refusing to send the SMTP password over an unencrypted connection")
	}
	if strings.ContainsAny(username, "\x00\r\n") {
		return errors.New("email: the SMTP username must not contain NUL, CR or LF")
	}
	raw := make([]byte, 0, len(username)+len(password)+2)
	raw = append(raw, 0)
	raw = append(raw, username...)
	raw = append(raw, 0)
	raw = append(raw, password...)
	defer secret.Wipe(raw)
	const verb = "AUTH PLAIN "
	line := make([]byte, len(verb)+base64.StdEncoding.EncodedLen(len(raw))+2)
	defer secret.Wipe(line)
	n := copy(line, verb)
	base64.StdEncoding.Encode(line[n:], raw)
	copy(line[len(line)-2:], "\r\n")
	if err := s.text.W.Flush(); err != nil {
		return err
	}
	if _, err := s.conn.Write(line); err != nil {
		return err
	}
	plainLineWritten(line)
	_, _, err := s.text.ReadResponse(235)
	return err
}

// validateLine refuses a CR or LF that would end a command early, as net/smtp
// does for MAIL and RCPT.
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}

func (s *smtpSession) mail(from string) error {
	if err := validateLine(from); err != nil {
		return err
	}
	format := "MAIL FROM:<%s>"
	if s.ext != nil {
		if _, ok := s.ext["8BITMIME"]; ok {
			format += " BODY=8BITMIME"
		}
		if _, ok := s.ext["SMTPUTF8"]; ok {
			format += " SMTPUTF8"
		}
	}
	_, _, err := s.cmd(250, format, from)
	return err
}

func (s *smtpSession) rcpt(to string) error {
	if err := validateLine(to); err != nil {
		return err
	}
	_, _, err := s.cmd(25, "RCPT TO:<%s>", to)
	return err
}

func (s *smtpSession) data(msg []byte) error {
	if _, _, err := s.cmd(354, "DATA"); err != nil {
		return err
	}
	w := s.text.DotWriter()
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, _, err := s.text.ReadResponse(250)
	return err
}

func (s *smtpSession) quit() error {
	if _, _, err := s.cmd(221, "QUIT"); err != nil {
		return err
	}
	return s.text.Close()
}

func (s *smtpSession) close() error { return s.text.Close() }
