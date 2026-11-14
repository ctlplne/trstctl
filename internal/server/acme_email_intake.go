// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/dkim"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// The RFC 8823 reply intake (P15): an SMTP receiver for the ACME challenge
// address only, to which the operator's mail system routes replies. Each
// message is parsed as an RFC 8823 reply, its DKIM signature is verified for
// its From domain (d= equal to it), and it goes to the ACME server, which
// matches it to a pending challenge by mailbox and token-part1 digest. A reply
// that fails a step is refused with a 5xx code naming the reason, so the
// sender's mail system bounces it to the user. It never relays, takes one
// recipient, bounds message size, sessions and commands, and offers STARTTLS
// when the control plane has a TLS certificate. Like every ACME request, a
// reply must reach the process that created the order.

const (
	acmeEmailIntakeMaxSessions    = 16
	acmeEmailIntakeSessionTimeout = 2 * time.Minute
	acmeEmailIntakeMaxCommands    = 64
	acmeEmailIntakeMaxLine        = 1024
)

// acmeEmailIntake is the configured reply intake.
type acmeEmailIntake struct {
	addr     string
	host     string
	from     string
	verifier dkim.Verifier
}

func newACMEEmailIntake(cfg config.ACMEEmail) *acmeEmailIntake {
	addr := strings.TrimSpace(cfg.SMTPListen)
	from, err := acme.NormalizeEmailIdentifier(strings.TrimSpace(cfg.From))
	if addr == "" || err != nil {
		return nil
	}
	return &acmeEmailIntake{
		addr: addr, host: from[strings.LastIndexByte(from, '@')+1:], from: from,
		verifier: dkim.Verifier{Lookup: net.DefaultResolver.LookupTXT, Pinned: cfg.DKIMKeys},
	}
}

// ACMEEmailIntakeAddr is the reply intake's listen address, or "" when it is
// not configured or ACME email challenges are not served.
func (s *Server) ACMEEmailIntakeAddr() string {
	if s == nil || s.acmeEmailIntake == nil || s.protocols == nil || s.protocols.acme == nil {
		return ""
	}
	return s.acmeEmailIntake.addr
}

// RunACMEEmailIntake serves the reply intake until ctx ends.
func (s *Server) RunACMEEmailIntake(ctx context.Context) {
	addr := s.ACMEEmailIntakeAddr()
	if addr == "" {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("ACME email reply intake listen failed", "addr", addr, "error", err.Error())
		return
	}
	var tlsCert *mtls.ServerCert
	if s.serverTLS.Mode != config.TLSDisabled {
		if tlsCert, err = controlPlaneServerCert(s.serverTLS); err != nil {
			s.logger.Warn("ACME email reply intake runs without STARTTLS: the server certificate is unavailable", "error", err.Error())
			tlsCert = nil
		}
	}
	s.serveACMEEmailIntake(ctx, ln, tlsCert)
}

func (s *Server) serveACMEEmailIntake(ctx context.Context, ln net.Listener, tlsCert *mtls.ServerCert) {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	slots := make(chan struct{}, acmeEmailIntakeMaxSessions)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				s.acmeEmailIntakeSession(ctx, conn, tlsCert)
			}()
		default:
			_, _ = conn.Write([]byte("421 4.3.2 too many sessions, try again later\r\n"))
			_ = conn.Close()
		}
	}
}

// acmeEmailIntakeSession runs one SMTP session (RFC 5321) for replies.
func (s *Server) acmeEmailIntakeSession(ctx context.Context, conn net.Conn, tlsCert *mtls.ServerCert) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(acmeEmailIntakeSessionTimeout))
	intake := s.acmeEmailIntake
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(lines ...string) {
		for _, line := range lines {
			_, _ = w.WriteString(line + "\r\n")
		}
		_ = w.Flush()
	}
	reply("220 " + intake.host + " ESMTP trstctl ACME reply intake")
	recipient, secured := false, false
	for range acmeEmailIntakeMaxCommands {
		line, err := readSMTPLine(r)
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			lines := []string{"250-" + intake.host, fmt.Sprintf("250-SIZE %d", acme.MaxEmailReplyBytes)}
			if tlsCert != nil && !secured {
				lines = append(lines, "250-STARTTLS")
			}
			// P15-L4: a reply from a mailbox with a non-ASCII local part comes
			// with SMTPUTF8 (RFC 6531) and UTF-8 header fields (RFC 6532).
			reply(append(lines, "250-SMTPUTF8", "250 8BITMIME")...)
		case "HELO":
			reply("250 " + intake.host)
		case "STARTTLS":
			if tlsCert == nil || secured {
				reply("454 4.7.0 TLS not available")
				continue
			}
			reply("220 2.0.0 ready to start TLS")
			conn = tlsCert.ServerConn(conn)
			r, w, recipient, secured = bufio.NewReader(conn), bufio.NewWriter(conn), false, true
		case "MAIL":
			recipient = false
			reply("250 2.1.0 ok")
		case "RCPT":
			if smtpPathAddress(arg) != intake.from {
				reply("550 5.1.1 this server takes replies for " + intake.from + " only")
				continue
			}
			recipient = true
			reply("250 2.1.5 ok")
		case "DATA":
			if !recipient {
				reply("503 5.5.1 RCPT first")
				continue
			}
			reply("354 end with <CRLF>.<CRLF>")
			msg, tooBig, err := readSMTPData(r, acme.MaxEmailReplyBytes)
			if err != nil {
				return
			}
			recipient = false
			if tooBig {
				reply(fmt.Sprintf("552 5.3.4 a reply is at most %d bytes", acme.MaxEmailReplyBytes))
				continue
			}
			reply(s.acceptACMEEmailReply(ctx, msg))
		case "RSET":
			recipient = false
			reply("250 2.0.0 ok")
		case "NOOP":
			reply("250 2.0.0 ok")
		case "QUIT":
			reply("221 2.0.0 bye")
			return
		default:
			reply("502 5.5.2 command not implemented")
		}
	}
	reply("421 4.7.0 too many commands")
}

// acceptACMEEmailReply checks one received message and answers it with an
// SMTP reply line.
func (s *Server) acceptACMEEmailReply(ctx context.Context, msg []byte) string {
	parsed, err := acme.ParseEmailReply(msg)
	if err != nil {
		s.refuseACMEEmailReply(ctx, acme.EmailReplyRefusedMalformed, "", "", err)
		return "550 5.6.0 not an RFC 8823 reply: " + strings.TrimPrefix(err.Error(), "acme: ")
	}
	domain := strings.ToLower(parsed.From[strings.LastIndexByte(parsed.From, '@')+1:])
	if err := s.acmeEmailIntake.verifier.VerifyDomain(ctx, msg, domain); err != nil {
		s.refuseACMEEmailReply(ctx, acme.EmailReplyRefusedDKIM, domain, "", err)
		return "550 5.7.20 no valid DKIM signature from " + domain
	}
	challengeID, err := s.protocols.acme.AcceptEmailReply(ctx, acme.EmailReply(parsed))
	switch {
	case err == nil:
		return "250 2.0.0 reply accepted"
	case errors.Is(err, acme.ErrEmailReplyUnmatched):
		s.refuseACMEEmailReply(ctx, acme.EmailReplyRefusedUnmatched, domain, "", err)
		return "550 5.7.1 no pending ACME challenge for this mailbox and token"
	case errors.Is(err, acme.ErrEmailReplyWrongResponse):
		s.refuseACMEEmailReply(ctx, acme.EmailReplyRefusedWrongResponse, domain, challengeID, err)
		return "550 5.7.1 the response does not match; the challenge is now invalid"
	default:
		s.refuseACMEEmailReply(ctx, acme.EmailReplyRefusedError, domain, "", err)
		return "451 4.3.0 the reply could not be processed; try again later"
	}
}

// refuseACMEEmailReply logs a refused reply and records it as an audit event
// (P15-L9), so a run of forged or misrouted replies shows in the tenant's
// audit trail and not only in one process's log.
func (s *Server) refuseACMEEmailReply(ctx context.Context, outcome, domain, challengeID string, err error) {
	if s.logger != nil {
		s.logger.Info("ACME email reply refused", slog.String("outcome", outcome), slog.String("from_domain", domain), slog.String("error", err.Error()))
	}
	s.protocols.acme.RecordEmailReplyRefused(ctx, outcome, domain, challengeID)
}

// readSMTPLine reads one command line, without its CRLF.
func readSMTPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(line) > acmeEmailIntakeMaxLine {
		return "", errors.New("smtp: command line too long")
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// readSMTPData reads a DATA body to its "." line, undoing dot-stuffing and
// keeping CRLF line ends (DKIM signs them). Past max bytes it keeps reading
// to the end and reports tooBig.
func readSMTPData(r *bufio.Reader, max int) ([]byte, bool, error) {
	var msg []byte
	tooBig := false
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			tooBig = true
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if string(line) == ".\r\n" {
			return msg, tooBig, nil
		}
		if len(line) > 1 && line[0] == '.' {
			line = line[1:]
		}
		if len(msg)+len(line) > max {
			tooBig = true
			continue
		}
		msg = append(msg, line...)
	}
}

// smtpPathAddress is the normalized address in a MAIL/RCPT argument
// ("TO:<a@b>" or "FROM:<a@b> SIZE=10").
func smtpPathAddress(arg string) string {
	_, rest, ok := strings.Cut(arg, "<")
	if !ok {
		return ""
	}
	address, _, ok := strings.Cut(rest, ">")
	if !ok {
		return ""
	}
	normalized, err := acme.NormalizeEmailIdentifier(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	return normalized
}
