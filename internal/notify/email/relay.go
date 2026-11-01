// SPDX-License-Identifier: BUSL-1.1

package email

import (
	"errors"
	"net/smtp"
)

// NewRelaySender returns a Sender that delivers a rendered message through
// the SMTP relay at addr — STARTTLS when the relay offers it — authenticating
// with PLAIN as username when password is non-empty. It borrows password for
// the sender's life and never turns it into a string; the caller wipes it
// after the send. Used for mail other than alerts, such as ACME email
// challenges (P15).
func NewRelaySender(addr, username string, password []byte) Sender {
	s := &realSender{addr: addr}
	if len(password) > 0 {
		s.auth = &bytePlainAuth{username: username, password: password, host: hostOf(addr)}
	}
	return s
}

// bytePlainAuth is SMTP PLAIN (RFC 4616) over a byte-held password, with
// net/smtp's PlainAuth rule: credentials go only over TLS or to localhost.
type bytePlainAuth struct {
	username string
	password []byte
	host     string
}

func (a *bytePlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("email: refusing to send the SMTP password over an unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("email: wrong SMTP host name")
	}
	resp := make([]byte, 0, len(a.username)+len(a.password)+2)
	resp = append(resp, 0)
	resp = append(resp, a.username...)
	resp = append(resp, 0)
	resp = append(resp, a.password...)
	return "PLAIN", resp, nil
}

func (a *bytePlainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("email: unexpected SMTP PLAIN challenge")
	}
	return nil, nil
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}
