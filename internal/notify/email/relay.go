// SPDX-License-Identifier: BUSL-1.1

package email

// NewRelaySender returns a Sender that delivers a rendered message through
// the SMTP relay at addr — STARTTLS when the relay offers it — authenticating
// with PLAIN as username when password is non-empty. It borrows password for
// the sender's life and never turns it into a string; the caller wipes it
// after the send, and the PLAIN line built from it is wiped as soon as it is
// written (P15-L5). Used for mail other than alerts, such as ACME email
// challenges (P15).
func NewRelaySender(addr, username string, password []byte) Sender {
	s := &realSender{addr: addr}
	if len(password) > 0 {
		s.plain = &plainCredentials{username: username, password: password}
	}
	return s
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}
