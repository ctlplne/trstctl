// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"errors"
	"strings"
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

const p15ReplyBlock = "-----BEGIN ACME RESPONSE-----\r\nLoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowy\r\njxAjEuX0=\r\n-----END ACME RESPONSE-----\r\n"

func p15Reply(headers, body string) []byte {
	return []byte(headers + "\r\n" + body)
}

// An RFC 8823 §3.2 reply: one From mailbox, the token after "ACME:" in the
// Subject (any reply prefix, RFC 2047 decoded), no List-* fields, and the
// response in a text/plain body or text/plain alternative.
func TestParseEmailReplyP15(t *testing.T) {
	want := acmesrv.ParsedEmailReply{From: "alice@p15.test", SubjectToken: "LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME", Response: "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"} // #nosec G101 -- RFC 8823 test token and digest, not a credential (CWE-798)
	for name, raw := range map[string][]byte{
		"plain":                           p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME\r\n", "Thanks\r\n"+p15ReplyBlock),
		"display name and folded subject": p15Reply("From: Alice Example <alice@p15.test>\r\nSubject: Re: ACME:\r\n LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME\r\nContent-Type: text/plain; charset=US-ASCII\r\n", p15ReplyBlock),
		"encoded subject":                 p15Reply("From: alice@p15.test\r\nSubject: =?UTF-8?Q?Re:_ACME:_LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME?=\r\n", p15ReplyBlock),
		"quoted-printable alternative": p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b1\r\n",
			"--b1\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n--b1\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+strings.ReplaceAll(p15ReplyBlock, "=\r\n", "=3D\r\n")+"--b1--\r\n"),
		"base64 body": p15Reply("From: alice@p15.test\r\nSubject: ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME\r\nContent-Transfer-Encoding: base64\r\n",
			"LS0tLS1CRUdJTiBBQ01FIFJFU1BPTlNFLS0tLS0NCkxvcVhjWVY4cTVPTmJKUXhibVI3U0NUTm8zdGlB\r\nWERmb3d5anhBakV1WDA9DQotLS0tLUVORCBBQ01FIFJFU1BPTlNFLS0tLS0NCg==\r\n"),
	} {
		got, err := acmesrv.ParseEmailReply(raw)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	for name, raw := range map[string][]byte{
		"a mailing list":      p15Reply("From: alice@p15.test\r\nList-Id: <team.p15.test>\r\nSubject: Re: ACME: abc\r\n", p15ReplyBlock),
		"two From fields":     p15Reply("From: alice@p15.test\r\nFrom: bob@p15.test\r\nSubject: Re: ACME: abc\r\n", p15ReplyBlock),
		"two mailboxes":       p15Reply("From: alice@p15.test, bob@p15.test\r\nSubject: Re: ACME: abc\r\n", p15ReplyBlock),
		"no ACME token":       p15Reply("From: alice@p15.test\r\nSubject: Re: hello\r\n", p15ReplyBlock),
		"no response block":   p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: abc\r\n", "thanks\r\n"),
		"html only":           p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: abc\r\nContent-Type: text/html\r\n", p15ReplyBlock),
		"unknown encoding":    p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: abc\r\nContent-Transfer-Encoding: x-uuencode\r\n", p15ReplyBlock),
		"oversized":           append(p15Reply("From: alice@p15.test\r\nSubject: Re: ACME: abc\r\n", p15ReplyBlock), make([]byte, acmesrv.MaxEmailReplyBytes)...),
		"no header separator": []byte("From: alice@p15.test"),
	} {
		if got, err := acmesrv.ParseEmailReply(raw); !errors.Is(err, acmesrv.ErrEmailReplyMalformed) {
			t.Fatalf("%s: accepted %+v (%v)", name, got, err)
		}
	}
}
