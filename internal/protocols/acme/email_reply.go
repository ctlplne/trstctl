// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
)

// MaxEmailReplyBytes bounds a reply message the intake reads.
const MaxEmailReplyBytes = 256 << 10

// maxEmailReplyParts bounds the parts of a multipart/alternative reply.
const maxEmailReplyParts = 8

// ErrEmailReplyMalformed: the message is not an RFC 8823 §3.2 reply.
var ErrEmailReplyMalformed = errors.New("acme: the message is not an RFC 8823 reply")

// ParsedEmailReply is what a received reply says before its DKIM signature
// is checked: the From mailbox, the token-part1 after "ACME:" in its Subject
// and the response from its ACME RESPONSE block.
type ParsedEmailReply struct {
	From         string
	SubjectToken string
	Response     string
}

// ParseEmailReply reads an RFC 8823 §3.2 reply: exactly one From mailbox; a
// Subject whose "ACME:" label — after any reply prefix, RFC 2047-decoded —
// carries token-part1; no List-* fields (a mailing list cannot answer for a
// mailbox); and a text/plain body, or the text/plain part of a
// multipart/alternative body, holding the ACME RESPONSE block.
func ParseEmailReply(raw []byte) (ParsedEmailReply, error) {
	if len(raw) > MaxEmailReplyBytes {
		return ParsedEmailReply{}, fmt.Errorf("%w: larger than %d bytes", ErrEmailReplyMalformed, MaxEmailReplyBytes)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ParsedEmailReply{}, fmt.Errorf("%w: %v", ErrEmailReplyMalformed, err)
	}
	for name := range msg.Header {
		if strings.HasPrefix(strings.ToLower(name), "list-") {
			return ParsedEmailReply{}, fmt.Errorf("%w: a mailing-list message (%s)", ErrEmailReplyMalformed, name)
		}
	}
	if len(msg.Header["From"]) != 1 {
		return ParsedEmailReply{}, fmt.Errorf("%w: one From field is required", ErrEmailReplyMalformed)
	}
	from, err := mail.ParseAddressList(msg.Header.Get("From"))
	if err != nil || len(from) != 1 {
		return ParsedEmailReply{}, fmt.Errorf("%w: From must name one mailbox", ErrEmailReplyMalformed)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		return ParsedEmailReply{}, fmt.Errorf("%w: the Subject does not decode", ErrEmailReplyMalformed)
	}
	_, after, ok := strings.Cut(subject, "ACME:")
	token := canonicalEmailToken(after)
	if !ok || token == "" {
		return ParsedEmailReply{}, fmt.Errorf("%w: the Subject has no ACME: token", ErrEmailReplyMalformed)
	}
	text, err := emailReplyText(msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Body)
	if err != nil {
		return ParsedEmailReply{}, err
	}
	response, ok := ExtractEmailResponse(text)
	if !ok {
		return ParsedEmailReply{}, fmt.Errorf("%w: no ACME RESPONSE block", ErrEmailReplyMalformed)
	}
	// The mail parser returns a quoted local part unquoted; quote it again
	// the canonical way so the address compares with the order's (P15-L4).
	at := strings.LastIndexByte(from[0].Address, '@')
	if at <= 0 {
		return ParsedEmailReply{}, fmt.Errorf("%w: From must name one mailbox", ErrEmailReplyMalformed)
	}
	local, err := CanonicalLocalPartContent(from[0].Address[:at])
	if err != nil {
		return ParsedEmailReply{}, fmt.Errorf("%w: the From mailbox: %v", ErrEmailReplyMalformed, err)
	}
	return ParsedEmailReply{From: local + "@" + from[0].Address[at+1:], SubjectToken: token, Response: response}, nil
}

// emailReplyText returns the reply's text/plain content, transfer-decoded.
func emailReplyText(contentType, transferEncoding string, body io.Reader) (string, error) {
	mediaType, params := "text/plain", map[string]string{}
	if strings.TrimSpace(contentType) != "" {
		var err error
		if mediaType, params, err = mime.ParseMediaType(contentType); err != nil {
			return "", fmt.Errorf("%w: Content-Type does not parse", ErrEmailReplyMalformed)
		}
	}
	switch mediaType {
	case "text/plain":
		return decodeTransfer(transferEncoding, body)
	case "multipart/alternative":
		reader := multipart.NewReader(body, params["boundary"])
		for i := 0; i < maxEmailReplyParts; i++ {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			partType := part.Header.Get("Content-Type")
			if partType == "" {
				partType = "text/plain"
			}
			if t, _, err := mime.ParseMediaType(partType); err == nil && t == "text/plain" {
				return decodeTransfer(part.Header.Get("Content-Transfer-Encoding"), part)
			}
		}
		return "", fmt.Errorf("%w: no text/plain alternative", ErrEmailReplyMalformed)
	default:
		return "", fmt.Errorf("%w: a reply is text/plain or multipart/alternative, not %s", ErrEmailReplyMalformed, mediaType)
	}
}

func decodeTransfer(encoding string, body io.Reader) (string, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit":
		r = body
	case "quoted-printable":
		r = quotedprintable.NewReader(body)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, &newlineStripper{r: body})
	default:
		return "", fmt.Errorf("%w: transfer encoding %q", ErrEmailReplyMalformed, encoding)
	}
	text, err := io.ReadAll(io.LimitReader(r, MaxEmailReplyBytes+1))
	if err != nil || len(text) > MaxEmailReplyBytes {
		return "", fmt.Errorf("%w: the body does not decode", ErrEmailReplyMalformed)
	}
	return string(text), nil
}

// newlineStripper drops CR and LF so base64 lines decode as one stream.
type newlineStripper struct{ r io.Reader }

func (n *newlineStripper) Read(p []byte) (int, error) {
	count, err := n.r.Read(p)
	kept := p[:0]
	for _, b := range p[:count] {
		if b != '\r' && b != '\n' {
			kept = append(kept, b)
		}
	}
	return len(kept), err
}
