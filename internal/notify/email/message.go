// SPDX-License-Identifier: MPL-2.0

package email

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/notify"
)

// messageSubject keeps triage text bounded without dropping any detail from the
// body. Serial, owner, deadline and diagnostic prose belong in the full message.
func messageSubject(alert notify.Alert) string {
	subject := notify.FormatMessage(notify.Alert{Kind: alert.Kind, Subject: alert.Subject})
	subject = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, subject)
	subject = strings.Join(strings.Fields(subject), " ")
	runes := []rune(subject)
	if len(runes) > 160 {
		subject = string(runes[:159]) + "…"
	}
	return subject
}

func buildMessage(from string, to []string, subject, body, messageID string, date time.Time) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	b.WriteString("To: ")
	for i, recipient := range to {
		if i > 0 {
			b.WriteString(",\r\n ")
		}
		b.WriteString(headerSafe(recipient))
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "Date: %s\r\nMessage-ID: %s\r\n", date.Format(time.RFC1123Z), messageID)
	b.WriteString("Subject: ")
	b.WriteString(encodeSubject(subject))
	b.WriteString("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	writer := quotedprintable.NewWriter(&b)
	if _, err := writer.Write([]byte(body)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Encoded words preserve long tokens and Unicode without splitting a code point.
// 39 source bytes produce at most 64 wire bytes. Including "Subject: ", the
// first line is at most 73 bytes: within RFC 2047's 76-byte encoded-header line
// limit and its separate 75-byte encoded-word limit.
func encodeSubject(subject string) string {
	if len(subject) <= 69 && !strings.Contains(subject, "=?") && strings.IndexFunc(subject, func(r rune) bool { return r > unicode.MaxASCII }) == -1 {
		return subject
	}
	var words []string
	for len(subject) > 0 {
		n := min(39, len(subject))
		for n < len(subject) && !utf8.RuneStart(subject[n]) {
			n--
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte(subject[:n]))+"?=")
		subject = subject[n:]
	}
	return strings.Join(words, "\r\n ")
}
