// SPDX-License-Identifier: BUSL-1.1

package email_test

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/email"
)

func readNotificationMail(t *testing.T, raw string) (*mail.Message, string, string) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	reader := m.Body
	if m.Header.Get("Content-Transfer-Encoding") == "quoted-printable" {
		reader = quotedprintable.NewReader(reader)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return m, subject, strings.ReplaceAll(string(body), "\r\n", "\n")
}

func TestMailHeadersAndUnicodeBody(t *testing.T) {
	for _, subject := range []string{
		"mail.partner-lab.example.com", strings.Repeat("long-host", 1000),
		strings.Repeat("サービス café 😀 ", 40), "host\r\nBcc: injected@example.test\x00", "=?UTF-8?B?4piD?=",
	} {
		t.Run(subject[:min(len(subject), 20)], func(t *testing.T) {
			fake := &fakeSender{}
			alert := notify.Alert{Kind: notify.KindRenewalFailed, TenantID: "tenant-1", Subject: subject,
				Serial: "exact-certificate", Detail: "Failed host job 344, attempt 1.\nOpen /operations?run=exact-run\n.dot line\n日本語 café 😀", OwnerName: "Platform SRE"}
			before := time.Now().UTC().Add(-time.Second)
			if err := email.New("unused:25", "alerts@example.test", []string{"oncall@example.test"}, email.WithSender(fake)).Notify(t.Context(), alert); err != nil {
				t.Fatal(err)
			}
			raw := fake.Message()
			m, gotSubject, body := readNotificationMail(t, raw)
			date, err := m.Header.Date()
			if err != nil || date.Before(before) || date.After(time.Now().UTC()) {
				t.Errorf("valid message generation Date missing: %q %v", m.Header.Get("Date"), err)
			}
			if !regexp.MustCompile(`^<[A-Za-z0-9_-]+@trstctl\.invalid>$`).MatchString(m.Header.Get("Message-ID")) {
				t.Errorf("missing or invalid Message-ID: %q", m.Header.Get("Message-ID"))
			}
			if !strings.HasPrefix(gotSubject, "Certificate renewal attempt failed: ") || utf8.RuneCountInString(gotSubject) > 160 || strings.ContainsAny(gotSubject, "\r\n\x00") {
				t.Errorf("unsafe or unbounded subject: %q", gotSubject)
			}
			if m.Header.Get("Bcc") != "" || strings.Contains(gotSubject, "exact-certificate") || strings.Contains(gotSubject, "Failed host job") {
				t.Error("injected or diagnostic header content")
			}
			if subject == "=?UTF-8?B?4piD?=" && gotSubject != "Certificate renewal attempt failed: "+subject {
				t.Error("literal encoded-word text was reinterpreted as a mail header")
			}
			if body != strings.ReplaceAll(notify.FormatMessage(alert), "\r\n", "\n") {
				t.Errorf("decoded body changed full alert context: %q", body)
			}
			media, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
			if err != nil || media != "text/plain" || params["charset"] != "utf-8" || m.Header.Get("MIME-Version") != "1.0" || m.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
				t.Errorf("missing UTF-8 MIME contract: %v", m.Header)
			}
			for _, line := range strings.Split(raw, "\r\n") {
				if strings.Contains(line, "=?UTF-8?B?") && len(line) > 76 {
					t.Fatalf("RFC 2047 encoded header line exceeds 76 bytes: %d", len(line))
				}
				if len(line) > 78 || strings.ContainsAny(line, "\r\n") {
					t.Fatalf("non-CRLF or oversized wire line (%d bytes): %.90q", len(line), line)
				}
			}
		})
	}
}

func TestMailMessageIdentityBindsOutboxAndSurvivesRetry(t *testing.T) {
	fake := &fakeSender{err: errors.New("acceptance acknowledgement lost")}
	newDispatcher := func(from, to string) *notify.Dispatcher {
		return notify.NewDispatcher(email.New("unused:25", from, []string{to}, email.WithSender(fake)))
	}
	payload, err := json.Marshal(notify.Alert{Kind: notify.KindRenewalFailed, TenantID: "tenant-1", Subject: "same-host", Detail: "same diagnosis"})
	if err != nil {
		t.Fatal(err)
	}
	message := notify.DeliveryMessage{TenantID: "tenant-1", Destination: notify.DestinationRenewalFailure, IdempotencyKey: "command-1", Payload: payload, OutboxID: 1, Attempts: 1}
	d := newDispatcher("alerts@example.test", "oncall@example.test")
	if err := d.DispatchMessage(t.Context(), message); err == nil {
		t.Fatal("lost acknowledgement must remain a delivery failure")
	}
	first, _, _ := readNotificationMail(t, fake.Message())
	id := first.Header.Get("Message-ID")
	if id == "" {
		t.Fatal("first submitted message has no Message-ID")
	}
	fake.err = nil
	message.Attempts++
	message.OutboxID = 99 // A projection rebuild may allocate a new physical row.
	// Reconstructing the channel simulates a process restart, not an in-memory cache.
	d = newDispatcher("alerts@example.test", "oncall@example.test")
	if err := d.DispatchMessage(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	retry, _, _ := readNotificationMail(t, fake.Message())
	if retry.Header.Get("Message-ID") != id {
		t.Fatal("retry/restart changed durable message identity")
	}
	seen := map[string]bool{id: true}
	for _, change := range []string{"command", "tenant", "destination", "payload", "from", "recipient"} {
		t.Run(change, func(t *testing.T) {
			next := message
			dispatcher := d
			switch change {
			case "command":
				next.IdempotencyKey = "command-2"
			case "tenant":
				next.TenantID = "tenant-2"
				next.Payload = []byte(strings.ReplaceAll(string(payload), "tenant-1", "tenant-2"))
			case "destination":
				next.Destination = notify.DestinationTest
			case "payload":
				next.Payload = []byte(strings.ReplaceAll(string(payload), "same diagnosis", "changed diagnosis"))
			case "from":
				dispatcher = newDispatcher("another@example.test", "oncall@example.test")
			case "recipient":
				dispatcher = newDispatcher("alerts@example.test", "another@example.test")
			}
			if err := dispatcher.DispatchMessage(t.Context(), next); err != nil {
				t.Fatal(err)
			}
			m, _, _ := readNotificationMail(t, fake.Message())
			got := m.Header.Get("Message-ID")
			if got == "" || seen[got] {
				t.Fatalf("different %s collapsed with another message: %q", change, got)
			}
			seen[got] = true
		})
	}
}

func TestDirectMailIdentityAndMissingDeliveryBinding(t *testing.T) {
	fake := &fakeSender{}
	channel := email.New("unused:25", "alerts@example.test", []string{"oncall@example.test"}, email.WithSender(fake))
	alert := notify.Alert{TenantID: "tenant-1", OperationID: "operation-1", Subject: "direct caller"}
	var first string
	for i := range 3 {
		if i == 2 {
			alert.OperationID = "operation-2"
		}
		if err := channel.Notify(t.Context(), alert); err != nil {
			t.Fatal(err)
		}
		message, _, _ := readNotificationMail(t, fake.Message())
		id := message.Header.Get("Message-ID")
		if i == 0 {
			first = id
		} else if (id == first) != (i == 1) {
			t.Fatal("direct calls must retain retry identity and distinguish operation IDs")
		}
	}
	if err := channel.NotifyDelivery(t.Context(), alert, notify.NotificationDeliveryReceipt{}); err == nil || fake.Calls() != 3 {
		t.Fatal("missing dispatch binding must fail before SMTP submission")
	}
}
