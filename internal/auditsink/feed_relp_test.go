// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"bytes"
	"strconv"
	"testing"
	"time"
)

// P5-L3: a syslog feed's endpoint picks its transport. relp+tls://host:port
// is RELP over TLS and must name its port; plain RELP is not offered.
func TestRELPEndpointFormsP5L3(t *testing.T) {
	for endpoint, want := range map[string]SyslogTarget{
		"relp+tls://logs.example.test:2514":  {Transport: SyslogRELP, Addr: "logs.example.test:2514", ServerName: "logs.example.test"},
		"relp+tls://[2001:db8::7]:20514/":    {Transport: SyslogRELP, Addr: "[2001:db8::7]:20514", ServerName: "2001:db8::7"},
		"syslog+tls://logs.example.test":     {Transport: SyslogTLS, Addr: "logs.example.test:6514", ServerName: "logs.example.test"},
		" relp+tls://logs.example.test:2514": {Transport: SyslogRELP, Addr: "logs.example.test:2514", ServerName: "logs.example.test"},
	} {
		if got, err := ParseSyslogEndpoint(endpoint); err != nil || got != want {
			t.Fatalf("%q → %+v, %v; want %+v", endpoint, got, err, want)
		}
	}
	for _, bad := range []string{
		"relp+tls://logs.example.test", "relp://logs.example.test:2514", "relp+tcp://logs.example.test:2514",
		"relp+tls://u:p@logs.example.test:2514", "relp+tls://logs.example.test:2514/x", "relp+tls://logs.example.test:2514?q=1",
		"relp+tls://logs.example.test:70000", "relp+tls://:2514",
	} {
		if _, err := ParseSyslogEndpoint(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// P5-L3: the framed syslog batch splits back into exactly the messages it
// was written from, sharing its bytes; a frame whose count does not match is
// refused.
func TestSyslogMessagesSplitsTheFramedBatchP5L3(t *testing.T) {
	records := []collectorRecord{{ID: "a", Sequence: 1, Type: "x"}, {ID: "b", Sequence: 2, Type: "y"}}
	when := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var framed bytes.Buffer
	if err := writeSyslogBatch(&framed, records, []time.Time{when, when}); err != nil {
		t.Fatal(err)
	}
	messages, err := SyslogMessages(framed.Bytes())
	if err != nil || len(messages) != 2 {
		t.Fatalf("SyslogMessages = %d, %v", len(messages), err)
	}
	var again bytes.Buffer
	for _, msg := range messages {
		if !bytes.HasPrefix(msg, []byte("<110>1 2026-11-14T12:00:00.000000Z - trstctl - trstctl-audit - {")) {
			t.Fatalf("message = %q", msg)
		}
		again.WriteString(strconv.Itoa(len(msg)) + " ")
		again.Write(msg)
	}
	if !bytes.Equal(again.Bytes(), framed.Bytes()) {
		t.Fatal("the messages do not frame back into the batch")
	}
	for _, bad := range []string{"", "5 abc", "x abc", "3abc", "0 ", "3 abc5 abcd", "1234567890 a"} {
		if _, err := SyslogMessages([]byte(bad)); err == nil {
			t.Fatalf("%q split", bad)
		}
	}
}
