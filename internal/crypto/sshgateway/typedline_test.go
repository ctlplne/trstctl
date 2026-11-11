// SPDX-License-Identifier: BUSL-1.1

package sshgateway

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

type judgedLine struct {
	line     string
	readable bool
}

// pumpFor runs pumpTypedLines over input with a check that refuses any line
// whose first word is "write" or "wr" (and any unreadable line), and returns
// what reached the device, what the client was told, the lines judged and
// how many were refused.
func pumpFor(t *testing.T, input string) (string, string, []judgedLine, int) {
	t.Helper()
	var device, client bytes.Buffer
	var judged []judgedLine
	refused := 0
	check := func(_ context.Context, line []byte, readable bool) bool {
		judged = append(judged, judgedLine{string(line), readable})
		fields := strings.Fields(string(line))
		return readable && (len(fields) == 0 || (fields[0] != "write" && fields[0] != "wr"))
	}
	if err := pumpTypedLines(context.Background(), strings.NewReader(input), &device, &client, check, func() { refused++ }); err != nil {
		t.Fatal(err)
	}
	return device.String(), client.String(), judged, refused
}

// A270-L1: every key reaches the device as typed; an allowed line's Enter is
// forwarded, and a refused line is killed (Ctrl-U) and submitted empty, with
// the client told.
func TestTypedLinesHoldOnlyARefusedLinesSubmission(t *testing.T) {
	device, client, judged, refused := pumpFor(t, "show version\rwr mem\rterminal length 0\r")
	if want := "show version\rwr mem\x15\rterminal length 0\r"; device != want {
		t.Fatalf("the device received %q, want %q", device, want)
	}
	if refused != 1 || !strings.Contains(client, "refused this line") {
		t.Fatalf("refused %d, client told %q", refused, client)
	}
	if len(judged) != 3 || judged[1] != (judgedLine{"wr mem", true}) {
		t.Fatalf("judged %+v", judged)
	}
}

// The gateway's copy follows the device's editing keys, so the line judged is
// the line the device would run.
func TestTypedLinesFollowTheDevicesEditingKeys(t *testing.T) {
	for _, tc := range []struct {
		name, input, judged string
	}{
		{"backspace", "show versioX\x7fn\r", "show version"},
		{"ctrl-h", "show versioX\x08n\r", "show version"},
		{"kill line", "write mem\x15show version\r", "show version"},
		{"ctrl-c abandons the line", "write mem\x03show clock\r", "show clock"},
		{"erase word", "show write\x17version\r", "show version"},
		{"erase word over trailing spaces", "write me  \x17\x17show run\r", "show run"},
		{"help is not part of the line", "wr?\r", "wr"},
		{"a multi-byte rune erases whole", "show caf\xc3\xa9\x7fe\r", "show cafe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, judged, _ := pumpFor(t, tc.input)
			if len(judged) != 1 || judged[0] != (judgedLine{tc.judged, true}) {
				t.Fatalf("judged %+v, want %q readable", judged, tc.judged)
			}
		})
	}
}

// Keys the gateway cannot follow make the line unreadable, and an unreadable
// line is refused, however it looks; killing the line makes the next one
// readable again.
func TestTypedLinesTheGatewayCannotFollowAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"history recall", "\x1b[A\r"},
		{"completion", "wri\tmem\r"},
		{"cursor movement", "show version\x01wr \r"},
		{"a line longer than a command", strings.Repeat("a", MaxExecCommandBytes+1) + "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, _, judged, refused := pumpFor(t, tc.input)
			if len(judged) != 1 || judged[0].readable || refused != 1 || !strings.HasSuffix(device, "\x15\r") {
				t.Fatalf("judged %+v, refused %d, device ends %q", judged, refused, device[max(0, len(device)-8):])
			}
		})
	}
	_, _, judged, refused := pumpFor(t, "\x1b[A\x15show version\r")
	if len(judged) != 1 || judged[0] != (judgedLine{"show version", true}) || refused != 0 {
		t.Fatalf("after a kill: judged %+v, refused %d", judged, refused)
	}
}

// Ctrl-Z runs the line on IOS-XE as it leaves configuration mode, so it
// submits the line like Enter; an empty Enter is forwarded unjudged.
func TestTypedLinesSubmitOnCtrlZAndPassEmptyLines(t *testing.T) {
	device, _, judged, refused := pumpFor(t, "\r\rwrite mem\x1a")
	if len(judged) != 1 || judged[0] != (judgedLine{"write mem", true}) || refused != 1 {
		t.Fatalf("judged %+v, refused %d", judged, refused)
	}
	if device != "\r\rwrite mem\x15\r" {
		t.Fatalf("the device received %q", device)
	}
}
