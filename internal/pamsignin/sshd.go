// SPDX-License-Identifier: BUSL-1.1

package pamsignin

import (
	"bufio"
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sshdAccepted is the message sshd logs for every successful sign-in, from
// OpenSSH's sshd and, since 9.8, its per-session sshd-session.
var sshdAccepted = regexp.MustCompile(`\bsshd(?:-session)?\[(\d+)\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: \S+)?(?:: (.*))?$`)

// sshdCertificate is the certificate an sshd sign-in names: its key ID and
// serial (a gateway session's certificate names the session).
var sshdCertificate = regexp.MustCompile(`\bID (.*?) \(serial (\d+)\)`)

// Timestamp layouts a host's log lines begin with: RFC 3339 (rsyslog's
// default file format), journald's short-iso-precise (an offset without a
// colon) and traditional syslog (no year, the host's local time).
var (
	rfc3339Prefix     = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) `)
	traditionalPrefix = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) `)
)

// ErrIncomplete is a collection whose output did not reach its end marker.
var ErrIncomplete = errors.New("pamsignin: the host's sign-in report was cut short")

// ParseSSHReport reads the framed report the Linux and Unix collector's
// script prints — "=== tz <+hhmm>", then journal and log-file sections of
// sshd lines, then "=== end" — and returns the sign-ins of the named
// accounts at or after since. A line it cannot date is skipped.
func ParseSSHReport(raw []byte, now time.Time, accounts []string, since time.Time) ([]SignIn, error) {
	managed := map[string]bool{}
	for _, a := range accounts {
		managed[a] = true
	}
	loc := time.UTC
	ended := false
	var out []SignIn
	lines := bufio.NewScanner(bytes.NewReader(raw))
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		line := strings.TrimRight(lines.Text(), "\r")
		if rest, ok := strings.CutPrefix(line, "=== "); ok {
			switch {
			case rest == "end":
				ended = true
			case strings.HasPrefix(rest, "tz "):
				if zone, err := time.Parse("-0700", strings.TrimSpace(strings.TrimPrefix(rest, "tz "))); err == nil {
					_, offset := zone.Zone()
					loc = time.FixedZone("host", offset)
				}
			}
			continue
		}
		s, ok := parseSSHDLine(line, now, loc)
		if !ok || !managed[s.Account] || s.At.Before(since) {
			continue
		}
		out = append(out, s)
	}
	if !ended {
		return nil, ErrIncomplete
	}
	return Dedupe(out), nil
}

// parseSSHDLine reads one sshd "Accepted" line.
func parseSSHDLine(line string, now time.Time, loc *time.Location) (SignIn, bool) {
	m := sshdAccepted.FindStringSubmatch(line)
	if m == nil {
		return SignIn{}, false
	}
	at, ok := lineTime(line, now, loc)
	if !ok {
		return SignIn{}, false
	}
	s := SignIn{Account: m[3], At: at.UTC(), Source: m[4], Method: m[2], Ref: "sshd[" + m[1] + "]:" + m[5]}
	if cert := sshdCertificate.FindStringSubmatch(m[6]); cert != nil {
		s.KeyID = cert[1] + " (serial " + cert[2] + ")"
		s.Method += "-cert"
	}
	return s, true
}

// lineTime dates a log line. A traditional syslog stamp has no year: it is
// this year's, or last year's when that would put it more than a day ahead
// of now.
func lineTime(line string, now time.Time, loc *time.Location) (time.Time, bool) {
	if m := rfc3339Prefix.FindStringSubmatch(line); m != nil {
		stamp := m[1]
		if n := len(stamp); n > 5 && (stamp[n-5] == '+' || stamp[n-5] == '-') {
			stamp = stamp[:n-2] + ":" + stamp[n-2:]
		}
		at, err := time.Parse(time.RFC3339Nano, stamp)
		return at, err == nil
	}
	if m := traditionalPrefix.FindStringSubmatch(line); m != nil {
		at, err := time.ParseInLocation("Jan _2 15:04:05 2006", m[1]+" "+strconv.Itoa(now.In(loc).Year()), loc)
		if err != nil {
			return time.Time{}, false
		}
		if at.After(now.Add(24 * time.Hour)) {
			at = at.AddDate(-1, 0, 0)
		}
		return at, true
	}
	return time.Time{}, false
}

// ParseWindowsReport reads the Windows collector's report — "=== windows",
// lines of time|domain|account|logon type|address|logon id from the Security
// log's logon events (4624), then "=== end" — and returns the sign-ins of
// the named accounts at or after since.
func ParseWindowsReport(raw []byte, accounts []string, since time.Time) ([]SignIn, error) {
	managed := map[string]bool{}
	for _, a := range accounts {
		managed[strings.ToLower(a)] = true
	}
	ended := false
	var out []SignIn
	lines := bufio.NewScanner(bytes.NewReader(raw))
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		switch {
		case line == "=== end":
			ended = true
			continue
		case line == "" || strings.HasPrefix(line, "=== "):
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 6 || !managed[strings.ToLower(fields[2])] {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, fields[0])
		if err != nil || at.Before(since) {
			continue
		}
		source := fields[4]
		if source == "-" || source == "::1" || source == "127.0.0.1" {
			// A logon with no network address (or a local one) names none.
			source = ""
		}
		out = append(out, SignIn{Account: fields[2], At: at.UTC(), Source: source, Method: "logon type " + fields[3], Ref: "logon " + fields[5]})
	}
	if !ended {
		return nil, ErrIncomplete
	}
	return Dedupe(out), nil
}
