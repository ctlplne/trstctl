// SPDX-License-Identifier: BUSL-1.1

// Package pamsignin is bypass detection's core (A274): the sign-in records a
// collector reads from a target — metadata only, never a credential or what a
// session did — and the windows in which trstctl itself, or a person it let
// in, signed in as a managed account: a gateway session, a revealed
// check-out, or the control plane's own rotation and health checks. A
// sign-in no window explains is a bypass: someone used the account's
// credential outside trstctl.
package pamsignin

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// SignIn is one sign-in a target recorded for a managed account.
type SignIn struct {
	// Account is the account that signed in, as the target names it.
	Account string `json:"account"`
	// At is when the target recorded the sign-in; Earliest, when set, is the
	// earliest it can have happened (a database session first seen at a
	// collection: some time since the previous one).
	At       time.Time `json:"at"`
	Earliest time.Time `json:"earliest,omitempty"`
	// Source is the client address the target recorded, when it records one.
	Source string `json:"source,omitempty"`
	// Method is how it signed in: password, publickey, keyboard-interactive,
	// a certificate, a database connection, a Windows logon type.
	Method string `json:"method,omitempty"`
	// KeyID is an SSH certificate's key ID and serial, when the target logs
	// one (a gateway session's certificate names its session).
	KeyID string `json:"key_id,omitempty"`
	// Ref identifies the record on the target (a process or connection id),
	// so the same sign-in read twice is one.
	Ref string `json:"ref,omitempty"`
}

// From is the earliest the sign-in can have happened.
func (s SignIn) From() time.Time {
	if s.Earliest.IsZero() || s.Earliest.After(s.At) {
		return s.At
	}
	return s.Earliest
}

// Window kinds: why trstctl expected a sign-in as an account.
const (
	WindowGatewaySession = "gateway_session"
	WindowSession        = "session"
	WindowCheckout       = "checkout"
	WindowRotation       = "rotation_check"
	WindowHealth         = "health_check"
)

// Window is a span in which a sign-in as Account was trstctl's own or one it
// let in.
type Window struct {
	Account string    `json:"account"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Kind    string    `json:"kind"`
	Ref     string    `json:"ref,omitempty"`
}

// DefaultSlack is how far a sign-in's recorded time may sit outside a window
// and still be explained by it: the clock skew and logging lag between the
// control plane, the gateway and the target. It is kept short — a sign-in
// within it of trstctl's own use of the account is attributed to trstctl —
// so targets keep their clocks synchronized.
const DefaultSlack = 30 * time.Second

// Matched is a sign-in and the window that explains it, if any.
type Matched struct {
	SignIn SignIn  `json:"sign_in"`
	Window *Window `json:"window,omitempty"`
}

// Match explains each sign-in by a window of the same account that overlaps
// it (within slack); a sign-in with none is a bypass. Accounts compare
// case-insensitively (a database or Windows may fold case).
func Match(signIns []SignIn, windows []Window, slack time.Duration) []Matched {
	byAccount := map[string][]Window{}
	for _, w := range windows {
		key := strings.ToLower(w.Account)
		byAccount[key] = append(byAccount[key], w)
	}
	out := make([]Matched, 0, len(signIns))
	for _, s := range signIns {
		m := Matched{SignIn: s}
		from, to := s.From().Add(-slack), s.At.Add(slack)
		for i, w := range byAccount[strings.ToLower(s.Account)] {
			if !w.To.Before(from) && !w.From.After(to) {
				explained := byAccount[strings.ToLower(s.Account)][i]
				m.Window = &explained
				break
			}
		}
		out = append(out, m)
	}
	return out
}

// Bypasses are the sign-ins no window explains.
func Bypasses(matched []Matched) []SignIn {
	var out []SignIn
	for _, m := range matched {
		if m.Window == nil {
			out = append(out, m.SignIn)
		}
	}
	return out
}

// Dedupe keeps one of each sign-in read twice (a host whose journal and log
// file both carry it): same account, second, source and reference.
func Dedupe(signIns []SignIn) []SignIn {
	seen := map[string]bool{}
	out := make([]SignIn, 0, len(signIns))
	for _, s := range signIns {
		key := identity(s)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Fingerprint is a sign-in's stable identity on a target: a finding raised
// for it is refreshed, not repeated, when a later collection reads it again.
func Fingerprint(target string, s SignIn) string {
	return "sha256:" + crypto.SHA256Hex([]byte(target+"\x00"+identity(s)))
}

// identity is what makes two reads of a sign-in the same one: the account,
// when, the client address and the target-side reference. A sign-in dated
// only when a collection first saw it (Earliest set: a MySQL connection,
// whose reference names the connection and the server's start) is the same
// one whenever it is seen, so its moving date is left out.
func identity(s SignIn) string {
	when := s.At.UTC().Truncate(time.Second).Format(time.RFC3339)
	if !s.Earliest.IsZero() && s.Ref != "" {
		when = "first-seen"
	}
	return strings.ToLower(s.Account) + "\x00" + when + "\x00" + s.Source + "\x00" + s.Ref
}

// accountName is an account name a collector may put in a filter it sends
// to a target: letters, digits and . _ - @ \ (a Windows domain\user or a
// database role), up to 128 characters.
var accountName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@\\-]{0,127}$`)

// ValidAccounts checks the managed account names a collector filters by.
func ValidAccounts(accounts []string) error {
	if len(accounts) == 0 || len(accounts) > 256 {
		return errors.New("pamsignin: a collection names 1-256 managed accounts")
	}
	for _, a := range accounts {
		if !accountName.MatchString(a) {
			return errors.New("pamsignin: a managed account name has characters a collector cannot filter by")
		}
	}
	return nil
}
