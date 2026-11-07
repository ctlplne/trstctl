// SPDX-License-Identifier: BUSL-1.1

package pamsignin

import (
	"strings"
	"testing"
	"time"
)

func TestParseSSHReportA274(t *testing.T) {
	now := time.Date(2026, 11, 7, 18, 30, 0, 0, time.UTC)
	report := strings.Join([]string{
		"=== tz +0000",
		"=== journal",
		"2026-11-07T18:00:01.123456+0000 lab sshd[101]: Accepted password for orders-single from 172.17.0.1 port 51234 ssh2",
		"2026-11-07T18:05:00.000001+0000 lab sshd-session[202]: Accepted publickey for orders-single from 10.0.0.9 port 40000 ssh2: ED25519-CERT SHA256:abc ID trstctl-pam-session-7 (serial 42) CA ED25519 SHA256:def",
		"=== file /var/log/auth.log",
		"2026-11-07T18:00:01.123456+00:00 lab sshd[101]: Accepted password for orders-single from 172.17.0.1 port 51234 ssh2",
		"2026-11-07T18:06:00+00:00 lab sshd[303]: Accepted password for someone-else from 172.17.0.1 port 1 ssh2",
		"2026-11-07T17:00:00+00:00 lab sshd[404]: Accepted password for orders-single from 172.17.0.1 port 2 ssh2",
		"Nov  7 18:10:00 lab sshd[505]: Accepted keyboard-interactive/pam for orders-single from 192.0.2.4 port 3 ssh2",
		"2026-11-07T18:11:00+00:00 lab sshd[606]: Failed password for orders-single from 192.0.2.4 port 4 ssh2",
		"=== end",
	}, "\n")
	got, err := ParseSSHReport([]byte(report), now, []string{"orders-single"}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("sign-ins: %+v", got)
	}
	if got[0].Method != "password" || got[0].Source != "172.17.0.1" || got[0].Ref != "sshd[101]:51234" {
		t.Fatalf("the password sign-in (read twice, kept once): %+v", got[0])
	}
	if got[1].Method != "publickey-cert" || got[1].KeyID != "trstctl-pam-session-7 (serial 42)" {
		t.Fatalf("the certificate sign-in: %+v", got[1])
	}
	if !got[2].At.Equal(time.Date(2026, 11, 7, 18, 10, 0, 0, time.UTC)) || got[2].Method != "keyboard-interactive/pam" {
		t.Fatalf("the traditional syslog line: %+v", got[2])
	}
	if _, err := ParseSSHReport([]byte("=== tz +0000\n=== journal\n"), now, []string{"orders-single"}, now); err != ErrIncomplete {
		t.Fatalf("a cut-short report: %v", err)
	}
	// A traditional stamp from late December read in early January is last year's.
	jan := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	got, err = ParseSSHReport([]byte("=== tz -0500\nDec 31 23:00:00 lab sshd[7]: Accepted password for orders-single from 192.0.2.4 port 9 ssh2\n=== end\n"),
		jan, []string{"orders-single"}, time.Time{})
	if err != nil || len(got) != 1 || !got[0].At.Equal(time.Date(2027, 1, 1, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("a year-end line in the host's zone: %+v %v", got, err)
	}
}

func TestMatchExplainsOnlyWindowsOfTheSameAccountA274(t *testing.T) {
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	signIns := []SignIn{
		{Account: "orders-single", At: at, Source: "203.0.113.5", Ref: "direct"},
		{Account: "orders-single", At: at.Add(10 * time.Minute), Ref: "through-the-gateway"},
		{Account: "ORDERS-SINGLE", At: at.Add(20*time.Minute + 20*time.Second), Ref: "just-after-a-rotation-check"},
		{Account: "orders-single", At: at.Add(20*time.Minute + 90*time.Second), Ref: "a-minute-after-a-rotation-check"},
		{Account: "app_reader", At: at.Add(31 * time.Minute), Earliest: at.Add(25 * time.Minute), Ref: "db-first-seen"},
		{Account: "orders-single", At: at.Add(40 * time.Minute), Ref: "another-accounts-window"},
	}
	windows := []Window{
		{Account: "orders-single", From: at.Add(9 * time.Minute), To: at.Add(12 * time.Minute), Kind: WindowGatewaySession, Ref: "session-1"},
		{Account: "orders-single", From: at.Add(20 * time.Minute), To: at.Add(20 * time.Minute), Kind: WindowRotation},
		{Account: "app_reader", From: at.Add(24 * time.Minute), To: at.Add(26 * time.Minute), Kind: WindowCheckout},
		{Account: "someone-else", From: at.Add(39 * time.Minute), To: at.Add(41 * time.Minute), Kind: WindowGatewaySession},
	}
	matched := Match(signIns, windows, DefaultSlack)
	bypasses := Bypasses(matched)
	if len(bypasses) != 3 || bypasses[0].Ref != "direct" || bypasses[1].Ref != "a-minute-after-a-rotation-check" || bypasses[2].Ref != "another-accounts-window" {
		t.Fatalf("bypasses: %+v", bypasses)
	}
	if matched[1].Window == nil || matched[1].Window.Kind != WindowGatewaySession || matched[4].Window == nil || matched[4].Window.Kind != WindowCheckout {
		t.Fatalf("matches: %+v", matched)
	}
	first, again, elsewhere := Fingerprint("host-a", signIns[0]), Fingerprint("host-a", signIns[0]), Fingerprint("host-b", signIns[0])
	if first != again || first == elsewhere {
		t.Fatal("a fingerprint names the target and the sign-in")
	}
}

// TestAFirstSeenSignInKeepsItsFingerprintA274: a MySQL connection is dated
// when a collection first sees it, so each collection that still sees it
// dates it anew; its reference (connection and server start) keeps it one
// sign-in. A dated sign-in's time stays part of its identity.
func TestAFirstSeenSignInKeepsItsFingerprintA274(t *testing.T) {
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	first := SignIn{Account: "app_reader", At: at, Earliest: at.Add(-15 * time.Minute), Source: "172.17.0.1", Method: "database", Ref: "connection 12 since 2026-11-07T17:00:00Z"}
	again := first
	again.At, again.Earliest = at.Add(5*time.Minute), at.Add(-10*time.Minute)
	if Fingerprint("orders-mysql", first) != Fingerprint("orders-mysql", again) {
		t.Fatal("a connection seen again by a later collection is a new sign-in")
	}
	if len(Dedupe([]SignIn{first, again})) != 1 {
		t.Fatal("a connection read twice in one report is two sign-ins")
	}
	other := first
	other.Ref = "connection 13 since 2026-11-07T17:00:00Z"
	if Fingerprint("orders-mysql", first) == Fingerprint("orders-mysql", other) {
		t.Fatal("two connections are one sign-in")
	}
	dated := SignIn{Account: "orders-single", At: at, Source: "203.0.113.5", Ref: "sshd[1]:2"}
	later := dated
	later.At = at.Add(time.Minute)
	if Fingerprint("lab-host", dated) == Fingerprint("lab-host", later) {
		t.Fatal("a dated sign-in's time is not part of its identity")
	}
}

func TestValidAccountsA274(t *testing.T) {
	if err := ValidAccounts([]string{"orders-single", "app_reader", `CORP\svc-sql`, "admin@corp.example"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {"a|b"}, {"a b"}, {"$(id)"}, {"a'"}, {strings.Repeat("a", 129)}} {
		if ValidAccounts(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestParseWindowsReportA274(t *testing.T) {
	report := strings.Join([]string{
		"=== windows",
		"2026-11-07T18:00:01.1234567Z|HOST01|svc-sql|3|203.0.113.7|0x3e7f1",
		"2026-11-07T18:01:00.0000000Z|HOST01|SVC-SQL|10|198.51.100.2|0x3e800",
		"2026-11-07T18:02:00.0000000Z|HOST01|svc-sql|2|-|0x3e801",
		"2026-11-07T18:03:00.0000000Z|HOST01|administrator|3|203.0.113.7|0x3e802",
		"2026-11-07T17:00:00.0000000Z|HOST01|svc-sql|3|203.0.113.7|0x3e803",
		"=== end",
	}, "\n")
	got, err := ParseWindowsReport([]byte(report), []string{"svc-sql"}, time.Date(2026, 11, 7, 17, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Method != "logon type 3" || got[0].Source != "203.0.113.7" || got[1].Method != "logon type 10" || got[2].Source != "" || got[2].Ref != "logon 0x3e801" {
		t.Fatalf("logons: %+v", got)
	}
	if _, err := ParseWindowsReport([]byte("=== windows\n"), []string{"svc-sql"}, time.Time{}); err != ErrIncomplete {
		t.Fatalf("a cut-short report: %v", err)
	}
}

func TestConfigAndBypassFindingA274(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"provider_id":"lab-host","lookback_seconds":900}`))
	if err != nil || cfg.ProviderID != "lab-host" || cfg.LookbackSeconds != 900 {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, bad := range []string{`{}`, `{"provider_id":"a b"}`, `{"provider_id":"x","lookback_seconds":60}`, `{"provider_id":"x","password":"p"}`, `[]`} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	s := SignIn{Account: "orders-single", At: time.Date(2026, 11, 7, 18, 0, 1, 0, time.UTC), Source: "203.0.113.5", Method: "password", Ref: "sshd[1]:2"}
	f := BypassFinding("lab-host", "unix", "sshd", s)
	if f.Ref != "pam:lab-host/orders-single" || f.RiskScore != BypassRisk || f.Metadata["ip"] != "203.0.113.5" || f.Metadata["capability"] != "CAP-ITDR-02" ||
		f.Fingerprint != Fingerprint("lab-host", s) || f.Provenance != "pam_signin:lab-host:sshd" {
		t.Fatalf("finding: %+v", f)
	}
}
