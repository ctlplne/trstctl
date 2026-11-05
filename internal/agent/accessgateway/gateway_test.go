// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

// fakeChannel hands out one session job and answers extensions until recalled.
type fakeChannel struct {
	mu       sync.Mutex
	jobs     []relay.Job
	material map[string][]byte
	recalled bool
	reports  []string
}

func (f *fakeChannel) ClaimJobs(context.Context, []string, int, int) ([]relay.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.jobs
	f.jobs = nil
	return out, nil
}

func (f *fakeChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.material {
		out[k] = append([]byte(nil), v...)
	}
	return out, nil
}

func (f *fakeChannel) ReportJobResult(_ context.Context, _ int64, _ int, outcome, detail, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, outcome+" "+detail)
	return true, nil
}

func (f *fakeChannel) ExtendJobClaim(context.Context, int64, int) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recalled {
		return time.Time{}, relay.ErrJobClaimLost
	}
	return time.Now().Add(time.Minute), nil
}

func startGateway(t *testing.T, ch *fakeChannel) (*Gateway, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{Channel: ch, Listener: ln, ClaimInterval: 20 * time.Millisecond, ExtendInterval: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = g.Run(ctx) }()
	return g, ln.Addr().String()
}

func sessionJob(t *testing.T, id, ticket string, expires time.Time) relay.Job {
	t.Helper()
	payload, err := json.Marshal(SessionIntent{SessionID: id, TargetType: TargetPostgres, TargetID: "pg", ExpiresAt: expires,
		TicketDigest: TicketDigest(ticket), CredentialRef: CredentialRef(id), RequiredAgentID: "gw"})
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 7, Kind: KindSession, Attempt: 1, Payload: payload}
}

func preface(t *testing.T, addr, line string) (net.Conn, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	answer, _ := bufio.NewReader(c).ReadString('\n')
	return c, strings.TrimSpace(answer)
}

func awaitSession(t *testing.T, g *Gateway, id string, held bool) {
	t.Helper()
	for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(10 * time.Millisecond) {
		has := false
		for _, s := range g.Sessions() {
			has = has || s == id
		}
		if has == held {
			return
		}
	}
	t.Fatalf("session %s held=%v never reached", id, held)
}

// A254: nothing reaches a session without its ticket — a malformed preface, an
// unknown session, a wrong ticket are each refused before any upstream
// connection; a recall (revocation) ends the session, closes its connections
// and reports it recalled.
func TestGatewayAdmitsOnlyTheTicketAndEndsOnRecallA254(t *testing.T) {
	const id, ticket = "11111111-1111-4111-8111-111111111111", "the-session-ticket"
	ch := &fakeChannel{jobs: []relay.Job{sessionJob(t, id, ticket, time.Now().Add(time.Minute))},
		material: map[string][]byte{CredentialRef(id): []byte("postgres://login:pw@127.0.0.1:1/db")}}
	g, addr := startGateway(t, ch)
	awaitSession(t, g, id, true)

	for line, want := range map[string]string{
		"HELLO\n": "DENY malformed preface",
		Preface + " 22222222-2222-4222-8222-222222222222 x\n": "DENY unknown session",
		Preface + " " + id + " wrong-ticket\n":                "DENY ticket refused",
	} {
		c, answer := preface(t, addr, line)
		_ = c.Close()
		if answer != want {
			t.Fatalf("preface %q answered %q, want %q", line, answer, want)
		}
	}
	held, answer := preface(t, addr, Preface+" "+id+" "+ticket+"\n")
	if answer != "OK" {
		t.Fatalf("the right ticket answered %q", answer)
	}
	ch.mu.Lock()
	ch.recalled = true
	ch.mu.Unlock()
	awaitSession(t, g, id, false)
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Fatal("a recalled session's connection stayed open")
	}
	_ = held.Close()
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.reports) == 0 || !strings.Contains(ch.reports[len(ch.reports)-1], `"ended":"recalled"`) {
		t.Fatalf("reports = %v", ch.reports)
	}
}

// A session whose deadline already passed is never held: it is reported
// ended at its deadline with no credential redeemed into use.
func TestGatewayRefusesAnExpiredSessionA254(t *testing.T) {
	const id = "33333333-3333-4333-8333-333333333333"
	ch := &fakeChannel{jobs: []relay.Job{sessionJob(t, id, "t", time.Now().Add(-time.Second))}}
	g, _ := startGateway(t, ch)
	for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(10 * time.Millisecond) {
		ch.mu.Lock()
		n := len(ch.reports)
		ch.mu.Unlock()
		if n > 0 {
			break
		}
	}
	if len(g.Sessions()) != 0 {
		t.Fatal("an expired session is held")
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.reports) != 1 || !strings.HasPrefix(ch.reports[0], "failed ") || !strings.Contains(ch.reports[0], `"ended":"deadline"`) {
		t.Fatalf("reports = %v", ch.reports)
	}
}

func TestSessionIntentValidationA254(t *testing.T) {
	good := SessionIntent{SessionID: "s", TargetType: TargetPostgres, TargetID: "pg", ExpiresAt: time.Now(),
		TicketDigest: TicketDigest("t"), CredentialRef: CredentialRef("s"), RequiredAgentID: "gw"}
	if err := ValidateSessionIntent(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SessionIntent){
		"another session's credential": func(i *SessionIntent) { i.CredentialRef = CredentialRef("other") },
		"no gateway":                   func(i *SessionIntent) { i.RequiredAgentID = "" },
		"not a digest":                 func(i *SessionIntent) { i.TicketDigest = "the-ticket-itself" },
		"unknown target type":          func(i *SessionIntent) { i.TargetType = "mcp" },
	} {
		in := good
		mutate(&in)
		if ValidateSessionIntent(in) == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if !TicketMatches("t", TicketDigest("t")) || TicketMatches("u", TicketDigest("t")) || TicketMatches("t", "") {
		t.Fatal("ticket comparison is wrong")
	}
	// An SSH session redeems nothing and names where to sign in, as whom, and
	// which host keys to accept.
	pin := "SHA256:" + strings.Repeat("A", 43)
	ssh := SessionIntent{SessionID: "s", TargetType: TargetSSH, TargetID: "bastion", ExpiresAt: time.Now(),
		TicketDigest: TicketDigest("t"), RequiredAgentID: "gw", SSHAddress: "10.0.0.5:22", SSHPrincipal: "deploy",
		SSHHostKeyFingerprints: []string{pin}}
	if err := ValidateSessionIntent(ssh); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SessionIntent){
		"a credential to redeem": func(i *SessionIntent) { i.CredentialRef = CredentialRef("s") },
		"no address":             func(i *SessionIntent) { i.SSHAddress = "10.0.0.5" },
		"no principal":           func(i *SessionIntent) { i.SSHPrincipal = "" },
		"two principals":         func(i *SessionIntent) { i.SSHPrincipal = "deploy,root" },
		"a wildcard principal":   func(i *SessionIntent) { i.SSHPrincipal = "*" },
		"no host key pin":        func(i *SessionIntent) { i.SSHHostKeyFingerprints = nil },
		"a malformed pin":        func(i *SessionIntent) { i.SSHHostKeyFingerprints = []string{"MD5:aa:bb"} },
	} {
		in := ssh
		mutate(&in)
		if ValidateSessionIntent(in) == nil {
			t.Fatalf("SSH intent with %s was accepted", name)
		}
	}
	routed := good
	routed.SSHAddress = "10.0.0.5:22"
	if ValidateSessionIntent(routed) == nil {
		t.Fatal("a PostgreSQL session carrying SSH routing was accepted")
	}
	if got := ClaimableKinds(); len(got) != 3 || got[0] != KindSession || got[1] != KindSessionRules || got[2] != KindSessionSSHRules {
		t.Fatalf("the gateway claims %v", got)
	}
}
