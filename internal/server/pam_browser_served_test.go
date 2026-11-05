// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestServedBrowserTerminalA259: an SSH session opened for the browser
// leaves its ticket with the control plane — the reply carries none — and its
// opener works in it through a terminal the control plane opens through the
// gateway: typed input runs, its output comes back by long-polling and is
// recorded at the gateway as any session's is. Nobody else can use the
// terminal, and terminating the session ends it.
func TestServedBrowserTerminalA259(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h

	opened := f.open("a259-browser", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice",
		"ttl_seconds": 120, "browser": true})
	if opened.Delivery != "gateway" || opened.Gateway == nil || opened.Gateway.Ticket != "" {
		t.Fatalf("a browser open's reply carries a ticket or no gateway: %+v", opened.Gateway)
	}

	terminalPath := "/api/v1/access/sessions/" + opened.ID + "/terminals"
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.operator, "a259-other", map[string]any{"cols": 80, "rows": 24}); status == http.StatusCreated {
		t.Fatal("someone other than the opener opened a terminal")
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.requester, "a259-terminal", map[string]any{"cols": 100, "rows": 30})
	var terminal struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &terminal) != nil || terminal.ID == "" {
		t.Fatalf("open a terminal = %d %s (gateway: %s)", status, body, f.gatewayLog.String())
	}
	base := terminalPath + "/" + terminal.ID
	var seen strings.Builder
	next := int64(0)
	closed := false
	read := func(wait int) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, base+"/output?from="+strconv.FormatInt(next, 10)+"&wait="+strconv.Itoa(wait), f.requester, nil)
		var out struct {
			Data   []byte `json:"data"`
			Next   int64  `json:"next"`
			Closed bool   `json:"closed"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read the terminal = %d %s", status, body)
		}
		seen.Write(out.Data)
		next, closed = out.Next, out.Closed
	}
	typed := 0
	typeLine := func(line string) {
		t.Helper()
		typed++
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/input", f.requester, "a259-input-"+strconv.Itoa(typed),
			map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(line + "\n"))}); status != http.StatusOK {
			t.Fatalf("type %q = %d %s", line, status, body)
		}
	}
	typeLine("echo browser-$((40+2))")
	a201Await(t, "the command's output reaches the browser", func() bool {
		read(5)
		return strings.Contains(seen.String(), "browser-42")
	})
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, base+"/output?from=0", f.operator, nil); status == http.StatusOK {
		t.Fatal("someone other than the opener read the terminal")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/resize", f.requester, "a259-resize", map[string]any{"cols": 120, "rows": 40}); status != http.StatusOK {
		t.Fatalf("resize = %d", status)
	}

	// The gateway recorded what the browser typed and saw.
	a201Await(t, "the gateway records the browser session", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+opened.ID+"/recording/frames?from=0", f.auditor, nil)
		if status != http.StatusOK {
			return false
		}
		var page struct {
			Frames []json.RawMessage `json:"frames"`
		}
		return json.Unmarshal(body, &page) == nil && strings.Contains(recordingOutput(t, page.Frames), "browser-42")
	})

	// Terminating the session ends the terminal.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+opened.ID+"/terminate", f.operator, "a259-terminate",
		map[string]any{"reason": "browser proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	deadline := time.Now().Add(60 * time.Second)
	for !closed && time.Now().Before(deadline) {
		read(5)
	}
	if !closed {
		t.Fatalf("the terminal outlived its terminated session: %q", seen.String())
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/input", f.requester, "a259-after", map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("id\n"))}); status == http.StatusOK {
		t.Fatal("an ended terminal took input")
	}
}

// TestServedBrowserDatabaseConsoleA259: a PostgreSQL session opened for the
// browser is queried from the console through the control plane: the
// gateway signs in as the session's login, a read answers with its rows, a
// write the read-only role may not make is the database's own refusal, a
// NULL stays null, the gateway records the statements, no reply carries the
// login's password, nobody else can query, and termination ends the console.
func TestServedBrowserDatabaseConsoleA259(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h

	opened := f.open("a259-console", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 50, "browser": true})
	if opened.Delivery != "gateway" || opened.Gateway == nil || opened.Gateway.Ticket != "" {
		t.Fatalf("a browser open's reply carries a ticket or no gateway: %+v", opened.Gateway)
	}
	dsn, err := h.srv.pam.gatewaySessionCredential(f.ctx, h.tenant, opened.ID)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.SplitN(strings.SplitN(string(dsn), "@", 2)[0], ":", 3)[2]
	if password == "" {
		t.Fatalf("the session's login has no password")
	}
	queries := 0
	run := func(token, sql string) (int, []byte) {
		t.Helper()
		queries++
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+opened.ID+"/queries", token,
			"a259-query-"+strconv.Itoa(queries), map[string]any{"sql": sql})
		if strings.Contains(string(body), password) || strings.Contains(string(body), string(dsn)) {
			t.Fatalf("a console reply carries the session's credential")
		}
		return status, body
	}
	if status, _ := run(f.operator, "SELECT 1"); status == http.StatusOK {
		t.Fatal("someone other than the opener queried the session")
	}
	type result struct {
		Columns []string    `json:"columns"`
		Rows    [][]*string `json:"rows"`
		Error   *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decode := func(status int, body []byte) result {
		t.Helper()
		var r result
		if status != http.StatusOK || json.Unmarshal(body, &r) != nil {
			t.Fatalf("query = %d %s (gateway: %s)", status, body, f.gatewayLog.String())
		}
		return r
	}
	if r := decode(run(f.requester, "SELECT count(*) AS seeded FROM public.pam_smoke")); len(r.Columns) != 1 || r.Columns[0] != "seeded" ||
		len(r.Rows) != 1 || r.Rows[0][0] == nil || *r.Rows[0][0] != "1" {
		t.Fatalf("read = %+v", r)
	}
	if r := decode(run(f.requester, "INSERT INTO public.pam_smoke VALUES (2)")); r.Error == nil || r.Error.Code != "42501" {
		t.Fatalf("a read-only login's write = %+v", r)
	}
	if r := decode(run(f.requester, "SELECT NULL::text AS empty, current_user = session_user AS same")); len(r.Rows) != 1 || r.Rows[0][0] != nil ||
		r.Rows[0][1] == nil || *r.Rows[0][1] != "t" {
		t.Fatalf("null and login = %+v", r)
	}

	a201Await(t, "the gateway records the console's statements", func() bool {
		return strings.Contains(recordingText(t, h, opened.ID), "SELECT count(*) AS seeded FROM public.pam_smoke")
	})

	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+opened.ID+"/terminate", f.operator, "a259-console-terminate",
		map[string]any{"reason": "console proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	a201Await(t, "the terminated session's console refuses", func() bool {
		status, _ := run(f.requester, "SELECT 1")
		return status != http.StatusOK
	})
}
