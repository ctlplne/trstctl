// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// consoleSessionPassword is the password in a session's credential: a URL's
// (redis://, mongodb://) or a MySQL DSN's (user:password@tcp(host)/db).
func consoleSessionPassword(t *testing.T, credential string) string {
	t.Helper()
	if strings.Contains(credential, "://") {
		parsed, err := url.Parse(credential)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := parsed.User.Password()
		return password
	}
	userinfo, _, _ := strings.Cut(credential, "@tcp(")
	_, password, _ := strings.Cut(userinfo, ":")
	return password
}

// TestServedBrowserDatabaseConsolesForMySQLMongoRedisA259L5 is A259-L5: a
// MySQL, MongoDB or Redis session opened for the browser has a console, as a
// PostgreSQL session does. The control plane runs each SQL statement or
// command through the session's gateway, which signs in as the session's
// account and records it. A read answers with its rows; a write the role may
// not make is the database's own refusal; a sign-in the gateway refuses
// leaves the session's account in place. Text the console cannot send is
// refused without ending the connection, the wrong field for the engine is
// refused before anything runs, nobody but the opener runs anything, no reply
// carries the session's credential, and termination ends each console.
func TestServedBrowserDatabaseConsolesForMySQLMongoRedisA259L5(t *testing.T) {
	const mysqlNote, mongoNote = "a259l5-mysql-note", "a259l5-mongo-note"
	f := startGatewayFixture(t, gatewayFixtureOptions{redis: true, mysqlNote: mysqlNote, mongoNote: mongoNote})
	h := f.h
	type result struct {
		Columns    []string    `json:"columns"`
		Rows       [][]*string `json:"rows"`
		CommandTag string      `json:"command_tag"`
		Error      *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	queries := 0
	passwords := map[string]string{}
	send := func(token, sessionID, field, text string) (int, []byte) {
		t.Helper()
		queries++
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+sessionID+"/queries", token,
			"a259l5-query-"+strconv.Itoa(queries), map[string]any{field: text})
		if password := passwords[sessionID]; password == "" || strings.Contains(string(body), password) {
			t.Fatalf("a console reply carries the session's credential, or the session has none")
		}
		return status, body
	}
	run := func(sessionID, field, text string) result {
		t.Helper()
		status, body := send(f.requester, sessionID, field, text)
		var r result
		if status != http.StatusOK || json.Unmarshal(body, &r) != nil {
			t.Fatalf("%s %q = %d %s (gateway: %s)", field, text, status, body, f.gatewayLog.String())
		}
		return r
	}
	cell := func(r result, row, column int) string {
		t.Helper()
		if row >= len(r.Rows) || column >= len(r.Rows[row]) {
			if r.Error != nil {
				t.Fatalf("result refused (%s): %s; it has no cell %d,%d", r.Error.Code, r.Error.Message, row, column)
			}
			t.Fatalf("result %+v has no cell %d,%d", r, row, column)
		}
		if r.Rows[row][column] == nil {
			return "(null)"
		}
		return *r.Rows[row][column]
	}
	open := func(key, targetType, targetID, role string) string {
		t.Helper()
		opened := f.open(key, map[string]any{"target_type": targetType, "target_id": targetID, "role": role, "ttl_seconds": 150, "browser": true})
		if opened.Delivery != "gateway" || opened.Gateway == nil || opened.Gateway.Ticket != "" {
			t.Fatalf("a browser open's reply carries a ticket or no gateway: %+v", opened.Gateway)
		}
		credential, err := h.srv.pam.gatewaySessionCredential(f.ctx, h.tenant, opened.ID)
		if err != nil {
			t.Fatal(err)
		}
		passwords[opened.ID] = consoleSessionPassword(t, string(credential))
		// Nobody but the opener runs anything.
		if status, _ := send(f.operator, opened.ID, map[bool]string{true: "sql", false: "command"}[targetType == "mysql"], "SELECT 1"); status == http.StatusOK {
			t.Fatalf("someone other than the opener used the %s console", targetType)
		}
		return opened.ID
	}

	// MySQL: SQL, as the mysql client sends it.
	mysqlID := open("a259l5-mysql", "mysql", "mysql-gw", "mysql-reader")
	if r := run(mysqlID, "sql", "SELECT CURRENT_USER() AS who, note FROM app.notes"); strings.Join(r.Columns, ",") != "who,note" ||
		!strings.HasPrefix(cell(r, 0, 0), "a256_mysql") || !strings.HasSuffix(cell(r, 0, 0), "@%") || cell(r, 0, 1) != mysqlNote {
		t.Fatalf("a MySQL read = %+v", r)
	}
	if r := run(mysqlID, "sql", "INSERT INTO app.notes VALUES (2, 'no')"); r.Error == nil || !strings.HasPrefix(r.Error.Code, "1142") ||
		!strings.Contains(r.Error.Message, "INSERT command denied") {
		t.Fatalf("a read-only account's write = %+v", r)
	}
	if r := run(mysqlID, "sql", "SELECT NULL AS nothing"); cell(r, 0, 0) != "(null)" {
		t.Fatalf("a MySQL NULL = %+v", r)
	}
	if status, body := send(f.requester, mysqlID, "command", "GET a256:x"); status != http.StatusUnprocessableEntity {
		t.Fatalf("a command on a MySQL console = %d %s", status, body)
	}

	// Redis: one command, as redis-cli takes it.
	redisID := open("a259l5-redis", "redis", "redis-gw", "redis-writer")
	if r := run(redisID, "command", `SET a256:console "hello world"`); r.CommandTag != "SET" || cell(r, 0, 0) != "OK" {
		t.Fatalf("a Redis write = %+v", r)
	}
	if r := run(redisID, "command", "GET a256:console"); strings.Join(r.Columns, ",") != "value" || cell(r, 0, 0) != "hello world" {
		t.Fatalf("a Redis read = %+v", r)
	}
	if r := run(redisID, "command", "GET a256:missing"); cell(r, 0, 0) != "(null)" {
		t.Fatalf("a missing key = %+v", r)
	}
	if r := run(redisID, "command", "CONFIG GET maxmemory"); r.Error == nil || r.Error.Code != "NOPERM" {
		t.Fatalf("a command outside the role = %+v", r)
	}
	// The gateway sends the server a command named for the refusal in its
	// place, which the server answers as unknown.
	if r := run(redisID, "command", "AUTH default someone-else"); r.Error == nil || r.Error.Code != "ERR" ||
		!strings.Contains(r.Error.Message, "TRSTCTL-GATEWAY-REFUSED-AUTH") {
		t.Fatalf("a sign-in through the console = %+v", r.Error)
	}
	if status, body := send(f.requester, redisID, "command", `GET "unclosed`); status != http.StatusUnprocessableEntity {
		t.Fatalf("an unclosed quote = %d %s", status, body)
	}
	// The connection is still the session's, through the refusals.
	if r := run(redisID, "command", "GET a256:console"); cell(r, 0, 0) != "hello world" {
		t.Fatalf("a read after the refusals = %+v", r)
	}

	// MongoDB: one command document, on the provider's database unless it
	// names $db.
	mongoID := open("a259l5-mongo", "mongodb", "mongo-gw", "mongo-reader")
	if r := run(mongoID, "command", `{"find": "notes", "filter": {"_id": 1}}`); r.CommandTag != "find" || strings.Join(r.Columns, ",") != "document" ||
		len(r.Rows) != 1 || !strings.Contains(cell(r, 0, 0), `"note":"`+mongoNote+`"`) {
		t.Fatalf("a MongoDB read = %+v", r)
	}
	if r := run(mongoID, "command", `{"insert": "notes", "documents": [{"_id": 2}]}`); r.Error == nil || r.Error.Code != "Unauthorized" {
		t.Fatalf("a read-only user's write = %+v", r)
	}
	if r := run(mongoID, "command", `{"saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": {"$binary": {"base64": "", "subType": "00"}}}`); r.Error == nil ||
		r.Error.Code != "Unauthorized" || !strings.Contains(r.Error.Message, "the access gateway signs in as the session's user") {
		t.Fatalf("a sign-in through the console = %+v", r)
	}
	if status, body := send(f.requester, mongoID, "command", "db.notes.find()"); status != http.StatusUnprocessableEntity {
		t.Fatalf("a shell expression for a command document = %d %s", status, body)
	}
	if r := run(mongoID, "command", `{"count": "notes"}`); !strings.Contains(cell(r, 0, 0), `"n":1`) {
		t.Fatalf("a count after the refusals = %+v", r)
	}
	if status, body := send(f.requester, mongoID, "sql", "SELECT 1"); status != http.StatusUnprocessableEntity {
		t.Fatalf("SQL on a MongoDB console = %d %s", status, body)
	}

	// Each session's recording holds its console's statements.
	for id, want := range map[string]string{mysqlID: "SELECT CURRENT_USER() AS who, note FROM app.notes", redisID: "a256:console", mongoID: "find"} {
		a201Await(t, "the gateway records the console's "+want, func() bool { return strings.Contains(recordingText(t, h, id), want) })
	}

	// Termination ends each console.
	for i, id := range []string{mysqlID, redisID, mongoID} {
		if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/terminate", f.operator, "a259l5-terminate-"+strconv.Itoa(i),
			map[string]any{"reason": "console proof"}); status != http.StatusAccepted {
			t.Fatalf("terminate = %d", status)
		}
	}
	a201Await(t, "the terminated sessions' consoles refuse", func() bool {
		mysqlStatus, _ := send(f.requester, mysqlID, "sql", "SELECT 1")
		redisStatus, _ := send(f.requester, redisID, "command", "PING")
		mongoStatus, _ := send(f.requester, mongoID, "command", `{"ping": 1}`)
		return mysqlStatus != http.StatusOK && redisStatus != http.StatusOK && mongoStatus != http.StatusOK
	})
}
