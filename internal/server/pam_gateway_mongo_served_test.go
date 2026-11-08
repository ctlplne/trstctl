// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mongosignin"
)

// a256MongoImage is the census's pinned MongoDB 7.0, which carries mongosh.
const a256MongoImage = mongoTwoUserImage

// startPAMMongo runs the pinned MongoDB image with a root user and an
// "orders" database holding a note, and returns its container and a
// provider of per-session users in the "mongo-reader" role (read on orders).
func startPAMMongo(t *testing.T, note string) (string, DynamicSecretProviderRegistry) {
	t.Helper()
	if out, err := exec.Command("docker", "image", "inspect", a256MongoImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a256MongoImage, err, out)
	}
	id, addr := a201Container(t, "27017", "-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD=a256-admin", a256MongoImage)
	root := func(script string) (string, error) {
		return a201Exec(id, "mongosh", "--quiet", "-u", "root", "-p", "a256-admin", "--authenticationDatabase", "admin", "--eval", script)
	}
	// The image's init server answers on localhost and then restarts; wait
	// for the init-done line, after which only the real server answers.
	a256AwaitLog(t, id, "MongoDB init process complete")
	a201Await(t, "MongoDB", func() bool {
		out, err := root("db.runCommand({ping: 1}).ok")
		return err == nil && strings.TrimSpace(out) == "1"
	})
	if out, err := root(`db.getSiblingDB("orders").notes.insertOne({_id: 1, note: "` + note + `"}).acknowledged`); err != nil || !strings.Contains(out, "true") {
		t.Fatalf("seed MongoDB: %v %s", err, out)
	}
	adminURI := (&url.URL{Scheme: "mongodb", User: url.UserPassword("root", "a256-admin"), Host: addr, Path: "/orders",
		RawQuery: "authSource=admin&directConnection=true"}).String()
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-mongo-provider", Type: "mongodb",
		AdminDSNRef: writeServedCredentialFile(t, "mongo-admin-uri", adminURI), Database: "orders",
		AllowedRoles: []string{"mongo-reader"}, RoleAccess: map[string]string{"mongo-reader": "read"}, MaxTTL: "1h", UsernamePrefix: "a256_mongo",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, registry
}

var fixtureMongoCommand = regexp.MustCompile(`mongosh mongodb://127\.0\.0\.1:(\d+)/`)

// a256AwaitLog waits until a container's log holds a line: a database
// image's init-done marker, after which only its real server answers.
func a256AwaitLog(t *testing.T, id, line string) {
	t.Helper()
	a201Await(t, "the container's "+strconv.Quote(line), func() bool {
		out, _ := exec.Command("docker", "logs", id).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		return strings.Contains(string(out), line)
	})
}

// mongoSessionUsers lists the per-session users the provider created.
func mongoSessionUsers(t *testing.T, mongoID string) []string {
	t.Helper()
	out, err := a201Exec(mongoID, "mongosh", "--quiet", "-u", "root", "-p", "a256-admin", "--authenticationDatabase", "admin", "--eval",
		`db.getSiblingDB("orders").getUsers().users.map(u => u.user).join("\n")`)
	if err != nil {
		t.Fatalf("list users: %v %s", err, out)
	}
	var users []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "a256_mongo") {
			users = append(users, line)
		}
	}
	return users
}

// mongoCommand sends one OP_MSG command over a raw connection and returns its
// reply document.
func mongoCommand(t *testing.T, conn net.Conn, id int32, doc []mongosignin.E) []byte {
	t.Helper()
	body := append([]byte{0, 0, 0, 0, 0}, mongosignin.Encode(doc)...)
	if _, err := conn.Write(append(mongosignin.MessageHeader(16+len(body), id, 0, mongosignin.OpMsg), body...)); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binary.LittleEndian.Uint32(header)-16)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	if int32(binary.LittleEndian.Uint32(header[8:])) != id { // #nosec G115 -- a request id's two's-complement bits (CWE-190)
		t.Fatalf("reply answers request %d, want %d", binary.LittleEndian.Uint32(header[8:]), id)
	}
	return payload[5:]
}

// TestServedGatewayMongoSessionsA256: a MongoDB target is served only
// through the access gateway, to the stock mongosh holding no credential.
// The gateway signs in as the session's own user (SCRAM-SHA-256); the
// user's role scopes the session; a client's own sign-in (saslStart) is
// refused and the connection keeps the session's user; the session is
// recorded masked, sealed and verifiable; an operator's termination closes a
// live connection and the gateway acknowledges it; the user is dropped.
func TestServedGatewayMongoSessionsA256(t *testing.T) {
	token := "ghp_a256MongoSessionToken" + strings.Repeat("G", 15) // a GitHub token's shape: ghp_ and 36 characters
	f := startGatewayFixture(t, gatewayFixtureOptions{mongoNote: token})
	h := f.h

	session := f.open("a256-mongo", map[string]any{"target_type": "mongodb", "target_id": "mongo-gw", "role": "mongo-reader", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil {
		t.Fatalf("the MongoDB session was not delivered through its gateway: %+v", session)
	}
	tunnelOut, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, fixtureMongoCommand.MatchString)
	defer stopTunnel()
	port := fixtureMongoCommand.FindStringSubmatch(tunnelOut)[1]
	users := mongoSessionUsers(t, f.mongoID)
	if len(users) != 1 {
		t.Fatalf("session users = %v, want the session's one", users)
	}
	_, read := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for what, text := range map[string]string{"session read": string(read), "CLI output": tunnelOut} {
		if strings.Contains(text, users[0]) || strings.Contains(text, "mongodb://"+users[0]) {
			t.Fatalf("the %s carries the session's credential: %s", what, text)
		}
	}
	mongosh := func(script string) string {
		cmd := exec.CommandContext(f.ctx, "docker", "exec", f.mongoID, "mongosh", "--quiet", "mongodb://host.docker.internal:"+port+"/orders?directConnection=true", "--eval", script) // #nosec G204 G702 -- the stock mongosh against the test's own tunnel (CWE-78)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	if got := mongosh(`db.notes.findOne({_id: 1}).note`); got != token {
		t.Fatalf("findOne through the gateway = %q (gateway: %s)", got, f.gatewayLog.String())
	}
	if got := mongosh(`try { db.notes.insertOne({_id: 2}); print("INSERTED") } catch (e) { print("DENIED " + e.codeName) }`); got != "DENIED Unauthorized" {
		t.Fatalf("a write outside the session's role = %q", got)
	}
	// A client's own sign-in is refused on a live connection, which keeps
	// the session's user.
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	refused := mongoCommand(t, conn, 7, []mongosignin.E{{Key: "saslStart", Value: int32(1)}, {Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: []byte("n,,n=root,r=abc")}, {Key: "$db", Value: "admin"}})
	if code, _ := mongosignin.Lookup(refused, "code"); !strings.Contains(string(refused), "saslStart is refused") || code.Type != mongosignin.TypeInt32 {
		t.Fatalf("saslStart through the gateway = %q", refused)
	}
	status := mongoCommand(t, conn, 8, []mongosignin.E{{Key: "connectionStatus", Value: int32(1)}, {Key: "$db", Value: "admin"}})
	if !strings.Contains(string(status), users[0]) || strings.Contains(string(status), "\x00root\x00") {
		t.Fatalf("after the refused saslStart the connection is %q", status)
	}

	// The live connection, terminated.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator,
		"a256-mongo-terminate", map[string]any{"reason": "a256 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err == nil {
		t.Fatal("the terminated connection is still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the terminated connection was not closed")
	}
	a201Await(t, "the gateway acknowledges the termination", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "the session's user is dropped", func() bool { return len(mongoSessionUsers(t, f.mongoID)) == 0 })

	// The recording.
	a201Await(t, "the MongoDB recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	if strings.Contains(text, token) || strings.Contains(text, "a256-admin") || strings.Contains(text, "n=root") {
		t.Fatalf("the MongoDB recording kept a secret:\n%s", text)
	}
	for _, want := range []string{`command: {find: "notes", filter: {_id: 1}`, `note: "[masked:github-token]"`, `command: {insert: "notes"`,
		"Unauthorized", "refused: saslStart", "command: {connectionStatus: 1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the MongoDB recording lacks %q:\n%s", want, text)
		}
	}
}
