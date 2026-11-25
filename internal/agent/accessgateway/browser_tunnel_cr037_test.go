// SPDX-License-Identifier: BUSL-1.1

// CR-037 regression from V9 verification of S15a-L1. The browser's
// requests travel the product's own path end to end: a loopback listener that
// pipes each local connection to the gateway behind the session's preface
// (what internal/cli/access_connect.go:276-300 does; it reads no HTTP), the
// real Gateway's ticket admission and dispatch (gateway.go:483-650), and the
// web-console, Kubernetes and ClickHouse relays. The attacker knows only the
// tunnel's port: the session ID and ticket are added by the tunnel.
package accessgateway

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/agent/relay"
)

func v9CAPEM(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// v9Tunnel is the CLI tunnel: every local connection becomes one gateway
// connection opened with "TRSTCTL-GATEWAY/1 <session> <ticket>"; after OK
// the bytes are piped unchanged.
func v9Tunnel(t *testing.T, gateway, id, ticket string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = local.Close() }()
				remote, err := net.Dial("tcp", gateway)
				if err != nil {
					return
				}
				defer func() { _ = remote.Close() }()
				if _, err := fmt.Fprintf(remote, "%s %s %s\n", Preface, id, ticket); err != nil {
					return
				}
				var answer []byte
				one := make([]byte, 1)
				for {
					if _, err := io.ReadFull(remote, one); err != nil {
						return
					}
					if one[0] == '\n' {
						break
					}
					answer = append(answer, one[0])
				}
				if string(answer) != "OK" {
					return
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
				go func() { _, _ = io.Copy(local, remote); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

// v9Send writes one raw HTTP/1.1 request, headers as a browser sends them,
// to the tunnel and reads the answer; the connection stays open for an
// upgraded stream.
func v9Send(t *testing.T, tunnel, raw string) (*http.Response, string, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", tunnel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("no answer through the tunnel: %v", err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return resp, "", c, r
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body), c, r
}

// v9ReadFrame reads one WebSocket frame and returns its unmasked payload.
func v9ReadFrame(r *bufio.Reader) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := uint64(head[1] & 0x7f)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		n = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		n = binary.BigEndian.Uint64(ext)
	}
	if n > 1<<16 {
		return nil, errors.New("frame too large for the test")
	}
	var key []byte
	if head[1]&0x80 != 0 {
		key = make([]byte, 4)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		if key != nil {
			payload[i] ^= key[i%4]
		}
	}
	return payload, nil
}

func v9Job(t *testing.T, jobID int64, intent SessionIntent) relay.Job {
	t.Helper()
	if err := ValidateSessionIntent(intent); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: KindForIntent(intent), Attempt: 1, Payload: payload}
}

// RFC 6455 section 1.3's sample key and its accept value (no hashing in the test).
const (
	v9WSKey    = "dGhlIHNh" + "bXBsZSBu" + "b25jZQ=="
	v9WSAccept = "s3pPLMBi" + "TxaQ9kYG" + "zzhZRbK+" + "xOo="
)

func TestCR037GatewayRejectsCrossSiteAndReboundBrowserRequests(t *testing.T) {
	const (
		webToken   = "web-fixture" // #nosec G101 -- non-secret local upstream fixture for CR-037 (CWE-352)
		k8sToken   = "k8s-fixture" // #nosec G101 -- non-secret local upstream fixture for CR-037 (CWE-352)
		chUser     = "v9_ch_session_user"
		chPassword = "ch-fixture" // #nosec G101 -- non-secret local upstream fixture for CR-037 (CWE-352)
	)
	var mu sync.Mutex
	var upstream []string
	note := func(s string) { mu.Lock(); upstream = append(upstream, s); mu.Unlock() }

	// A console whose CSRF defense is the usual one: a state change only with
	// its own Origin and Referer.
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != webToken {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		own := "https://" + r.Host
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/console/users/delete":
			if r.Header.Get("Origin") != own || !strings.HasPrefix(r.Header.Get("Referer"), own+"/") {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			_ = r.ParseForm()
			note("web: deleted user " + r.PostForm.Get("user") + " (console saw Origin " + r.Header.Get("Origin") + ", Referer " + r.Header.Get("Referer") + ")")
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/console/terminal" && strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
			// A console terminal that does what a careful console does
			// against cross-site WebSocket hijacking: only its own Origin.
			if r.Header.Get("Origin") != own || r.Header.Get("Sec-WebSocket-Key") != v9WSKey {
				http.Error(w, "cross-site WebSocket refused", http.StatusForbidden)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", v9WSAccept)
			_ = rw.Flush()
			typed, err := v9ReadFrame(rw.Reader)
			if err != nil {
				return
			}
			note("web: terminal ran " + strings.TrimSpace(string(typed)) + " (console saw Origin " + r.Header.Get("Origin") + ")")
			_, _ = rw.Write(wsFrame(0x1, []byte("root@console:~# uid=0(root)\n"), false))
			_ = rw.Flush()
			time.Sleep(100 * time.Millisecond)
		case r.URL.Path == "/console/secrets":
			note("web: served /console/secrets to Host " + r.Host)
			_, _ = io.WriteString(w, "<p>console data only an administrator reads</p>")
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer web.Close()

	// A Kubernetes API server: bearer authentication, WebSocket exec with a
	// channel protocol and no Origin check (kube-apiserver checks none).
	k8s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+k8sToken {
			http.Error(w, `{"kind":"Status","code":401}`, http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/exec") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
			if !strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "v4.channel.k8s.io") || r.Header.Get("Sec-WebSocket-Key") != v9WSKey {
				http.Error(w, "bad handshake", http.StatusBadRequest)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n", v9WSAccept)
			_ = rw.Flush()
			stdin, err := v9ReadFrame(rw.Reader)
			if err != nil || len(stdin) == 0 || stdin[0] != 0 {
				return
			}
			note("k8s: exec " + r.URL.RawQuery + " stdin " + strings.TrimSpace(string(stdin[1:])) + " (Origin " + r.Header.Get("Origin") + ")")
			_, _ = rw.Write(wsFrame(0x2, append([]byte{1}, "uid=0(root) gid=0(root)\n"...), false))
			_ = rw.Flush()
			time.Sleep(100 * time.Millisecond)
		case r.URL.Path == "/api/v1/namespaces/default/secrets":
			note("k8s: listed secrets for Host " + r.Host)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"SecretList","items":[{"metadata":{"name":"db-root"},"data":{"password":"Zg=="}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer k8s.Close()

	// ClickHouse's HTTP interface: the statement is the query parameter plus
	// the body; a GET is read-only.
	ch := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClickHouse-User") != chUser || r.Header.Get("X-ClickHouse-Key") != chPassword {
			http.Error(w, "Code: 516. Authentication failed", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		stmt := strings.TrimSpace(r.URL.Query().Get("query") + " " + string(body))
		if r.Method == http.MethodGet && !strings.HasPrefix(strings.ToUpper(stmt), "SELECT") {
			http.Error(w, "Code: 164. readonly", http.StatusBadRequest)
			return
		}
		note("clickhouse: ran " + stmt + " as " + r.Header.Get("X-ClickHouse-User") + " (Origin " + r.Header.Get("Origin") + ")")
		_, _ = io.WriteString(w, "Ok.\n")
	}))
	defer ch.Close()

	const (
		webID, webTicket = "91919191-0000-4000-8000-000000000001", "v9-web-ticket"
		k8sID, k8sTicket = "91919191-0000-4000-8000-000000000002", "v9-k8s-ticket"
		chID, chTicket   = "91919191-0000-4000-8000-000000000003", "v9-ch-ticket"
	)
	expires := time.Now().Add(time.Minute)
	base := func(id, ticket, target string, typ string) SessionIntent {
		return SessionIntent{SessionID: id, TargetType: typ, TargetID: target, ExpiresAt: expires, TicketDigest: TicketDigest(ticket),
			CredentialRef: CredentialRef(id), RequiredAgentID: "gw"}
	}
	webIntent := base(webID, webTicket, "console", TargetWeb)
	webIntent.UpstreamURL, webIntent.UpstreamCAPEM = web.URL+"/console/", v9CAPEM(web)
	webIntent.WebSignIn = &accessweb.SignIn{Mode: accessweb.SignInHeader, Header: "X-Api-Key"}
	k8sIntent := base(k8sID, k8sTicket, "cluster", TargetKubernetes)
	k8sIntent.UpstreamURL, k8sIntent.UpstreamCAPEM = k8s.URL, v9CAPEM(k8s)
	chIntent := base(chID, chTicket, "warehouse", TargetClickHouse)
	chIntent.UpstreamURL, chIntent.UpstreamCAPEM = ch.URL, v9CAPEM(ch)
	channel := &fakeChannel{
		jobs: []relay.Job{v9Job(t, 901, webIntent), v9Job(t, 902, k8sIntent), v9Job(t, 903, chIntent)},
		material: map[string][]byte{
			CredentialRef(webID): []byte(`{"token":"` + webToken + `"}`),
			CredentialRef(k8sID): []byte(k8sToken),
			CredentialRef(chID):  []byte(`{"username":"` + chUser + `","password":"` + chPassword + `"}`),
		}}
	g, gatewayAddr := startGateway(t, channel)
	for _, id := range []string{webID, k8sID, chID} {
		awaitSession(t, g, id, true)
	}
	webTunnel := v9Tunnel(t, gatewayAddr, webID, webTicket)
	k8sTunnel := v9Tunnel(t, gatewayAddr, k8sID, k8sTicket)
	chTunnel := v9Tunnel(t, gatewayAddr, chID, chTicket)

	// Control: the operator's own same-origin form post is served.
	form := "user=control"
	resp, _, _, _ := v9Send(t, webTunnel, "POST /console/users/delete HTTP/1.1\r\nHost: "+webTunnel+"\r\nOrigin: http://"+webTunnel+
		"\r\nReferer: http://"+webTunnel+"/console/users\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(form), form))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("setup: the operator's own same-origin post answered %d", resp.StatusCode)
	}
	mu.Lock()
	upstream = nil
	mu.Unlock()

	var acted []string
	// (1) Web console, cross-site form post (a top-level navigation from
	// https://evil.example: no preflight).
	form = "user=admin"
	resp, _, _, _ = v9Send(t, webTunnel, "POST /console/users/delete HTTP/1.1\r\nHost: "+webTunnel+"\r\nOrigin: https://evil.example"+
		"\r\nReferer: https://evil.example/landing.html\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document"+
		"\r\nContent-Type: application/x-www-form-urlencoded\r\n"+fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(form), form))
	acted = append(acted, fmt.Sprintf("web cross-site POST -> %d", resp.StatusCode))
	// (2) Web console, DNS-rebound read (the page's own origin, Host = its name).
	resp, body, _, _ := v9Send(t, webTunnel, "GET /console/secrets HTTP/1.1\r\nHost: rebind.attacker.example:"+strings.Split(webTunnel, ":")[1]+
		"\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n")
	acted = append(acted, fmt.Sprintf("web rebound GET -> %d %q", resp.StatusCode, body))
	// (3) Kubernetes, cross-site WebSocket (no CORS for WebSockets): exec in a pod.
	resp, _, wsConn, wsr := v9Send(t, k8sTunnel, "GET /api/v1/namespaces/default/pods/web/exec?command=sh&stdin=true&stdout=true HTTP/1.1\r\nHost: "+k8sTunnel+
		"\r\nOrigin: https://evil.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+v9WSKey+
		"\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: websocket\r\n\r\n")
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The page writes stdin (channel 0) and reads stdout (channel 1):
		// WebSocket messages are readable cross-origin.
		_, _ = wsConn.Write(wsFrame(0x2, append([]byte{0}, "id\n"...), true))
		out, err := v9ReadFrame(wsr)
		acted = append(acted, fmt.Sprintf("k8s cross-site WebSocket exec -> 101 (accept %s), page read stdout %q (err %v)",
			resp.Header.Get("Sec-WebSocket-Accept"), out, err))
	} else {
		acted = append(acted, fmt.Sprintf("k8s cross-site WebSocket -> %d", resp.StatusCode))
	}
	// (3b) Web console, cross-site WebSocket to the console's terminal: the
	// console checks Origin, the gateway rewrites it to the console's own.
	resp, _, wsConn, wsr = v9Send(t, webTunnel, "GET /console/terminal HTTP/1.1\r\nHost: "+webTunnel+
		"\r\nOrigin: https://evil.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+v9WSKey+
		"\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: websocket\r\n\r\n")
	if resp.StatusCode == http.StatusSwitchingProtocols {
		_, _ = wsConn.Write(wsFrame(0x1, []byte("id\n"), true))
		out, err := v9ReadFrame(wsr)
		acted = append(acted, fmt.Sprintf("web cross-site WebSocket terminal -> 101, page read %q (err %v)", out, err))
	} else {
		acted = append(acted, fmt.Sprintf("web cross-site WebSocket terminal -> %d", resp.StatusCode))
	}
	// (4) Kubernetes, DNS-rebound read of the namespace's secrets.
	resp, body, _, _ = v9Send(t, k8sTunnel, "GET /api/v1/namespaces/default/secrets HTTP/1.1\r\nHost: rebind.attacker.example:"+strings.Split(k8sTunnel, ":")[1]+
		"\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
	acted = append(acted, fmt.Sprintf("k8s rebound GET secrets -> %d %q", resp.StatusCode, body))
	// (5) ClickHouse, cross-site form post with an empty text/plain body: the
	// statement is in the action URL's query.
	resp, _, _, _ = v9Send(t, chTunnel, "POST /?query=DROP%20TABLE%20victim HTTP/1.1\r\nHost: "+chTunnel+"\r\nOrigin: https://evil.example"+
		"\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	acted = append(acted, fmt.Sprintf("clickhouse cross-site POST -> %d", resp.StatusCode))

	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	reached := append([]string(nil), upstream...)
	mu.Unlock()
	if len(reached) > 0 {
		t.Fatalf("requests from another site (foreign Origin, or a rebound Host) reached the targets signed in as the session's account:\n  upstream: %s\n  browser: %s",
			strings.Join(reached, "\n            "), strings.Join(acted, "; "))
	}
}
