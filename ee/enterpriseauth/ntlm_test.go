// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
)

// ntlmMessage builds the minimal NTLMSSP framing the handler inspects; the
// fake helper decides on the account, not on message contents.
func ntlmMessage(kind uint32, marker string) string {
	raw := append([]byte(ntlmSignature), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(raw[8:], kind)
	raw = append(raw, []byte(marker)...)
	return base64.StdEncoding.EncodeToString(raw)
}

// fakeNTLMHelper speaks the squid-2.5-ntlmssp protocol over TCP: TT to YR,
// then AF for an authenticate message carrying "good", NA otherwise.
func fakeNTLMHelper(t *testing.T, account string) (address string, handshakes *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var count int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					verb, payload, _ := strings.Cut(strings.TrimSpace(line), " ")
					switch verb {
					case "YR":
						atomic.AddInt32(&count, 1)
						_, _ = conn.Write([]byte("TT " + ntlmMessage(2, "challenge") + "\n"))
					case "KK":
						raw, _ := base64.StdEncoding.DecodeString(payload)
						if strings.Contains(string(raw), "good") {
							_, _ = conn.Write([]byte("AF " + account + "\n"))
						} else {
							_, _ = conn.Write([]byte("NA NT_STATUS_WRONG_PASSWORD\n"))
						}
						return
					default:
						_, _ = conn.Write([]byte("BH unknown verb\n"))
						return
					}
				}
			}(conn)
		}
	}()
	return "tcp://" + ln.Addr().String(), &count
}

// A80: the handler challenges with NTLM, relays the negotiate message to the
// helper and returns its challenge, binds the handshake to the client
// connection, and admits only what the helper reports AF for; the account is
// normalized to user@DOMAIN and a pinned domain is enforced.
func TestNTLMLoginRelaysTheHandshakeToTheHelper(t *testing.T) {
	address, handshakes := fakeNTLMHelper(t, `ADLAB\alice`)
	helper, err := NTLMSocketHelper(address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v := &NTLMVerifier{Helper: helper, Domain: "ADLAB"}
	var seen auth.Claims
	handler := v.Login(func(w http.ResponseWriter, _ *http.Request, c auth.Claims) {
		seen = c
		w.WriteHeader(http.StatusNoContent)
	})
	do := func(remote, authorization string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/ntlm/login", nil)
		req.RemoteAddr = remote
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("10.0.0.1:50000", ""); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "NTLM" {
		t.Fatalf("no token = %d %q, want 401 NTLM", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	rec := do("10.0.0.1:50000", "NTLM "+ntlmMessage(1, "negotiate"))
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "NTLM "+ntlmMessage(2, "challenge")) {
		t.Fatalf("negotiate = %d %q, want the helper's challenge", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// Another connection cannot complete this connection's handshake.
	if rec := do("10.0.0.2:50000", "NTLM "+ntlmMessage(3, "good")); rec.Code != http.StatusUnauthorized || seen.Subject != "" {
		t.Fatalf("authenticate from another connection = %d, want a fresh 401", rec.Code)
	}
	if rec := do("10.0.0.1:50000", "NTLM "+ntlmMessage(3, "good")); rec.Code != http.StatusNoContent || seen.Subject != "alice@ADLAB" || seen.Issuer != "ADLAB" {
		t.Fatalf("authenticate = %d claims %+v, want alice@ADLAB admitted", rec.Code, seen)
	}
	// Refused by the helper.
	seen = auth.Claims{}
	do("10.0.0.3:50000", "NTLM "+ntlmMessage(1, "negotiate"))
	if rec := do("10.0.0.3:50000", "NTLM "+ntlmMessage(3, "bad")); rec.Code != http.StatusUnauthorized || seen.Subject != "" {
		t.Fatalf("helper NA = %d claims %+v, want 401 and no claims", rec.Code, seen)
	}
	// A completed or refused handshake is gone: a replayed authenticate restarts.
	if rec := do("10.0.0.1:50000", "NTLM "+ntlmMessage(3, "good")); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "NTLM" {
		t.Fatalf("replayed authenticate = %d %q, want a fresh challenge", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if got := atomic.LoadInt32(handshakes); got != 2 {
		t.Fatalf("helper handshakes = %d, want 2", got)
	}
	// Garbage and unknown message types never reach the helper.
	if rec := do("10.0.0.4:50000", "NTLM bm90LW50bG0="); rec.Code != http.StatusUnauthorized || atomic.LoadInt32(handshakes) != 2 {
		t.Fatalf("garbage token = %d (handshakes %d)", rec.Code, atomic.LoadInt32(handshakes))
	}

	// Domain pin and account normalization.
	for account, want := range map[string]string{`ADLAB\bob`: "bob@ADLAB", "bob@adlab": "bob@ADLAB", `OTHER\bob`: "", "": ""} {
		claims, ok := ntlmClaims(account, "ADLAB")
		if (want == "") == ok || claims.Subject != want {
			t.Fatalf("ntlmClaims(%q) = %+v %v, want subject %q", account, claims, ok, want)
		}
	}
	if claims, ok := ntlmClaims("carol", ""); !ok || claims.Subject != "carol" || claims.Issuer != "" {
		t.Fatalf("unqualified account without a pin = %+v %v", claims, ok)
	}
}
