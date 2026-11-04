// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"context"
	"crypto/md5" // #nosec G501 -- the test recomputes PostgreSQL's md5 password exchange (CWE-327)
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// RFC 7677 section 3's example exchange (user "user", password "pencil").
func TestSCRAMSHA256MatchesRFC7677(t *testing.T) {
	c := newSCRAMClient("user", []byte("pencil"), "rOprNGfwEbeRWgbNEkqO")
	if got := string(c.firstMessage()); got != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client-first = %q", got)
	}
	final, err := c.finalMessage([]byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="; string(final) != want {
		t.Fatalf("client-final = %q, want %q", final, want)
	}
	if err := c.verifyServer([]byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")); err != nil {
		t.Fatalf("server signature: %v", err)
	}
	if err := c.verifyServer([]byte("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")); err == nil {
		t.Fatal("a wrong server signature was accepted")
	}
	if _, err := newSCRAMClient("", []byte("pencil"), "abc").finalMessage([]byte("r=xyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err == nil {
		t.Fatal("a server nonce that does not extend the client's was accepted")
	}
}

func TestParseDSNKeepsThePasswordInBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		dsn                                  string
		host, port, user, password, db, mode string
	}{
		"uri": {"postgres://pam_ab12:p%40ss%3Aw0rd@db.internal:6432/orders?sslmode=verify-full&application_name=x",
			"db.internal", "6432", "pam_ab12", "p@ss:w0rd", "orders", "verify-full"},
		"uri ipv6 default port": {"postgresql://u:pw@[::1]/db", "::1", "5432", "u", "pw", "db", "prefer"},
		"keywords": {`host=10.0.0.5 port=5433 user=pam_cd34 password=s3cr\\et dbname=orders sslmode=disable`,
			"10.0.0.5", "5433", "pam_cd34", `s3cr\et`, "orders", "disable"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDSN([]byte(tc.dsn))
			if err != nil {
				t.Fatal(err)
			}
			if got.Host != tc.host || got.Port != tc.port || got.User != tc.user || got.Database != tc.db || got.SSLMode != tc.mode {
				t.Fatalf("parsed %+v", got)
			}
			if string(got.Password) != tc.password {
				t.Fatalf("password = %q", got.Password)
			}
			got.Wipe()
			for _, b := range got.Password {
				if b != 0 {
					t.Fatal("Wipe left password bytes")
				}
			}
		})
	}
	quoted, err := ParseDSN([]byte(`host=h user=u password='a \'b\' c' dbname=d`))
	if err != nil || string(quoted.Password) != "a 'b' c" {
		t.Fatalf("quoted password = %q, %v", quoted.Password, err)
	}
	for _, bad := range []string{"host=a,b user=u dbname=d", "host=/var/run/postgresql user=u", "postgres://u:p@h:99999/d", "host=h password='open", "postgres://u:%zz@h/d"} {
		if _, err := ParseDSN([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// fakePostgres answers one connection with the given authentication request,
// records the password message it gets, and after it sends the ready
// sequence.
func fakePostgres(t *testing.T, authCode uint32, sslAnswer byte, password chan<- []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		head := make([]byte, 8)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		if binary.BigEndian.Uint32(head[4:]) == sslRequestCode {
			_, _ = conn.Write([]byte{sslAnswer})
			if sslAnswer != 'N' {
				return
			}
			if _, err := io.ReadFull(conn, head); err != nil {
				return
			}
		}
		rest := make([]byte, binary.BigEndian.Uint32(head)-8)
		_, _ = io.ReadFull(conn, rest)
		send := func(kind byte, body []byte) {
			msg := append([]byte{kind}, binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))...) // #nosec G115 -- a fake server's messages are a few bytes (CWE-190)
			_, _ = conn.Write(append(msg, body...))
		}
		request := binary.BigEndian.AppendUint32(nil, authCode)
		if authCode == 5 {
			request = append(request, 1, 2, 3, 4)
		}
		send('R', request)
		if authCode != 0 {
			header := make([]byte, 5)
			if _, err := io.ReadFull(conn, header); err != nil || header[0] != 'p' {
				return
			}
			body := make([]byte, binary.BigEndian.Uint32(header[1:])-4)
			_, _ = io.ReadFull(conn, body)
			password <- body
			send('R', binary.BigEndian.AppendUint32(nil, 0))
		}
		send('S', []byte("server_version\x0017.0\x00"))
		send('K', []byte{0, 0, 0, 7, 0, 0, 0, 9})
		send('Z', []byte{'I'})
	}()
	return ln.Addr().String()
}

func TestSignInAnswersTheServersPasswordRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dsn := func(addr, extra string) []byte {
		host, port, _ := net.SplitHostPort(addr)
		return []byte("host=" + host + " port=" + port + " user=u password=p dbname=d" + extra)
	}
	session, err := SignIn(ctx, dsn(fakePostgres(t, 0, 'N', nil), ""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Conn.Close() }()
	if session.ProcessID != 7 || session.SecretKey != 9 || session.TxStatus != 'I' || len(session.Parameters) != 1 || session.Parameters[0][1] != "17.0" {
		t.Fatalf("session = %+v", session)
	}
	for code, want := range map[uint32]string{
		3: "p\x00",
		// md5(hex(md5("pu")) || 01020304), as PostgreSQL computes it.
		5: "md5" + md5Hex(md5Hex("pu")+"\x01\x02\x03\x04") + "\x00",
	} {
		got := make(chan []byte, 1)
		s, err := SignIn(ctx, dsn(fakePostgres(t, code, 'N', got), " sslmode=disable"), Options{})
		if err != nil {
			t.Fatalf("method %d: %v", code, err)
		}
		_ = s.Conn.Close()
		if msg := string(<-got); msg != want {
			t.Errorf("method %d password message = %q, want %q", code, msg, want)
		}
	}
	// Kerberos is refused, and sslmode=require is TLS or nothing.
	if _, err := SignIn(ctx, dsn(fakePostgres(t, 2, 'N', nil), " sslmode=disable"), Options{}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("Kerberos sign-in = %v, want refused", err)
	}
	if _, err := SignIn(ctx, dsn(fakePostgres(t, 0, 'N', nil), " sslmode=require"), Options{}); err == nil || !strings.Contains(err.Error(), "offers none") {
		t.Fatalf("require without TLS = %v", err)
	}
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 -- the test recomputes PostgreSQL's md5 password exchange (CWE-327)
	return hex.EncodeToString(sum[:])
}
