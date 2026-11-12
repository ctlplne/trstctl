// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"context"
	"crypto/md5" // #nosec G501 -- the test recomputes PostgreSQL's md5 password exchange (CWE-327)
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
)

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
func fakePostgres(t *testing.T, authCode uint32, sslAnswer byte, password chan<- []byte, serverTLS ...*tls.Config) string {
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
			switch {
			case sslAnswer == 'S' && len(serverTLS) > 0:
				// The rest of the exchange runs inside TLS.
				server := tls.Server(conn, serverTLS[0])
				if err := server.Handshake(); err != nil {
					return
				}
				conn = server
			case sslAnswer != 'N':
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

// TestSignInVerifiesThePrivateCATheSessionCarriesA256L1 is A256-L1: a
// database behind a private CA verifies against the CA the session carries,
// with no root file on the gateway's host, and that CA takes precedence over
// a DSN's sslrootcert (a path on the control plane's host). Without it the
// handshake does not verify; a CA with no certificate is refused.
func TestSignInVerifiesThePrivateCATheSessionCarriesA256L1(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("db.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dsn := func(addr, extra string) []byte {
		host, port, _ := net.SplitHostPort(addr)
		return []byte("host=" + host + " port=" + port + " user=u password=p dbname=d sslmode=verify-full" + extra)
	}
	carried := Options{RootCAPEM: caPEM, ServerName: "db.private.test"}
	for name, extra := range map[string]string{
		"no root file":                 "",
		"a control-plane path ignored": " sslrootcert=/nonexistent/on/this/host/root.pem",
	} {
		session, err := SignIn(ctx, dsn(fakePostgres(t, 0, 'S', nil, serverTLS), extra), carried)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := session.Conn.(*tls.Conn); !ok || session.ProcessID != 7 {
			t.Fatalf("%s: session = %+v", name, session)
		}
		_ = session.Conn.Close()
	}
	if _, err := SignIn(ctx, dsn(fakePostgres(t, 0, 'S', nil, serverTLS), ""), Options{}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a private CA without the carried CA = %v, want unverified", err)
	}
	if _, err := SignIn(ctx, dsn(fakePostgres(t, 0, 'S', nil, serverTLS), ""), Options{RootCAPEM: []byte("not a certificate"), ServerName: "db.private.test"}); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Fatalf("a carried CA with no certificate = %v", err)
	}
}
