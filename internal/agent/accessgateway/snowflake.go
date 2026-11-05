// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const snowflakeRequestBytes = 1 << 20

var snowflakeSQLPath = regexp.MustCompile(`^/api/v2/statements/?$|^/api/v2/statements/[A-Za-z0-9_-]+(/cancel)?/?$`)

type snowflakeCredential struct {
	Account    string           `json:"account"`
	User       string           `json:"user"`
	PrivateKey secret.JSONBytes `json:"private_key"`
}

// parseSnowflakeCredential accepts only a bounded provider-issued key envelope.
func parseSnowflakeCredential(raw []byte) (snowflakeCredential, error) {
	var credential snowflakeCredential
	if len(raw) > 64<<10 || json.Unmarshal(raw, &credential) != nil || credential.Account == "" || credential.User == "" || len(credential.PrivateKey) == 0 {
		secret.Wipe(credential.PrivateKey)
		return snowflakeCredential{}, errors.New("accessgateway: invalid Snowflake credential")
	}
	return credential, nil
}

func snowflakeJWT(account, user string, key []byte, now, deadline time.Time) ([]byte, error) {
	if !deadline.After(now) {
		return nil, errors.New("accessgateway: Snowflake session expired")
	}
	der, err := crypto.PublicKeyDERFromPEMKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.ParsePublicKeyPEM(crypto.MarshalPublicKeyPEM(der))
	if err != nil || (pub.Algorithm != crypto.RSA2048 && pub.Algorithm != crypto.RSA3072 && pub.Algorithm != crypto.RSA4096) {
		return nil, errors.New("accessgateway: Snowflake requires an RSA key")
	}
	expiry := now.Add(59 * time.Minute)
	if deadline.Before(expiry) {
		expiry = deadline
	}
	qualified := strings.ToUpper(account) + "." + strings.ToUpper(user)
	fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(crypto.SHA256Sum(der))
	return crypto.SignJWTWithPEMKeyBytes(key, "", map[string]any{"iss": qualified + "." + fingerprint, "sub": qualified, "iat": now.Unix(), "exp": expiry.Unix()})
}

// snowflakeRoundTrip writes the bearer credential directly as bytes. It never
// places that secret in http.Header's immutable string storage.
func snowflakeRoundTrip(ctx context.Context, request *http.Request, body []byte, upstream httpUpstream, account, user string, key *secret.Buffer, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
	target, err := url.Parse(upstream.URL)
	if err != nil || target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, errors.New("accessgateway: invalid Snowflake upstream")
	}
	if target.Scheme == "http" {
		host := target.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("accessgateway: Snowflake requires verified HTTPS")
		}
	}
	address := target.Host
	if target.Port() == "" {
		port := "443"
		if target.Scheme == "http" {
			port = "80"
		}
		address = net.JoinHostPort(target.Hostname(), port)
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if target.Scheme == "https" {
		name := upstream.ServerName
		if name == "" {
			name = target.Hostname()
		}
		conn, err = mtls.VerifyClientConnection(ctx, conn, name, []byte(upstream.CAPEM))
		if err != nil {
			return nil, err
		}
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	success := false
	defer func() {
		if !success {
			stop()
			_ = conn.Close()
		}
	}()
	out := request.Clone(ctx)
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.User = nil
	out.URL.Fragment = ""
	out.Host = target.Host
	out.RequestURI = ""
	out.Close = true
	out.TransferEncoding = nil
	out.Trailer = nil
	out.GetBody = nil
	out.ContentLength = int64(len(body))
	out.Body = io.NopCloser(bytes.NewReader(body))
	for _, name := range strings.Split(out.Header.Get("Connection"), ",") {
		out.Header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Snowflake-Authorization-Token-Type", "Cookie", "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Idempotency-Key", "X-Idempotency-Key", "Expect"} {
		out.Header.Del(name)
	}
	out.Header.Set("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
	var wire bytes.Buffer
	if err := out.Write(&wire); err != nil {
		return nil, err
	}
	defer secret.Wipe(wire.Bytes())
	split := bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))
	if split < 0 {
		return nil, errors.New("accessgateway: invalid serialized SQL API request")
	}
	err = key.Use(func(private []byte) error {
		token, err := snowflakeJWT(account, user, private, time.Now(), deadline)
		if err != nil {
			return err
		}
		defer secret.Wipe(token)
		held, err := secret.NewFrom(token)
		if err != nil {
			return err
		}
		defer held.Destroy()
		return held.Use(func(auth []byte) error {
			parts := net.Buffers{wire.Bytes()[:split], []byte("\r\nAuthorization: Bearer "), auth, wire.Bytes()[split:]}
			_, err := parts.WriteTo(conn)
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	var response *http.Response
	for interim := 0; ; interim++ {
		response, err = http.ReadResponse(reader, out)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 200 {
			break
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusSwitchingProtocols || interim >= 7 {
			return nil, errors.New("accessgateway: unsupported SQL API interim response")
		}
	}
	limited.N = 1 << 62

	response.Body = &snowflakeResponseBody{ReadCloser: response.Body, conn: conn, stop: stop}
	response.Header.Del("Set-Cookie")
	response.Header.Del("Authorization")
	success = true
	return response, nil
}

type snowflakeResponseBody struct {
	io.ReadCloser
	conn net.Conn
	stop func() bool
}

func (b *snowflakeResponseBody) Close() error {
	b.stop()
	_ = b.conn.Close()
	return b.ReadCloser.Close()
}

func serveSnowflake(ctx context.Context, client net.Conn, raw []byte, upstream httpUpstream, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	credential, err := parseSnowflakeCredential(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	key, err := secret.NewFrom(credential.PrivateKey)
	secret.Wipe(credential.PrivateKey)
	if err != nil {
		return err
	}
	defer key.Destroy()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" || !snowflakeSQLPath.MatchString(r.URL.Path) || (r.Method != http.MethodGet && r.Method != http.MethodPost) || r.Header.Get("Upgrade") != "" {
			http.Error(w, "only the Snowflake SQL API is supported", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, snowflakeRequestBytes+1))
		defer secret.Wipe(body)
		if err != nil || len(body) > snowflakeRequestBytes {
			http.Error(w, "SQL API request exceeds the bound", http.StatusRequestEntityTooLarge)
			return
		}
		if rec != nil {
			rec.event("snowflake", "request", "snowflake: "+r.Method+" "+r.URL.Path+" body="+boundedHTTPText(body, len(body)), 0)
		}
		response, err := snowflakeRoundTrip(r.Context(), r, body, upstream, credential.Account, credential.User, key, deadline, dial)
		if err != nil {
			http.Error(w, "the access gateway could not reach the target", http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		if rec != nil {
			response.Body = &recordedBody{ReadCloser: response.Body, done: func(head []byte, size int) {
				rec.event("result", "response", strconv.Itoa(response.StatusCode)+": "+boundedHTTPText(head, size), 0)
			}}
		}
		for name, values := range response.Header {
			if name == "Connection" || name == "Transfer-Encoding" || name == "Content-Length" {
				continue
			}
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	listener := newOneConnListener(client)
	server := &http.Server{Handler: handler, MaxHeaderBytes: 64 << 10, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	return nil
}
