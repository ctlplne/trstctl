// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// consoleState belongs to a whole gateway session, across its TCP connections.
// Minting has one outcome; an ambiguous failure is never retried blindly.
type consoleState struct {
	mu        sync.Mutex
	attempted bool
	token     *secret.Buffer
	expires   time.Time
	err       error
}

func consoleStateForAttempt(attempt int) *consoleState {
	if attempt > 1 {
		return &consoleState{attempted: true, err: errors.New("accessgateway: original console handoff state was lost; open a new approved session")}
	}
	return &consoleState{}
}

func (s *consoleState) destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != nil {
		s.token.Destroy()
		s.token = nil
	}
	s.err = secret.ErrDestroyed
	s.attempted = true
}
func (s *consoleState) page(ctx context.Context, deadline time.Time, mint func(context.Context) (*secret.Buffer, error), render func([]byte) (*secret.Buffer, error)) (*secret.Buffer, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := !s.attempted
	if first {
		s.attempted = true
		s.expires = earliest(deadline, time.Now().Add(14*time.Minute))
		s.token, s.err = mint(ctx)
	}
	if s.err != nil {
		return nil, first, s.err
	}
	if s.token == nil || !time.Now().Before(s.expires) {
		return nil, first, errors.New("accessgateway: console handoff expired")
	}
	var page *secret.Buffer
	err := s.token.Use(func(raw []byte) error { var err error; page, err = render(raw); return err })
	return page, first, err
}

func mintConsoleToken(ctx context.Context, material *awsGatewayMaterial, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error)) (*secret.Buffer, error) {
	if !time.Now().Before(earliest(intent.ExpiresAt, material.expiration)) {
		return nil, errors.New("accessgateway: console session expired")
	}
	var held *secret.Buffer
	err := material.use(func(c awssignin.Credentials) error {
		raw, err := json.Marshal(struct {
			ID    secret.JSONBytes `json:"sessionId"`
			Key   secret.JSONBytes `json:"sessionKey"`
			Token secret.JSONBytes `json:"sessionToken"`
		}{c.AccessKeyID, c.SecretAccessKey, c.SessionToken}) // #nosec G117 -- native federation Session grant; scratch wiped and request serialized from locked bytes (CWE-200)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		form := make([]byte, 0, len(raw)*3+40)
		form = append(form, []byte("Action=getSigninToken&Session=")...)
		form = appendOAuthFormValue(form, raw)
		defer secret.Wipe(form)
		if len(form) > 256<<10 {
			return errors.New("accessgateway: console grant exceeds its bound")
		}
		held, err = secret.NewFrom(form)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer held.Destroy()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, intent.Console.FederationEndpoint, nil)
	if err != nil {
		return nil, errors.New("accessgateway: invalid federation endpoint")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response *http.Response
	err = held.Use(func(form []byte) error {
		var err error
		response, err = credentialHTTPRoundTrip(ctx, request, form, httpUpstream{URL: intent.Console.FederationEndpoint}, earliest(intent.ExpiresAt, time.Now().Add(30*time.Second)), dial, nil)
		return err
	})
	if err != nil {
		return nil, errors.New("accessgateway: console mint outcome unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	defer secret.Wipe(raw)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, errors.New("accessgateway: federation did not return a sign-in token")
	}
	return parseConsoleToken(raw)
}

func parseConsoleToken(raw []byte) (*secret.Buffer, error) {
	var result struct {
		Value secret.JSONBytes `json:"SigninToken"`
	}
	defer func() { secret.Wipe(result.Value) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &result) != nil || len(result.Value) == 0 || len(result.Value) > 32<<10 || !validOAuthBearer(result.Value) {
		return nil, errors.New("accessgateway: federation did not return a bounded sign-in token")
	}
	return secret.NewFrom(result.Value)
}

func consoleProof(material *awsGatewayMaterial, intent SessionIntent, host string, now time.Time) ([]byte, error) {
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(nonce)
	raw := make([]byte, 24, 56)
	defer func() { secret.Wipe(raw) }()
	seconds := earliest(intent.ExpiresAt, now.Add(time.Minute)).Unix()
	if seconds < 0 {
		return nil, errors.New("accessgateway: invalid console proof epoch")
	}
	binary.BigEndian.PutUint64(raw[:8], uint64(seconds))
	copy(raw[8:], nonce)
	claim := append([]byte(intent.SessionID+"\n"+host+"\n"), raw...)
	defer secret.Wipe(claim)
	err = material.key.Use(func(key []byte) error {
		mac := crypto.HMACSHA256(key, claim)
		raw = append(raw, mac...)
		secret.Wipe(mac)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.AppendEncode(nil, raw), nil
}
func validConsoleProof(material *awsGatewayMaterial, intent SessionIntent, host string, proof []byte, now time.Time) bool {
	if len(proof) > 128 {
		return false
	}
	raw, err := base64.RawURLEncoding.AppendDecode(nil, proof)
	defer secret.Wipe(raw)
	if err != nil || len(raw) != 56 {
		return false
	}
	encodedExpiry := binary.BigEndian.Uint64(raw[:8])
	if encodedExpiry > math.MaxInt64 {
		return false
	}
	expiry := int64(encodedExpiry)
	if expiry <= now.Unix() || expiry > intent.ExpiresAt.Unix() || expiry > now.Add(61*time.Second).Unix() {
		return false
	}
	claim := append([]byte(intent.SessionID+"\n"+host+"\n"), raw[:24]...)
	defer secret.Wipe(claim)
	valid := false
	_ = material.key.Use(func(key []byte) error {
		mac := crypto.HMACSHA256(key, claim)
		valid = crypto.ConstantTimeEqual(mac, raw[24:])
		secret.Wipe(mac)
		return nil
	})
	return valid
}

// lockedConsoleHTML escapes private form values directly into a locked page.
// parts are public HTML; the private value appears between each adjacent pair.
func lockedConsoleHTML(parts []string, value []byte) (*secret.Buffer, error) {
	escaped := 0
	for _, b := range value {
		switch b {
		case '&':
			escaped += 5
		case '<', '>':
			escaped += 4
		case '\'', '"':
			escaped += 5
		default:
			escaped++
		}
	}
	size := escaped * (len(parts) - 1)
	for _, part := range parts {
		size += len(part)
	}
	if len(parts) < 2 || size > 256<<10 {
		return nil, errors.New("accessgateway: console page exceeds its bound")
	}
	page, err := secret.New(size)
	if err != nil {
		return nil, err
	}
	err = page.Use(func(raw []byte) error {
		out := raw[:0]
		for i, part := range parts {
			out = append(out, part...)
			if i == len(parts)-1 {
				continue
			}
			for _, b := range value {
				switch b {
				case '&':
					out = append(out, []byte("&amp;")...)
				case '<':
					out = append(out, []byte("&lt;")...)
				case '>':
					out = append(out, []byte("&gt;")...)
				case '\'':
					out = append(out, []byte("&#39;")...)
				case '"':
					out = append(out, []byte("&#34;")...)
				default:
					out = append(out, b)
				}
			}
		}
		if len(out) != size {
			return errors.New("accessgateway: console page serialization mismatch")
		}
		return nil
	})
	if err != nil {
		page.Destroy()
		return nil, err
	}
	return page, nil
}
func consoleForm(raw []byte) (map[string][]byte, error) {
	fields := map[string][]byte{}
	bad := func() (map[string][]byte, error) {
		for _, value := range fields {
			secret.Wipe(value)
		}
		return nil, errors.New("accessgateway: invalid console form")
	}
	for _, field := range bytes.Split(raw, []byte("&")) {
		pair := bytes.SplitN(field, []byte("="), 2)
		if len(pair) != 2 || (!bytes.Equal(pair[0], []byte("proof")) && !bytes.Equal(pair[0], []byte("idempotency_key"))) {
			return bad()
		}
		name := string(pair[0])
		if _, ok := fields[name]; ok {
			return bad()
		}
		value := make([]byte, 0, len(pair[1]))
		fields[name] = value
		for i := 0; i < len(pair[1]); i++ {
			switch pair[1][i] {
			case '+':
				value = append(value, ' ')
			case '%':
				if i+2 >= len(pair[1]) {
					fields[name] = value
					return bad()
				}
				var one [1]byte
				if _, err := hex.Decode(one[:], pair[1][i+1:i+3]); err != nil {
					fields[name] = value
					return bad()
				}
				value = append(value, one[0])
				i += 2
			default:
				value = append(value, pair[1][i])
			}
			fields[name] = value
		}
	}
	if len(fields) != 2 {
		return bad()
	}
	return fields, nil
}
func consoleLocalHost(host string) bool {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

func serveAWSConsole(ctx context.Context, client net.Conn, raw []byte, intent SessionIntent, state *consoleState, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	if intent.Console == nil || intent.Console.Validate(true) != nil || state == nil {
		secret.Wipe(raw)
		return errors.New("accessgateway: missing validated console state")
	}

	material, err := parseAWSGatewayMaterial(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer material.destroy()
	intent.ExpiresAt = earliest(intent.ExpiresAt, material.expiration)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' "+intent.Console.FederationEndpoint)
		if !consoleLocalHost(r.Host) || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("Upgrade") != "" || !time.Now().Before(intent.ExpiresAt) {
			http.Error(w, "console request is outside this session", http.StatusForbidden)
			return
		}
		var page *secret.Buffer
		var err error
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			var proof []byte
			proof, err = consoleProof(material, intent, r.Host, time.Now())
			if err != nil {
				http.Error(w, "console preparation unavailable", http.StatusServiceUnavailable)
				return
			}
			defer secret.Wipe(proof)
			page, err = lockedConsoleHTML([]string{"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Native AWS console</title><h1>Open the native AWS console</h1><p>Target: " + html.EscapeString(intent.TargetID) + "; role: " + html.EscapeString(intent.ConsoleRole) + ".</p><p>This recording covers the handoff. Native console activity and browser cookies remain outside the gateway. Closing this tunnel does not log the browser out.</p><form method=\"post\" action=\"/handoff\"><input type=\"hidden\" name=\"proof\" value=\"", "\"><input type=\"hidden\" name=\"idempotency_key\" value=\"", "\"><button>Prepare AWS sign-in</button></form></html>"}, proof)
		case r.Method == http.MethodPost && r.URL.Path == "/handoff":
			mediaType, params, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if r.Header.Get("Origin") != "http://"+r.Host || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") || mediaErr != nil || mediaType != "application/x-www-form-urlencoded" || len(params) > 1 || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") {
				http.Error(w, "console sign-in requires its same-origin review page", http.StatusForbidden)
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(r.Body, 4097))
			defer secret.Wipe(body)
			if readErr != nil || len(body) > 4096 {
				w.Header().Set("Connection", "close")
				http.Error(w, "console form exceeds its bound", http.StatusRequestEntityTooLarge)
				return
			}
			fields, formErr := consoleForm(body)
			if formErr != nil {
				http.Error(w, "console review form is invalid", http.StatusForbidden)
				return
			}
			defer func() {
				for _, value := range fields {
					secret.Wipe(value)
				}
			}()
			headerKey := r.Header.Get("Idempotency-Key")
			if headerKey != "" && !crypto.ConstantTimeEqual([]byte(headerKey), fields["idempotency_key"]) {
				http.Error(w, "console idempotency key does not match the reviewed form", http.StatusConflict)
				return
			}
			if !crypto.ConstantTimeEqual(fields["proof"], fields["idempotency_key"]) || !validConsoleProof(material, intent, r.Host, fields["proof"], time.Now()) {
				http.Error(w, "console review expired or does not match", http.StatusForbidden)
				return
			}
			var first bool
			page, first, err = state.page(r.Context(), intent.ExpiresAt, func(ctx context.Context) (*secret.Buffer, error) {
				return mintConsoleToken(ctx, material, intent, dial)
			}, func(token []byte) (*secret.Buffer, error) {
				return lockedConsoleHTML([]string{"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>AWS sign-in handoff</title><p>Continue to AWS. Activity there is outside this gateway recording.</p><form method=\"post\" action=\"" + html.EscapeString(intent.Console.FederationEndpoint) + "\"><input type=\"hidden\" name=\"Action\" value=\"login\"><input type=\"hidden\" name=\"Issuer\" value=\"" + html.EscapeString("http://"+r.Host+"/") + "\"><input type=\"hidden\" name=\"Destination\" value=\"" + html.EscapeString(intent.Console.Destination) + "\"><input type=\"hidden\" name=\"SigninToken\" value=\"", "\"><button>Open AWS console</button></form></html>"}, token)
			})
			if rec != nil {
				kind := "handoff_replayed"
				if first {
					kind = "handoff_prepared"
				}
				if err != nil {
					kind = "handoff_unavailable"
				}
				rec.event("aws-console", kind, "native_console_handoff: "+kind+"; native activity is outside gateway capture", 0)
			}
		default:
			http.Error(w, "console request is not supported", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "console handoff outcome unavailable; reopen an approved session instead of retrying credentials", http.StatusServiceUnavailable)
			return
		}
		defer page.Destroy()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Use(func(body []byte) error { _, err := w.Write(body); return err })
	})
	listener := newOneConnListener(client)
	var serving sync.WaitGroup
	server := &http.Server{Handler: handler, MaxHeaderBytes: 16 << 10, ReadHeaderTimeout: 15 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			serving.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			serving.Done()
		}
	}}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	serving.Wait()
	return nil
}
