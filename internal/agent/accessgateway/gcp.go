// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type gcpGatewayMaterial struct {
	key         *secret.Buffer
	id, subject string
}

func parseGCPGatewayMaterial(raw []byte, subject string) (*gcpGatewayMaterial, error) {
	var c struct {
		Type    string           `json:"type"`
		ID      string           `json:"private_key_id"`
		Subject string           `json:"client_email"`
		Key     secret.JSONBytes `json:"private_key"`
	}
	defer func() { secret.Wipe(c.Key) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || c.Type != "service_account" || c.Subject != subject || c.ID == "" || len(c.ID) > 256 || len(c.Key) == 0 {
		return nil, errors.New("accessgateway: invalid Google Cloud credential binding")
	}
	der, err := crypto.PublicKeyDERFromPEMKey(c.Key)
	if err != nil {
		return nil, errors.New("accessgateway: invalid Google Cloud key")
	}
	pub, err := crypto.ParsePublicKeyPEM(crypto.MarshalPublicKeyPEM(der))
	if err != nil || (pub.Algorithm != crypto.RSA2048 && pub.Algorithm != crypto.RSA3072 && pub.Algorithm != crypto.RSA4096) {
		return nil, errors.New("accessgateway: Google Cloud requires an RSA key")
	}
	held, err := secret.NewFrom(c.Key)
	if err != nil {
		return nil, err
	}
	return &gcpGatewayMaterial{key: held, id: c.ID, subject: c.Subject}, nil
}

func gcpAssertion(material *gcpGatewayMaterial, intent SessionIntent, now time.Time) ([]byte, error) {
	expires := earliest(intent.ExpiresAt, now.Add(time.Hour))
	if expires.Unix() <= now.Unix() {
		return nil, errors.New("accessgateway: OAuth session expired")
	}
	var assertion []byte
	err := material.key.Use(func(key []byte) error {
		var err error
		assertion, err = crypto.SignJWTWithPEMKeyBytes(key, material.id, map[string]any{"iss": material.subject, "scope": strings.Join(intent.OAuthScopes, " "), "aud": intent.OAuthTokenEndpoint, "iat": now.Unix(), "exp": expires.Unix()})
		return err
	})
	return assertion, err
}

func gcpExchange(ctx context.Context, material *gcpGatewayMaterial, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error)) (*secret.Buffer, time.Time, error) {
	assertion, err := gcpAssertion(material, intent, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	form := append([]byte("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="), assertion...)
	secret.Wipe(assertion)
	held, err := secret.NewFrom(form)
	secret.Wipe(form)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer held.Destroy()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, intent.OAuthTokenEndpoint, nil)
	if err != nil {
		return nil, time.Time{}, errors.New("accessgateway: invalid OAuth endpoint")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response *http.Response
	// The fixed token endpoint, never credential token_uri or client input, is the audience and destination.
	started := time.Now()
	err = held.Use(func(body []byte) error {
		var err error
		response, err = credentialHTTPRoundTrip(ctx, request, body, httpUpstream{URL: intent.OAuthTokenEndpoint}, earliest(intent.ExpiresAt, started.Add(30*time.Second)), dial, nil)
		return err
	})
	if err != nil {
		return nil, time.Time{}, errors.New("accessgateway: OAuth token exchange unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	defer secret.Wipe(raw)
	if err != nil || len(raw) > 64<<10 || response.StatusCode != http.StatusOK {
		return nil, time.Time{}, errors.New("accessgateway: OAuth grant rejected; check key propagation and approved scopes")
	}
	var token struct {
		Value   secret.JSONBytes `json:"access_token"`
		Type    string           `json:"token_type"`
		Expires int64            `json:"expires_in"`
	}
	defer func() { secret.Wipe(token.Value) }()
	if json.Unmarshal(raw, &token) != nil || !strings.EqualFold(token.Type, "Bearer") || token.Expires <= 0 || token.Expires > 3600 || len(token.Value) == 0 || len(token.Value) > 32<<10 || !validOAuthBearer(token.Value) {
		return nil, time.Time{}, errors.New("accessgateway: invalid bounded OAuth token response")
	}
	// The gateway stops using the token at its own deadline. Native validity is unchanged.
	expires := earliest(intent.ExpiresAt, started.Add(time.Duration(token.Expires)*time.Second))
	value, err := secret.NewFrom(token.Value)
	return value, expires, err
}

func recordGCP(rec *connRecorder, material *gcpGatewayMaterial, token *secret.Buffer, kind string, head []byte, size int) {
	if rec == nil {
		return
	}
	var masked []byte
	err := material.key.Use(func(key []byte) error {
		return token.Use(func(value []byte) error {
			masked = maskCredentialHead(head, size, key, value)
			return nil
		})
	})
	if err != nil {
		return
	}
	defer secret.Wipe(masked)
	rec.event("gcp", kind, "gcp: "+boundedHTTPText(masked, max(size, len(masked))), 0)
}

func serveGCP(ctx context.Context, client net.Conn, raw []byte, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	material, err := parseGCPGatewayMaterial(raw, intent.OAuthSubject)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer material.key.Destroy()
	var token *secret.Buffer
	var tokenExpires time.Time
	defer func() {
		if token != nil {
			token.Destroy()
		}
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
			http.Error(w, "this cloud account forwards API requests only", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, snowflakeRequestBytes+1))
		defer secret.Wipe(body)
		if err != nil || len(body) > snowflakeRequestBytes {
			w.Header().Set("Connection", "close")
			http.Error(w, "cloud request exceeds its bound", http.StatusRequestEntityTooLarge)
			return
		}
		if !time.Now().Before(intent.ExpiresAt) {
			http.Error(w, "cloud session expired", http.StatusForbidden)
			return
		}
		if token == nil || !time.Now().Before(tokenExpires) {
			if token != nil {
				token.Destroy()
				token = nil
			}
			token, tokenExpires, err = gcpExchange(r.Context(), material, intent, dial)
			if err != nil {
				http.Error(w, "OAuth grant unavailable; verify key propagation, token endpoint and approved scopes, then retry", http.StatusServiceUnavailable)
				return
			}
		}
		// A client cannot substitute a different bearer/API key through query parameters.
		query := r.URL.Query()
		for name := range query {
			switch strings.ToLower(name) {
			case "access_token", "oauth_token", "key", "api_key":
				query.Del(name)
			}
		}
		r.URL.RawQuery = query.Encode()
		recordGCP(rec, material, token, "request", []byte(r.Method+" "+r.URL.Path), len(r.Method)+1+len(r.URL.Path))
		if len(body) > 0 {
			recordGCP(rec, material, token, "body", body[:min(len(body), clickhouseRecordBytes)], len(body))
		}
		response, err := credentialHTTPRoundTrip(r.Context(), r, body, httpUpstream{URL: intent.UpstreamURL, CAPEM: intent.UpstreamCAPEM, ServerName: intent.UpstreamServerName}, intent.ExpiresAt, dial, func(out *http.Request) (*secret.Buffer, error) {
			out.Header.Del("X-Goog-Api-Key")
			out.Header.Del("X-Goog-Iam-Authorization-Token")
			out.Header.Del("X-Serverless-Authorization")
			var headers []byte
			err := token.Use(func(value []byte) error { headers = append([]byte("Authorization: Bearer "), value...); return nil })
			if err != nil {
				return nil, err
			}
			defer secret.Wipe(headers)
			return secret.NewFrom(headers)
		})
		if err != nil {
			http.Error(w, "the access gateway could not reach the cloud target", http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		if rec != nil {
			rec.event("gcp", "status", strconv.Itoa(response.StatusCode), 0)
			response.Body = &recordedBody{ReadCloser: response.Body, done: func(head []byte, size int) { recordGCP(rec, material, token, "response", head, size) }}
		}
		for name, values := range response.Header {
			if name == "Connection" || name == "Transfer-Encoding" || name == "Content-Length" || name == "X-Goog-Iam-Authorization-Token" {
				continue
			}
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	listener := newOneConnListener(client)
	var serving sync.WaitGroup
	server := &http.Server{Handler: handler, MaxHeaderBytes: 64 << 10, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }, ConnState: func(_ net.Conn, state http.ConnState) {
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

// RFC 6750 b64token: header injection and arbitrary controls are refused before
// any bearer bytes are serialized. Padding is allowed only at the end.
func validOAuthBearer(raw []byte) bool {
	padding := false
	for _, b := range raw {
		if b == '=' {
			padding = true
			continue
		}
		allowed := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~' || b == '+' || b == '/'
		if padding || !allowed {
			return false
		}
	}
	return len(raw) > 0 && raw[0] != '='
}
