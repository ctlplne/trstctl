// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type awsGatewayMaterial struct {
	id, key, token *secret.Buffer
	expiration     time.Time
}

func parseAWSGatewayMaterial(raw []byte) (*awsGatewayMaterial, error) {
	var decoded struct {
		AccessKeyID     secret.JSONBytes `json:"access_key_id"`
		SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
		SessionToken    secret.JSONBytes `json:"session_token"`
		Expiration      time.Time        `json:"expiration"`
	}
	defer func() {
		secret.Wipe(decoded.AccessKeyID)
		secret.Wipe(decoded.SecretAccessKey)
		secret.Wipe(decoded.SessionToken)
	}()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &decoded) != nil || len(decoded.AccessKeyID) == 0 || len(decoded.AccessKeyID) > 256 || len(decoded.SecretAccessKey) == 0 || len(decoded.SecretAccessKey) > 1024 || len(decoded.SessionToken) == 0 || len(decoded.SessionToken) > 32<<10 || decoded.Expiration.IsZero() {
		return nil, errors.New("accessgateway: invalid bounded AWS STS credential")
	}
	material := &awsGatewayMaterial{expiration: decoded.Expiration}
	var err error
	if material.id, err = secret.NewFrom(decoded.AccessKeyID); err != nil {
		return nil, err
	}
	if material.key, err = secret.NewFrom(decoded.SecretAccessKey); err != nil {
		material.destroy()
		return nil, err
	}
	if material.token, err = secret.NewFrom(decoded.SessionToken); err != nil {
		material.destroy()
		return nil, err
	}
	return material, nil
}

func (m *awsGatewayMaterial) destroy() {
	if m.id != nil {
		m.id.Destroy()
	}
	if m.key != nil {
		m.key.Destroy()
	}
	if m.token != nil {
		m.token.Destroy()
	}
}
func (m *awsGatewayMaterial) use(fn func(awssignin.Credentials) error) error {
	return m.id.Use(func(id []byte) error {
		return m.key.Use(func(key []byte) error {
			return m.token.Use(func(token []byte) error {
				return fn(awssignin.Credentials{AccessKeyID: id, SecretAccessKey: key, SessionToken: token})
			})
		})
	})
}

// recordAWS masks the exact injected bytes before any request/result text is
// made immutable. A truncated recording head drops a possibly completing secret.
func recordAWS(rec *connRecorder, material *awsGatewayMaterial, kind string, head []byte, size int) {
	if rec == nil {
		return
	}
	head = head[:min(len(head), clickhouseRecordBytes)]
	var masked []byte
	err := material.use(func(credential awssignin.Credentials) error {
		masked = maskAWSHead(credential, head, size)
		return nil
	})
	if err != nil {
		return
	}
	defer secret.Wipe(masked)
	rec.event("aws", kind, boundedHTTPText(masked, max(size, len(masked))), 0)
}

// maskAWSHead copies only a bounded recording head. Returned bytes contain no
// complete injected credential or truncated suffix that could finish one.
func maskAWSHead(credential awssignin.Credentials, head []byte, size int) []byte {
	head = head[:min(len(head), clickhouseRecordBytes)]

	masked := bytes.Clone(head)

	for _, literal := range [][]byte{credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken} {
		replaced := bytes.ReplaceAll(masked, literal, []byte("[masked:credential]"))
		secret.Wipe(masked)
		masked = replaced
		if size > len(head) {
			for n := min(len(masked), len(literal)-1); n >= 4; n-- {
				if bytes.Equal(masked[len(masked)-n:], literal[:n]) {
					short := append(bytes.Clone(masked[:len(masked)-n]), []byte("[masked:credential]")...)
					secret.Wipe(masked)
					masked = short
					break
				}
			}
		}
	}
	return masked
}

func serveAWS(ctx context.Context, client net.Conn, raw []byte, upstream httpUpstream, service, region string, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	material, err := parseAWSGatewayMaterial(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer material.destroy()
	deadline = earliest(deadline, material.expiration)
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
		// Query auth is removed by the signer; record only the method/path/body,
		// never incoming authentication headers or query-string credentials.
		recordAWS(rec, material, "request", []byte(r.Method+" "+r.URL.Path), len(r.Method)+1+len(r.URL.Path))
		if len(body) > 0 {
			recordAWS(rec, material, "body", body[:min(len(body), clickhouseRecordBytes)], len(body))
		}
		response, err := credentialHTTPRoundTrip(r.Context(), r, body, upstream, deadline, dial, func(out *http.Request) (*secret.Buffer, error) {
			if !time.Now().Before(deadline) {
				return nil, errors.New("accessgateway: AWS session expired")
			}
			var headers []byte
			err := material.use(func(credential awssignin.Credentials) error {
				var err error
				headers, err = awssignin.Sign(out, body, credential, region, service, time.Now())
				return err
			})
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
			status := strconv.Itoa(response.StatusCode)
			rec.event("aws", "status", status, 0)
			response.Body = &recordedBody{ReadCloser: response.Body, done: func(head []byte, size int) { recordAWS(rec, material, "response", head, size) }}
		}
		for name, values := range response.Header {
			if name == "Connection" || name == "Transfer-Encoding" || name == "Content-Length" || name == "X-Amz-Security-Token" {
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
	server := &http.Server{Handler: handler, MaxHeaderBytes: 64 << 10, ReadHeaderTimeout: 30 * time.Second, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			serving.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			serving.Done()
		}
	}, ReadTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	serving.Wait()
	return nil
}
