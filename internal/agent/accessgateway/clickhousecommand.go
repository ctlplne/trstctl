// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const clickhouseRuleHeaderBytes = 64 << 10
const clickhouseRuleQueue = 16

type clickhouseRuleRequest struct {
	request *http.Request
	body    []byte
	release func()
}

func (f clickhouseRuleRequest) done() {
	secret.Wipe(f.body)
	if f.request != nil && f.request.Body != nil {
		_ = f.request.Body.Close()
	}
	if f.release != nil {
		f.release()
	}
}

// readClickHouseRuleRequest consumes a complete bounded request. One reader owns
// the whole stream, so pipelined bytes cannot hide a later disconnect.
func readClickHouseRuleRequest(reader *bufio.Reader, limit *io.LimitedReader, reserve func(int) (func(), bool)) (clickhouseRuleRequest, error) {
	limit.N = int64(clickhouseRuleHeaderBytes - reader.Buffered())
	request, err := http.ReadRequest(reader)
	if err != nil {
		return clickhouseRuleRequest{}, err
	}
	frame := clickhouseRuleRequest{request: request}
	release, ok := reserve(accessrules.MaxStatementBytes + clickhouseRuleHeaderBytes)
	if !ok {
		return clickhouseRuleRequest{}, errCommandBusy
	}
	frame.release = release
	// Include wire overhead in the bounded body read. Chunked input is normalized
	// to one complete body before any inspection or forwarding.
	limit.N = int64(accessrules.MaxStatementBytes + clickhouseRuleHeaderBytes)
	if request.ContentLength > accessrules.MaxStatementBytes {
		request.Body = http.NoBody
		frame.done()
		return clickhouseRuleRequest{}, accessrules.ErrUninspectable
	}
	body := request.Body
	frame.body, err = io.ReadAll(io.LimitReader(body, accessrules.MaxStatementBytes+1))
	// On failure the caller closes the connection. Closing an unread
	// ReadRequest body here would drain attacker-controlled bytes first.
	request.Body = http.NoBody
	if err != nil || len(frame.body) > accessrules.MaxStatementBytes {
		frame.done()
		if err != nil {
			return clickhouseRuleRequest{}, err
		}
		return clickhouseRuleRequest{}, accessrules.ErrUninspectable
	}
	_ = body.Close()
	return frame, nil
}

func relayClickHouseCommands(parent context.Context, client net.Conn, transport *http.Transport, c *commandConnection, rec *connRecorder, rewrite func(*httputil.ProxyRequest)) error {
	ctx, cancel := context.WithCancelCause(parent)
	frames := make(chan clickhouseRuleRequest, clickhouseRuleQueue)
	go func() {
		<-ctx.Done()
		_ = client.SetReadDeadline(time.Now())
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	}()
	go func() {
		defer close(frames)
		limited := &io.LimitedReader{R: client, N: clickhouseRuleHeaderBytes}
		reader := bufio.NewReaderSize(limited, 4096)
		for {
			// Wait for the next request under the session deadline, then bound the
			// active header/body read. An idle peer does not shorten human review.
			_ = client.SetReadDeadline(c.expiresAt)
			limited.N = int64(clickhouseRuleHeaderBytes - reader.Buffered())
			if _, err := reader.Peek(1); err != nil {
				cancel(err)
				return
			}
			_ = client.SetReadDeadline(earliest(c.expiresAt, time.Now().Add(30*time.Second)))
			frame, err := readClickHouseRuleRequest(reader, limited, c.reserveFrame)
			if err != nil {
				cancel(err)
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				frame.done()
				return
			default:
				frame.done()
				cancel(errCommandBusy)
				return
			}
		}
	}()
	defer func() {
		cancel(context.Canceled)
		if errors.Is(context.Cause(ctx), errCommandBusy) {
			_ = client.SetWriteDeadline(time.Now().Add(time.Second))
			_ = writeClickHouseRuleProblem(client, &http.Request{Close: true}, http.StatusServiceUnavailable, "TRSTCTL_COMMAND_CAPACITY_FULL", "")
		}
		_ = client.Close()
		for frame := range frames {
			frame.done()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case frame, ok := <-frames:
			if !ok {
				return context.Cause(ctx)
			}
			err := forwardClickHouseRuleRequest(ctx, client, transport, c, rec, rewrite, frame)
			closeAfter := frame.request.Close
			frame.done()
			if err != nil {
				return err
			}
			if closeAfter {
				return nil
			}
		}
	}
}

// clickhouseRuleSQL extracts only the SQL text. Auth headers, user and password
// parameters are never part of this classifier's input or source message.
func clickhouseRuleSQL(request *http.Request, body []byte) ([]byte, string, string) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(query["query"]) > 1 {
		return nil, "uninspectable", ""
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost || request.URL.Path != "/" || len(request.Header.Values("Content-Encoding")) > 1 || request.Header.Get("Content-Encoding") != "" && !strings.EqualFold(request.Header.Get("Content-Encoding"), "identity") || strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "multipart/") || query.Has("decompress") {
		return nil, "control", ""
	}
	prefix := []byte(query.Get("query"))
	if len(prefix)+len(body)+1 > accessrules.MaxStatementBytes {
		return nil, "uninspectable", ""
	}
	sql := make([]byte, 0, len(prefix)+len(body)+1)
	sql = append(sql, prefix...)
	if len(prefix) > 0 && len(body) > 0 {
		sql = append(sql, '\n')
	}
	sql = append(sql, body...)
	// Bind public request routing/settings while excluding both credential
	// parameter names and all auth headers. Only its digest crosses the source.
	query.Del("user")
	query.Del("password")
	query.Del("query")
	parent := crypto.SHA256Hex([]byte(request.Method + "\x00" + request.URL.Path + "\x00" + query.Encode() + "\x00" + request.Header.Get("X-ClickHouse-Database")))
	return sql, "query", parent
}

func forwardClickHouseRuleRequest(ctx context.Context, client io.Writer, transport *http.Transport, c *commandConnection, rec *connRecorder, rewrite func(*httputil.ProxyRequest), frame clickhouseRuleRequest) error {
	request := frame.request
	sql, phase, parent := clickhouseRuleSQL(request, frame.body)
	defer secret.Wipe(sql)
	operations := []string{}
	if phase == "query" {
		var err error
		operations, err = accessrules.ClickHouseOperations(sql)
		if err != nil {
			phase = "uninspectable"
		} else if accessrules.UnsupportedClickHouseControl(operations) {
			phase = "control"
		}
	}
	result, err := c.evaluate(ctx, phase, operations, sql, parent)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	allowed := err == nil && (result.decision.ID == "" || result.durable && accessrules.Permits(result.decision.Status))
	if allowed && result.decision.ReviewExpiresAt != nil && !time.Now().Before(*result.decision.ReviewExpiresAt) {
		allowed = false
	}
	if !allowed {
		if rec != nil {
			rec.event("clickhouse", "refused", "TRSTCTL_COMMAND_REFUSED", 0)
		}
		status := http.StatusForbidden
		if err != nil {
			status = http.StatusServiceUnavailable
		}
		return writeClickHouseRuleProblem(client, request, status, "TRSTCTL_COMMAND_REFUSED", result.decision.ID)
	}
	if rec != nil {
		rec.event("clickhouse", "request", request.Method+" "+request.URL.Path+" query="+boundedHTTPText(sql, len(sql)), 0)
	}
	out := request.Clone(ctx)
	out.Body = io.NopCloser(bytes.NewReader(frame.body))
	out.ContentLength = int64(len(frame.body))
	out.TransferEncoding = nil
	out.Trailer = nil
	out.GetBody = nil
	out.RequestURI = ""
	out.Close = false
	for _, name := range strings.Split(out.Header.Get("Connection"), ",") {
		out.Header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Idempotency-Key", "X-Idempotency-Key"} {
		out.Header.Del(name)
	}
	rewrite(&httputil.ProxyRequest{In: request, Out: out})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	response, err := transport.RoundTrip(out)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return writeClickHouseRuleProblem(client, request, http.StatusBadGateway, "TRSTCTL_TARGET_UNAVAILABLE", "")
	}
	defer func() { _ = response.Body.Close() }()
	if rec != nil {
		status := strconv.Itoa(response.StatusCode)
		response.Body = &recordedBody{ReadCloser: response.Body, done: func(head []byte, size int) {
			rec.event("result", "response", status+": "+boundedHTTPText(head, size), 0)
		}}
	}
	response.Close = request.Close
	return response.Write(client)
}

func writeClickHouseRuleProblem(dst io.Writer, request *http.Request, status int, code, id string) error {
	body, err := json.Marshal(map[string]any{"type": "about:blank", "title": "Gateway request refused", "status": status, "code": code, "action_id": id})
	if err != nil {
		return err
	}
	response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"application/problem+json"}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: request.Close}
	return response.Write(dst)
}
