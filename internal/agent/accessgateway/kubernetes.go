// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// kubernetesClientAuth are the request headers by which a Kubernetes client
// could act as someone else: its own credential and impersonation. The
// gateway removes them and authenticates every request as the session's
// service account.
var kubernetesClientAuth = []string{"Authorization", "Proxy-Authorization", "Impersonate-User", "Impersonate-Group", "Impersonate-Uid"}

// kubernetesStreamProtocols are the remote-command channel protocols whose
// streams the recording decodes (a message's first byte names its channel:
// 0 stdin, 1 stdout, 2 stderr, 3 status, 4 resize).
var kubernetesStreamProtocols = map[string]bool{"v5.channel.k8s.io": true, "v4.channel.k8s.io": true,
	"v3.channel.k8s.io": true, "v2.channel.k8s.io": true, "channel.k8s.io": true, "base64.channel.k8s.io": true}

// serveKubernetes relays a stock Kubernetes client (kubectl with a
// kubeconfig that names the tunnel and no user) to the API server as the
// session's service account (A256). The client sends no credential — the
// admitted tunnel is its authentication — and any it sends, or any
// impersonation, is removed; the gateway adds the session's token to every
// request, exec and port-forward streams included. The client never
// receives the token.
func serveKubernetes(ctx context.Context, client net.Conn, token []byte, upstream httpUpstream, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	if len(token) == 0 {
		return errors.New("accessgateway: the Kubernetes session has no token")
	}
	target, transport, err := upstream.transport(dial)
	if err != nil {
		return err
	}
	if target.Scheme != "https" {
		return errors.New("accessgateway: a Kubernetes API server is reached over https")
	}
	defer transport.CloseIdleConnections()
	var streams atomic.Int32
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			for _, h := range kubernetesClientAuth {
				r.Out.Header.Del(h)
			}
			for h := range r.Out.Header {
				if strings.HasPrefix(h, "Impersonate-Extra-") {
					r.Out.Header.Del(h)
				}
			}
			r.Out.Header.Set("Authorization", "Bearer "+string(token))
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			if rec == nil {
				return nil
			}
			status := strconv.Itoa(resp.StatusCode)
			if resp.StatusCode == http.StatusSwitchingProtocols {
				// An exec, attach or port-forward stream: its bytes pass
				// through a tap that records them as they go.
				rwc, ok := resp.Body.(io.ReadWriteCloser)
				if !ok {
					return nil
				}
				protocol := resp.Header.Get("Sec-WebSocket-Protocol")
				upgrade := strings.ToLower(resp.Header.Get("Upgrade"))
				rec.event("result", "response", status+" stream "+upgrade+" "+protocol, 0)
				resp.Body = newStreamTap(rwc, rec, int(streams.Add(1)), upgrade == "websocket" && kubernetesStreamProtocols[protocol], protocol == "base64.channel.k8s.io")
				return nil
			}
			resp.Body = &recordedBody{ReadCloser: resp.Body, done: func(head []byte, size int) {
				rec.event("result", "response", status+": "+boundedHTTPText(head, size), 0)
			}}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "the access gateway could not reach the target", http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			text := r.Method + " " + r.URL.RequestURI()
			if r.Body != nil && r.ContentLength != 0 && r.Header.Get("Upgrade") == "" {
				body := bufio.NewReaderSize(r.Body, clickhouseRecordBytes+1)
				head, _ := body.Peek(clickhouseRecordBytes)
				if len(head) > 0 {
					text += " body=" + boundedHTTPText(head, len(head))
				}
				r.Body = struct {
					io.Reader
					io.Closer
				}{body, r.Body}
			}
			rec.event("kubernetes", "request", text, 0)
		}
		proxy.ServeHTTP(w, r)
	})
	listener := newOneConnListener(client)
	server := &http.Server{
		Handler: handler, MaxHeaderBytes: clickhouseMaxHeader, ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	return nil
}

// streamTap passes an upgraded stream through unchanged and records it: a
// remote-command WebSocket stream decoded into its stdin, stdout and stderr
// (masked, as an SSH session's are), any other stream by its size.
type streamTap struct {
	io.ReadWriteCloser
	rec       *connRecorder
	ch        int
	in, out   *wsReader
	inN, outN atomic.Int64
	once      sync.Once
}

func newStreamTap(rwc io.ReadWriteCloser, rec *connRecorder, ch int, decode, base64Channel bool) *streamTap {
	t := &streamTap{ReadWriteCloser: rwc, rec: rec, ch: ch}
	if decode {
		t.in = &wsReader{emit: t.emit, base64: base64Channel}
		t.out = &wsReader{emit: t.emit, base64: base64Channel}
	}
	return t
}

// Read carries the server's bytes to the client.
func (t *streamTap) Read(p []byte) (int, error) {
	n, err := t.ReadWriteCloser.Read(p)
	t.outN.Add(int64(n))
	if t.out != nil && n > 0 {
		t.out.feed(p[:n])
	}
	return n, err
}

// Write carries the client's bytes to the server.
func (t *streamTap) Write(p []byte) (int, error) {
	if t.in != nil && len(p) > 0 {
		t.in.feed(p)
	}
	n, err := t.ReadWriteCloser.Write(p)
	t.inN.Add(int64(n))
	return n, err
}

func (t *streamTap) Close() error {
	t.once.Do(func() {
		t.rec.event("result", "stream closed", strconv.FormatInt(t.inN.Load(), 10)+" bytes in, "+strconv.FormatInt(t.outN.Load(), 10)+" bytes out", 0)
	})
	return t.ReadWriteCloser.Close()
}

// emit records one channel's data.
func (t *streamTap) emit(channel byte, data []byte) {
	switch channel {
	case 0:
		t.rec.Data(t.ch, "in", data)
	case 1:
		t.rec.Data(t.ch, "out", data)
	case 2:
		t.rec.Data(t.ch, "err", data)
	case 3:
		t.rec.event("result", "stream status", boundedHTTPText(data, len(data)), 0)
	}
}

// wsReader reads one direction of a WebSocket stream as it passes, frame by
// frame, unmasking payloads and handing each message's data to emit with the
// channel its first byte names. It never holds a whole frame: payloads are
// handed on in the pieces they arrive in.
type wsReader struct {
	emit   func(channel byte, data []byte)
	base64 bool

	header   []byte
	need     int
	payload  uint64
	mask     [4]byte
	masked   bool
	maskAt   int
	control  bool
	starting bool // the next payload byte begins a message
	channel  byte
	pending  []byte // base64 text waiting for a whole quantum
}

func (w *wsReader) feed(p []byte) {
	for len(p) > 0 {
		if w.payload == 0 && w.need == 0 && len(w.header) == 0 {
			w.need = 2
		}
		if w.need > 0 {
			take := min(w.need, len(p))
			w.header = append(w.header, p[:take]...)
			w.need -= take
			p = p[take:]
			if w.need > 0 {
				return
			}
			// A header still short asks for more bytes; a frame without a
			// payload is done: either way the loop goes on.
			w.parseHeader()
			continue
		}
		take := int(min(w.payload, uint64(len(p)))) // #nosec G115 -- bounded by len(p) (CWE-190)
		chunk := append([]byte(nil), p[:take]...)
		if w.masked {
			for i := range chunk {
				chunk[i] ^= w.mask[(w.maskAt+i)%4]
			}
			w.maskAt = (w.maskAt + take) % 4
		}
		w.payload -= uint64(take) // #nosec G115 -- take is non-negative (CWE-190)
		p = p[take:]
		if !w.control {
			w.data(chunk)
		}
	}
}

// parseHeader reads a complete frame header, asking for the rest of it when
// the length or mask is still to come; it reports whether a payload follows.
func (w *wsReader) parseHeader() bool {
	h := w.header
	opcode := h[0] & 0x0f
	length := uint64(h[1] & 0x7f)
	w.masked = h[1]&0x80 != 0
	extra := 0
	switch length {
	case 126:
		extra = 2
	case 127:
		extra = 8
	}
	if w.masked {
		extra += 4
	}
	if len(h) < 2+extra {
		w.need = 2 + extra - len(h)
		return false
	}
	off := 2
	switch length {
	case 126:
		length = uint64(binary.BigEndian.Uint16(h[2:]))
		off = 4
	case 127:
		length = binary.BigEndian.Uint64(h[2:])
		off = 10
	}
	if w.masked {
		copy(w.mask[:], h[off:off+4])
	}
	w.maskAt = 0
	w.control = opcode >= 8
	if opcode == 1 || opcode == 2 {
		w.starting = true
	}
	w.payload = length
	w.header = w.header[:0]
	return length > 0
}

func (w *wsReader) data(chunk []byte) {
	if w.starting && len(chunk) > 0 {
		w.channel, chunk = chunk[0], chunk[1:]
		if w.base64 {
			w.channel -= '0'
		}
		w.starting = false
		w.pending = w.pending[:0]
	}
	if len(chunk) == 0 {
		return
	}
	if !w.base64 {
		w.emit(w.channel, chunk)
		return
	}
	w.pending = append(w.pending, chunk...)
	whole := len(w.pending) / 4 * 4
	decoded, err := base64.StdEncoding.DecodeString(string(w.pending[:whole]))
	w.pending = append(w.pending[:0], w.pending[whole:]...)
	if err == nil && len(decoded) > 0 {
		w.emit(w.channel, decoded)
	}
	secret.Wipe(decoded)
}
