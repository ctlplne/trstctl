// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// A273-O2: many consoles name their own origin in what they send: an
// absolute link, a form action, a <base>, a script's API or WebSocket URL, a
// JSON "self" link, a Refresh header. Followed as written, these would take
// the browser off the session's tunnel, where the console cannot be reached
// and where no gateway signs in or records. The gateway rewrites each of
// them to the tunnel's own origin, the one the browser is on.

// webTunnelKey carries the browser's tunnel origin from a request to the
// console's response.
type webTunnelKey struct{}

// webTunnelOrigin is the tunnel origin a browser request names in its Host
// header: the CLI's loopback listener. Any other host is not a tunnel the
// gateway knows, and links are then made root-relative instead.
func webTunnelOrigin(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return ""
	}
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return ""
	}
	return "http://" + net.JoinHostPort(host, port)
}

// withWebTunnel records the browser's tunnel origin on the console request.
func withWebTunnel(r *http.Request, browserHost string) *http.Request {
	origin := webTunnelOrigin(browserHost)
	if origin == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), webTunnelKey{}, origin))
}

func webTunnelFrom(ctx context.Context) string {
	origin, _ := ctx.Value(webTunnelKey{}).(string)
	return origin
}

// webTextMedia are the content types whose bodies may name the console's
// origin as text: markup, style sheets, scripts and JSON or XML documents.
var webTextMedia = regexp.MustCompile(`^text/|^application/(javascript|x-javascript|ecmascript|json|xml)$|\+(json|xml)$`)

// webOriginForm is one way a body writes the console's origin, and what the
// browser gets instead. A scheme-relative form ("//host") also needs the
// byte before it to start a URL, so another scheme's "x://host" stays.
type webOriginForm struct {
	from, to       []byte
	schemeRelative bool
}

// webOriginForms lists the console origin's written forms: with and without
// a default port, plain and JSON-escaped ("https:\/\/host"), its WebSocket
// scheme and scheme-relative. Each becomes the tunnel's origin, or nothing
// (a root-relative URL) when the tunnel is unknown.
func webOriginForms(target *url.URL, tunnel string) []webOriginForm {
	scheme := strings.ToLower(target.Scheme)
	host := target.Hostname()
	if host == "" || (scheme != "https" && scheme != "http") {
		return nil
	}
	defaultPort, ws := "443", "wss"
	if scheme == "http" {
		defaultPort, ws = "80", "ws"
	}
	bare := func(h string) string {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	hosts := []string{host}
	if lower := strings.ToLower(host); lower != host {
		hosts = append(hosts, lower)
	}
	var authorities []string
	for _, h := range hosts {
		if port := target.Port(); port != "" && port != defaultPort {
			authorities = append(authorities, net.JoinHostPort(h, port))
			continue
		}
		authorities = append(authorities, bare(h), net.JoinHostPort(h, defaultPort))
	}
	tunnelAuthority := strings.TrimPrefix(tunnel, "http://")
	escape := func(s string) string { return strings.ReplaceAll(s, "/", `\/`) }
	var forms []webOriginForm
	add := func(from, to string, schemeRelative bool) {
		forms = append(forms, webOriginForm{from: []byte(from), to: []byte(to), schemeRelative: schemeRelative})
		forms = append(forms, webOriginForm{from: []byte(escape(from)), to: []byte(escape(to)), schemeRelative: schemeRelative})
	}
	for _, a := range authorities {
		if tunnelAuthority == "" {
			add(scheme+"://"+a, "", false)
			add(ws+"://"+a, "", false)
			add("//"+a, "", true)
			continue
		}
		add(scheme+"://"+a, "http://"+tunnelAuthority, false)
		add(ws+"://"+a, "ws://"+tunnelAuthority, false)
		add("//"+a, "//"+tunnelAuthority, true)
	}
	return forms
}

// webAuthorityContinues reports whether a byte after a matched origin makes
// it another origin: a longer host name or port, a port after a host, or
// user information ("host@elsewhere").
func webAuthorityContinues(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte(".-_:@%", b) >= 0
}

// webURLStarts reports whether a scheme-relative URL may start after a byte:
// the start of the body, a quote, an attribute's "=", a parenthesis, a
// separator or white space; never another scheme's ":".
func webURLStarts(prev byte, first bool) bool {
	return first || strings.IndexByte("\"'`=( \t\r\n,;[>", prev) >= 0
}

// webOriginBody rewrites the console origin's forms in a response as it
// streams: a body is never held whole. Lengths change, so the response is
// sent without its Content-Length.
type webOriginBody struct {
	src     io.ReadCloser
	forms   []webOriginForm
	longest int
	held    []byte
	out     []byte
	prev    byte
	emitted bool
	eof     bool
}

func newWebOriginBody(src io.ReadCloser, forms []webOriginForm) *webOriginBody {
	b := &webOriginBody{src: src, forms: forms}
	for _, f := range forms {
		b.longest = max(b.longest, len(f.from))
	}
	return b
}

func (b *webOriginBody) Read(p []byte) (int, error) {
	for len(b.out) == 0 && (!b.eof || len(b.held) > 0) {
		if !b.eof {
			chunk := make([]byte, 32<<10)
			n, err := b.src.Read(chunk)
			b.held = append(b.held, chunk[:n]...)
			switch {
			case errors.Is(err, io.EOF):
				b.eof = true
			case err != nil:
				return 0, err
			}
		}
		b.scan()
	}
	if len(b.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.out)
	b.out = b.out[n:]
	return n, nil
}

func (b *webOriginBody) Close() error { return b.src.Close() }

func (b *webOriginBody) emit(p []byte) {
	if len(p) == 0 {
		return
	}
	b.out = append(b.out, p...)
	b.prev, b.emitted = p[len(p)-1], true
}

// scan rewrites what is held. Bytes that may begin a form, and a match
// until a longer form and the byte after it could have arrived, are held for
// the next read unless the body has ended.
func (b *webOriginBody) scan() {
	pos := 0
	for {
		at, chosen := -1, -1
		for i, f := range b.forms {
			j := bytes.Index(b.held[pos:], f.from)
			if j < 0 {
				continue
			}
			j += pos
			if at < 0 || j < at || j == at && len(f.from) > len(b.forms[chosen].from) {
				at, chosen = j, i
			}
		}
		if at < 0 {
			keep := 0
			if !b.eof {
				keep = min(len(b.held)-pos, b.longest-1)
			}
			b.emit(b.held[pos : len(b.held)-keep])
			b.held = append(b.held[:0], b.held[len(b.held)-keep:]...)
			return
		}
		if !b.eof && len(b.held)-at <= b.longest {
			// A longer form at the same place, or the byte after this one,
			// may still arrive.
			b.emit(b.held[pos:at])
			b.held = append(b.held[:0], b.held[at:]...)
			return
		}
		f := b.forms[chosen]
		end := at + len(f.from)
		b.emit(b.held[pos:at])
		if end < len(b.held) && webAuthorityContinues(b.held[end]) || f.schemeRelative && !webURLStarts(b.prev, !b.emitted) {
			b.emit(b.held[at : at+1])
			pos = at + 1
			continue
		}
		b.emit(f.to)
		pos = end
	}
}

// webTunnelURI is where a console URL on its own origin is on the tunnel.
func webTunnelURI(u *url.URL) string {
	uri := u.RequestURI()
	if u.Fragment != "" {
		uri += "#" + u.EscapedFragment()
	}
	return uri
}

var webLinkTarget = regexp.MustCompile(`<([^>]*)>`)

// rewriteHeaderURLs keeps the URLs a response's headers name on the
// console's own origin on the tunnel: Content-Location, a Refresh header's
// url=, each Link target and the Content-Security-Policy's sources. The
// Location header has its own handling.
func (c *webConsoleClient) rewriteHeaderURLs(resp *http.Response) {
	base := resp.Request.URL
	onTunnel := func(raw string) (string, bool) {
		next, err := base.Parse(strings.TrimSpace(raw))
		if err != nil || !next.IsAbs() || !sameOrigin(next, c.target) {
			return "", false
		}
		return webTunnelURI(next), true
	}
	if v := resp.Header.Get("Content-Location"); v != "" {
		if uri, ok := onTunnel(v); ok {
			resp.Header.Set("Content-Location", uri)
		}
	}
	if v := resp.Header.Get("Refresh"); v != "" {
		if delay, rest, found := strings.Cut(v, ";"); found {
			rest = strings.TrimSpace(rest)
			if len(rest) > 4 && strings.EqualFold(rest[:4], "url=") {
				target := strings.Trim(strings.TrimSpace(rest[4:]), `"'`)
				if uri, ok := onTunnel(target); ok {
					resp.Header.Set("Refresh", strings.TrimSpace(delay)+"; url="+uri)
				}
			}
		}
	}
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		if policies := resp.Header.Values(name); len(policies) > 0 {
			fitted := make([]string, 0, len(policies))
			for _, policy := range policies {
				fitted = append(fitted, webTunnelPolicy(policy, c.target, webTunnelFrom(resp.Request.Context())))
			}
			resp.Header[name] = fitted
		}
	}
	if links := resp.Header.Values("Link"); len(links) > 0 {
		rewritten := make([]string, 0, len(links))
		for _, link := range links {
			rewritten = append(rewritten, webLinkTarget.ReplaceAllStringFunc(link, func(m string) string {
				if uri, ok := onTunnel(m[1 : len(m)-1]); ok {
					return "<" + uri + ">"
				}
				return m
			}))
		}
		resp.Header["Link"] = rewritten
	}
}

// webTunnelPolicy fits a console's Content-Security-Policy to the tunnel: a
// source naming the console's origin names the tunnel's, and the directives
// that upgrade or block plain-http loads go, because the browser's tunnel is
// plain http on loopback (Strict-Transport-Security is dropped for the same
// reason). Every other directive and source stands as the console set it.
func webTunnelPolicy(policy string, target *url.URL, tunnel string) string {
	var kept []string
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 || strings.EqualFold(fields[0], "upgrade-insecure-requests") || strings.EqualFold(fields[0], "block-all-mixed-content") {
			continue
		}
		for i := 1; i < len(fields); i++ {
			fields[i] = webTunnelSource(fields[i], target, tunnel)
		}
		kept = append(kept, strings.Join(fields, " "))
	}
	return strings.Join(kept, "; ")
}

// webTunnelSource maps one policy source on the console's origin (with or
// without its scheme, or its WebSocket scheme) to the tunnel's origin; a
// keyword, nonce, hash, wildcard or other origin is returned as it is.
func webTunnelSource(source string, target *url.URL, tunnel string) string {
	authority := strings.TrimPrefix(tunnel, "http://")
	if authority == "" || strings.HasPrefix(source, "'") || strings.Contains(source, "*") {
		return source
	}
	scheme, rest, found := strings.Cut(source, "://")
	if !found {
		scheme, rest = target.Scheme, source
	}
	host, path, hasPath := strings.Cut(rest, "/")
	compare := strings.ToLower(scheme)
	switch compare {
	case "wss":
		compare = "https"
	case "ws":
		compare = "http"
	}
	u, err := url.Parse(compare + "://" + host)
	if err != nil || u.Host == "" || !sameOrigin(u, target) {
		return source
	}
	out := "http://" + authority
	if strings.HasPrefix(strings.ToLower(scheme), "ws") {
		out = "ws://" + authority
	}
	if hasPath {
		out += "/" + path
	}
	return out
}

// rewriteBodyOrigin rewrites a text response's body, when it is not
// compressed, so the console's origin in it names the tunnel's.
func (c *webConsoleClient) rewriteBodyOrigin(resp *http.Response, media string) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if !webTextMedia.MatchString(media) || (encoding != "" && encoding != "identity") || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	forms := webOriginForms(c.target, webTunnelFrom(resp.Request.Context()))
	if len(forms) == 0 {
		return
	}
	resp.Body = newWebOriginBody(resp.Body, forms)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
}
