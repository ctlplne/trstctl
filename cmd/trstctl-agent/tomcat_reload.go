// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

type tomcatReloadOptions struct {
	url, user, passwordFile, tlsHost string
}

// runTomcatReload is an operator-owned host action, invoked by a connector's
// outbox attempt with fixed argv from the local exec profile. Stock catalina.sh
// has no TLS reload command; Tomcat Manager's sslReload is the supported API.
// A file change, HTTP 200 with FAIL text, or a redirect is not an acknowledgement.
func runTomcatReload(ctx context.Context, options tomcatReloadOptions) (bool, error) {
	if options.url == "" && options.user == "" && options.passwordFile == "" {
		return false, nil
	}
	u, err := url.Parse(options.url)
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.RawPath != "" ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Path != "/manager/text/sslReload" {
		return true, errors.New("tomcat reload: URL must be HTTP(S) /manager/text/sslReload without credentials, query or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return true, errors.New("tomcat reload: Manager must use a literal loopback address on this host")
	}
	if options.user == "" || strings.ContainsAny(options.user, ":\r\n\x00") || options.passwordFile == "" {
		return true, errors.New("tomcat reload: manager username and private password file are required")
	}
	if options.tlsHost == "" || len(options.tlsHost) > 253 || strings.ContainsAny(options.tlsHost, "\r\n\x00 []") {
		return true, errors.New("tomcat reload: an exact SSLHostConfig name is required")
	}
	u.RawQuery = url.Values{"tlsHostName": {options.tlsHost}}.Encode()
	raw, err := secretfile.Load(options.passwordFile)
	if err != nil {
		return true, errors.New("tomcat reload: could not read a password file with private ownership and permissions")
	}
	defer secret.Wipe(raw)
	password := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	if len(password) == 0 || len(password) > 4096 || bytes.ContainsAny(password, "\r\n\x00") {
		return true, errors.New("tomcat reload: password file must contain one nonempty line of at most 4096 bytes")
	}
	credentials, err := secret.New(len(options.user) + 1 + len(password))
	if err != nil {
		return true, errors.New("tomcat reload: could not protect management credentials in memory")
	}
	defer credentials.Destroy()
	copy(credentials.Bytes(), options.user)
	credentials.Bytes()[len(options.user)] = ':'
	copy(credentials.Bytes()[len(options.user)+1:], password)
	encoded, err := secret.New(base64.StdEncoding.EncodedLen(credentials.Len()))
	if err != nil {
		return true, errors.New("tomcat reload: could not protect management authorization in memory")
	}
	defer encoded.Destroy()
	base64.StdEncoding.Encode(encoded.Bytes(), credentials.Bytes())
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return true, errors.New("tomcat reload: request could not be constructed")
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Basic ", encoded.Bytes()))
	defer req.Header.Del("Authorization")
	req.Header.Set("Accept-Language", "en")
	client := netsec.InsecureLoopbackClient(15 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return true, errors.New("tomcat reload: Manager request failed or timed out")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := secret.ReadBounded(resp.Body, 4096)
	defer secret.Wipe(body)
	if err != nil {
		return true, errors.New("tomcat reload: Manager response was unreadable or exceeded 4096 bytes")
	}
	if resp.StatusCode != http.StatusOK {
		return true, errors.New("tomcat reload: Manager rejected the request; check the local manager-script account and access policy")
	}
	want := "OK - Reloaded TLS configuration for [" + options.tlsHost + "]"
	if !bytes.Equal(bytes.TrimSpace(body), []byte(want)) {
		return true, errors.New("tomcat reload: Manager did not acknowledge this SSLHostConfig reload; inspect local Tomcat logs")
	}
	return true, nil
}
