// SPDX-License-Identifier: BUSL-1.1
// Package accessconsole validates the public, reviewed destinations of a native
// console handoff. It holds no credentials and performs no network calls.
package accessconsole

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

const TargetAWS = "aws-console"
const RecordingScope = "native_console_handoff"

type Binding struct {
	FederationEndpoint string `json:"federation_endpoint"`
	Destination        string `json:"destination"`
}

func (b Binding) Validate(allowLoopback bool) error {
	for i, raw := range []string{b.FederationEndpoint, b.Destination} {
		if len(raw) > 2048 {
			return errors.New("console binding URL exceeds its bound")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(raw, "\r\n\x00") {
			return errors.New("console binding requires fixed URLs without credentials, query or fragment")
		}
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		local := host == "localhost" || ip != nil && ip.IsLoopback()
		if local {
			if !allowLoopback || (u.Scheme != "http" && u.Scheme != "https") {
				return errors.New("console loopback binding requires explicit lab opt-in")
			}
		} else {
			if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
				return errors.New("native console endpoints require HTTPS on port 443")
			}
			suffix := "console.aws.amazon.com"
			if i == 0 {
				suffix = "signin.aws.amazon.com"
			}
			if host != suffix && !strings.HasSuffix(host, "."+suffix) {
				return errors.New("console binding is outside the supported AWS commercial endpoints")
			}
		}
		if i == 0 && u.Path != "/federation" {
			return errors.New("AWS federation endpoint must use /federation")
		}
	}
	return nil
}
