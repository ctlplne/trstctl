// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
)

// SourceIdentity is the exact authority that opened a ticket request. A name
// or ticket key alone is not an authority: two instances can use the same key.
// JSON keeps each component unambiguous even when an instance URL has a path.
func SourceIdentity(system, schedule, instanceURL string) (string, error) {
	schedule = ScheduleName(schedule)
	if (system != SystemServiceNow && system != SystemJira) || !ValidScheduleName(schedule) {
		return "", errors.New("ticket intake: invalid source system or schedule")
	}
	u, err := url.Parse(strings.TrimSpace(instanceURL))
	if err != nil || u.Hostname() == "" || (strings.ToLower(u.Scheme) != "https" && strings.ToLower(u.Scheme) != "http") || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("ticket intake: source needs an absolute HTTP(S) instance URL without userinfo, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	encoded, err := json.Marshal([3]string{system, schedule, u.String()})
	return string(encoded), err
}

// SourceSchedule extracts only the schedule from a stored source identity.
// Callers must compare the complete identity against current configuration.
func SourceSchedule(source, system string) (string, bool) {
	var parts []string
	if json.Unmarshal([]byte(source), &parts) != nil || len(parts) != 3 || parts[0] != system || !ValidScheduleName(parts[1]) {
		return "", false
	}
	return parts[1], true
}
