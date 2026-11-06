// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// nativeCAConfigurationArgument keeps a directory-supplied CA selector in one
// native -config value. It never supplies executable names or command switches.
func nativeCAConfigurationArgument(host, name string) (string, bool) {
	if len(host) == 0 || len(host) > 253 || len(name) == 0 || len(name) > 255 || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return "", false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	for _, c := range name {
		if unicode.IsControl(c) || c == '\\' || c == '/' || c == '"' {
			return "", false
		}
	}
	return host + "\\" + name, true
}
