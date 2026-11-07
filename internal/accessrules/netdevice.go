// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"unicode/utf8"
)

// netDeviceOperationNames are the network device commands a rule can name
// (A270): the verbs that change, save, restart or leave a device's command
// line on IOS-XE, Junos, EOS, FortiOS and BIG-IP's tmsh. Read-only commands
// (show, get, ping) are never operations.
var netDeviceOperationNames = []string{"bash", "clear", "commit", "configure", "copy", "create", "debug", "delete", "diagnose", "erase",
	"execute", "format", "load", "modify", "no", "reload", "request", "restart", "rollback", "run", "save", "set", "start", "write"}

// NetDeviceOperations reads each line of a device command (an exec request
// may carry several) and returns the operations its first word can name. A
// device command line accepts any unambiguous abbreviation of a command
// ("conf t", "wr"), so a word of two or more letters names every operation it
// abbreviates — "co" names commit, configure and copy — and a rule on any of
// them applies; "do" (configuration mode's exec escape) is skipped. A
// one-letter word names nothing a device would take unambiguously.
func NetDeviceOperations(raw []byte) ([]string, error) {
	if len(raw) > MaxSSHCommandBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUninspectable
	}
	out := []string{}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		words := bytes.Fields(bytes.ToLower(line))
		if len(words) > 0 && bytes.Equal(words[0], []byte("do")) {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		word := words[0]
		for _, c := range word {
			if c < 0x20 || c == 0x7f {
				return nil, ErrUninspectable
			}
		}
		for _, name := range netDeviceOperationNames {
			if (bytes.Equal(word, []byte(name)) || (len(word) >= 2 && bytes.HasPrefix([]byte(name), word))) && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}
