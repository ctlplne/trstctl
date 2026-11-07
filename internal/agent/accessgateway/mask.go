// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"regexp"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// maskRule is one token shape the gateway masks in recordings before they
// leave it (A255). The control plane's secret-scan rule set cannot be linked
// into the agent (it links a database driver), so the gateway carries this
// short, documented list of issued-credential shapes.
type maskRule struct {
	name string
	re   *regexp.Regexp
}

var maskRules = []maskRule{
	{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`)},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"slack-token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"stripe-key", regexp.MustCompile(`\b[rs]k_live_[A-Za-z0-9]{16,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)},
}

var privateKeyBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

// tokenStarts are how the token shapes above begin. A write holds back
// from a start that may still be completing, never ordinary output.
var tokenStarts = [][]byte{[]byte("AKIA"), []byte("ASIA"), []byte("ghp_"), []byte("gho_"), []byte("ghu_"), []byte("ghs_"),
	[]byte("ghr_"), []byte("github_pat_"), []byte("glpat-"), []byte("xoxa-"), []byte("xoxb-"), []byte("xoxp-"), []byte("xoxo-"),
	[]byte("xoxs-"), []byte("xoxr-"), []byte("sk_live_"), []byte("rk_live_"), []byte("AIza"), []byte("eyJ"), []byte("-----BEGIN")}

const (
	// maskTokenHold bounds how long a token still completing is held back;
	// a token-shaped run longer than this is masked to where it stands.
	maskTokenHold = 8 << 10
	// maskKeyHold bounds an unterminated private-key block kept back waiting
	// for its END line; past it the block is masked to the end of the write.
	maskKeyHold = 16 << 10
)

// masker masks one recorded stream: the session's own injected credential
// (exact bytes) and the token shapes above become "[masked:<rule>]". It is
// not safe for concurrent use; each stream has its own.
type masker struct {
	literals [][]byte
	pending  []byte
}

// newMasker copies the literal secrets it must mask; Close wipes them.
func newMasker(literals ...[]byte) *masker {
	m := &masker{}
	for _, l := range literals {
		if len(l) >= 4 {
			m.literals = append(m.literals, append([]byte(nil), l...))
		}
	}
	return m
}

// Write masks p together with what an earlier write held back and returns
// the bytes safe to record now. Only a tail that may still become a secret
// is held for the next write: a token start still running to the end, the
// start of the session's credential, an unterminated private-key block.
func (m *masker) Write(p []byte) []byte {
	m.pending = append(m.pending, p...)
	masked := m.mask(m.pending)
	if begin := privateKeyBegin.FindIndex(masked); begin != nil && len(masked)-begin[0] > maskKeyHold {
		masked = append(masked[:begin[0]:begin[0]], []byte("[masked:private-key]")...)
	}
	cut := m.holdFrom(masked)
	out := append([]byte(nil), masked[:cut]...)
	m.keep(masked[cut:])
	return out
}

// holdFrom is where the tail that may still become a secret begins.
func (m *masker) holdFrom(b []byte) int {
	cut := len(b)
	hold := func(i int) {
		if i < cut {
			cut = i
		}
	}
	if begin := privateKeyBegin.FindIndex(b); begin != nil {
		hold(begin[0])
	}
	// A key header still being written: "-----BEGIN" with no line end yet.
	if i := bytes.LastIndex(b, []byte("-----BEGIN")); i >= 0 && len(b)-i < 80 && bytes.IndexByte(b[i:], '\n') < 0 {
		hold(i)
	}
	// A token still running to the end: the earliest token start inside the
	// trailing run of token characters (a JWT's dots included).
	run := len(b)
	for run > 0 && len(b)-run < maskTokenHold && tokenChar(b[run-1]) {
		run--
	}
	for _, start := range tokenStarts {
		if i := bytes.Index(b[run:], start); i >= 0 {
			hold(run + i)
		}
		hold(len(b) - partialSuffix(b, start))
	}
	for _, l := range m.literals {
		hold(len(b) - partialSuffix(b, l))
	}
	return cut
}

func tokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// partialSuffix is the length of the longest proper prefix of s that b ends
// with: the start of s, cut off by the end of the write.
func partialSuffix(b, s []byte) int {
	for k := min(len(s)-1, len(b)); k > 0; k-- {
		if bytes.HasSuffix(b, s[:k]) {
			return k
		}
	}
	return 0
}

// Flush returns everything still held back, masked.
func (m *masker) Flush() []byte {
	out := m.mask(m.pending)
	if begin := privateKeyBegin.FindIndex(out); begin != nil {
		out = append(out[:begin[0]:begin[0]], []byte("[masked:private-key]")...)
	}
	m.keep(nil)
	return out
}

// Close wipes the literal secrets and anything held back.
func (m *masker) Close() {
	for _, l := range m.literals {
		secret.Wipe(l)
	}
	m.literals = nil
	m.keep(nil)
}

func (m *masker) keep(rest []byte) {
	next := append([]byte(nil), rest...)
	secret.Wipe(m.pending)
	m.pending = next
}

func (m *masker) mask(b []byte) []byte {
	out := append([]byte(nil), b...)
	for _, l := range m.literals {
		out = bytes.ReplaceAll(out, l, []byte("[masked:session-credential]"))
	}
	for _, rule := range maskRules {
		out = rule.re.ReplaceAll(out, []byte("[masked:"+rule.name+"]"))
	}
	return out
}

// MaskText masks the issued-credential shapes in a text the control plane
// shows or keeps (A275: recording search results and the searches it
// records). Recordings are masked as they are made; this masks again.
func MaskText(text string) string {
	m := newMasker()
	defer m.Close()
	return string(append(m.Write([]byte(text)), m.Flush()...))
}
