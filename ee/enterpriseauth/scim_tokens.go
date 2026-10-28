// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// A207: tenant SCIM tokens reload without a restart. The set re-reads its
// token files when one changes (size, modification time or file identity), at
// most every scimTokenRecheck, so rotating a token is writing its file. A
// reload that fails (an unreadable or empty file, a duplicate) keeps the last
// good set. Tenants, names and group maps come from the configuration, so
// adding a token is still a configuration change.

// scimTokenRecheck is a variable so a test can check on every request.
var scimTokenRecheck = 2 * time.Second

type scimTokenSet struct {
	entries []config.SCIMToken
	current atomic.Pointer[map[string]scimToken]

	mu      sync.Mutex
	checked time.Time
	stats   []os.FileInfo
	now     func() time.Time
}

// newSCIMTokenSet reads every configured token file once; a failure here stops
// startup like before.
func newSCIMTokenSet(entries []config.SCIMToken) (*scimTokenSet, error) {
	s := &scimTokenSet{entries: entries, now: time.Now}
	stats, err := statSCIMTokenFiles(entries)
	if err != nil {
		return nil, err
	}
	tokens, err := loadSCIMTokens(entries)
	if err != nil {
		return nil, err
	}
	s.current.Store(&tokens)
	s.stats, s.checked = stats, s.now()
	return s, nil
}

// lookup returns the token whose SHA-256 is hash, after refreshing the set
// when its files changed.
func (s *scimTokenSet) lookup(hash string) (scimToken, bool) {
	s.refresh()
	tokens := s.current.Load()
	if tokens == nil {
		return scimToken{}, false
	}
	tok, ok := (*tokens)[hash]
	return tok, ok
}

func (s *scimTokenSet) empty() bool {
	tokens := s.current.Load()
	return tokens == nil || len(*tokens) == 0
}

func (s *scimTokenSet) refresh() {
	if !s.mu.TryLock() {
		return // another request is refreshing; this one uses the current set
	}
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.checked) < scimTokenRecheck {
		return
	}
	s.checked = now
	stats, err := statSCIMTokenFiles(s.entries)
	if err != nil {
		slog.Default().Warn("scim token files unreadable; keeping the loaded tokens", slog.String("error", err.Error()))
		return
	}
	changed := false
	for i := range stats {
		if !sameSCIMTokenFile(s.stats[i], stats[i]) {
			changed = true
			break
		}
	}
	if !changed {
		return
	}
	tokens, err := loadSCIMTokens(s.entries)
	if err != nil {
		slog.Default().Warn("scim token reload refused; keeping the loaded tokens", slog.String("error", err.Error()))
		return
	}
	s.current.Store(&tokens)
	s.stats = stats
	slog.Default().Info("scim tokens reloaded", slog.Int("tokens", len(tokens)))
}

func statSCIMTokenFiles(entries []config.SCIMToken) ([]os.FileInfo, error) {
	stats := make([]os.FileInfo, len(entries))
	for i, tok := range entries {
		info, err := os.Stat(tok.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("auth.scim.tokens[%d].token_file: %w", i, err)
		}
		stats[i] = info
	}
	return stats, nil
}

func sameSCIMTokenFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

// loadSCIMTokens reads and hashes every token file, refusing an empty file and
// a token two entries share.
func loadSCIMTokens(entries []config.SCIMToken) (map[string]scimToken, error) {
	out := make(map[string]scimToken, len(entries))
	for i, tok := range entries {
		raw, err := secretfile.Load(tok.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("auth.scim.tokens[%d].token_file: %w", i, err)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			secret.Wipe(raw)
			return nil, fmt.Errorf("auth.scim.tokens[%d].token_file is empty", i)
		}
		hash := crypto.SHA256Hex(trimmed)
		secret.Wipe(raw)
		if _, dup := out[hash]; dup {
			return nil, fmt.Errorf("auth.scim.tokens[%d] duplicates another SCIM token", i)
		}
		normalized, ok := normalizeSCIMToken(tok.Name, tok.TenantID, hash, tok.SubjectAttribute, tok.GroupRoles)
		if !ok {
			continue
		}
		out[hash] = normalized
	}
	return out, nil
}

// staticSCIMTokens is a set that never reloads, for a handler built from
// token hashes rather than token files.
func staticSCIMTokens(tokens map[string]scimToken) *scimTokenSet {
	s := &scimTokenSet{now: time.Now}
	s.current.Store(&tokens)
	return s
}
