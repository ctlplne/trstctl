package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auth"
)

const defaultOIDCPreLoginTTL = 10 * time.Minute

var errOIDCPreLoginNotFound = errors.New("oidc pre-login state not found")

type oidcPreLoginEntry struct {
	State        string
	Nonce        string
	PKCEVerifier string
	ClientIP     string
	UserAgent    string
	ExpiresAt    time.Time
}

type oidcPreLoginStore struct {
	mu           sync.Mutex
	now          func() time.Time
	ttl          time.Duration
	limits       oidcPreLoginLimits
	entries      map[string]oidcPreLoginEntry
	sourceCounts map[string]int
}

type oidcPreLoginLimits struct {
	MaxEntries   int
	MaxPerSource int
}

type oidcPreLoginCapacityError struct {
	retryAfter time.Duration
}

func (e oidcPreLoginCapacityError) Error() string {
	return "OIDC pre-login store is over capacity"
}

func newOIDCPreLoginStore(ttl time.Duration, limits oidcPreLoginLimits) *oidcPreLoginStore {
	if ttl <= 0 {
		ttl = defaultOIDCPreLoginTTL
	}
	if limits.MaxEntries <= 0 {
		limits.MaxEntries = defaultOIDCPreLoginMaxEntries
	}
	if limits.MaxPerSource <= 0 {
		limits.MaxPerSource = defaultOIDCPreLoginMaxEntriesPerSource
	}
	return &oidcPreLoginStore{
		now:          time.Now,
		ttl:          ttl,
		limits:       limits,
		entries:      map[string]oidcPreLoginEntry{},
		sourceCounts: map[string]int{},
	}
}

func (s *oidcPreLoginStore) create(state, nonce, verifier, clientIP, userAgent string) (string, error) {
	id, err := auth.RandomState()
	if err != nil {
		return "", err
	}
	source := normalizePreLoginSource(clientIP)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	if retryAfter, over := s.capacityRetryAfterLocked(now, source); over {
		return "", oidcPreLoginCapacityError{retryAfter: retryAfter}
	}
	if old, ok := s.entries[id]; ok {
		s.decrementSourceLocked(old.ClientIP)
	}
	s.entries[id] = oidcPreLoginEntry{
		State: state, Nonce: nonce, PKCEVerifier: verifier,
		ClientIP: source, UserAgent: userAgent, ExpiresAt: now.Add(s.ttl),
	}
	s.sourceCounts[source]++
	return id, nil
}

func (s *oidcPreLoginStore) consume(id string) (oidcPreLoginEntry, error) {
	if id == "" {
		return oidcPreLoginEntry{}, errOIDCPreLoginNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entry, ok := s.entries[id]
	if ok {
		delete(s.entries, id)
		s.decrementSourceLocked(entry.ClientIP)
	}
	s.pruneLocked(now)
	if !ok || !entry.ExpiresAt.After(now) {
		return oidcPreLoginEntry{}, errOIDCPreLoginNotFound
	}
	return entry, nil
}

func (s *oidcPreLoginStore) pruneLocked(now time.Time) {
	for id, entry := range s.entries {
		if !entry.ExpiresAt.After(now) {
			delete(s.entries, id)
			s.decrementSourceLocked(entry.ClientIP)
		}
	}
}

func (s *oidcPreLoginStore) decrementSourceLocked(source string) {
	source = normalizePreLoginSource(source)
	count := s.sourceCounts[source]
	if count <= 1 {
		delete(s.sourceCounts, source)
		return
	}
	s.sourceCounts[source] = count - 1
}

func (s *oidcPreLoginStore) capacityRetryAfterLocked(now time.Time, source string) (time.Duration, bool) {
	var retryAfter time.Duration
	if len(s.entries) >= s.limits.MaxEntries {
		retryAfter = maxDuration(retryAfter, s.retryAfterForLocked(now, ""))
	}
	if s.sourceCounts[source] >= s.limits.MaxPerSource {
		retryAfter = maxDuration(retryAfter, s.retryAfterForLocked(now, source))
	}
	if retryAfter <= 0 {
		return 0, false
	}
	return retryAfter, true
}

func (s *oidcPreLoginStore) retryAfterForLocked(now time.Time, source string) time.Duration {
	var earliest time.Time
	for _, entry := range s.entries {
		if source != "" && normalizePreLoginSource(entry.ClientIP) != source {
			continue
		}
		if earliest.IsZero() || entry.ExpiresAt.Before(earliest) {
			earliest = entry.ExpiresAt
		}
	}
	if earliest.IsZero() {
		return s.ttl
	}
	retryAfter := earliest.Sub(now)
	if retryAfter <= 0 {
		return time.Second
	}
	return retryAfter
}

func normalizePreLoginSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "unknown"
	}
	return source
}

func maxDuration(a, b time.Duration) time.Duration {
	if b > a {
		return b
	}
	return a
}

func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
