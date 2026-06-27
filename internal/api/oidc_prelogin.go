package api

import (
	"errors"
	"net"
	"net/http"
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
	mu      sync.Mutex
	now     func() time.Time
	ttl     time.Duration
	entries map[string]oidcPreLoginEntry
}

func newOIDCPreLoginStore(ttl time.Duration) *oidcPreLoginStore {
	if ttl <= 0 {
		ttl = defaultOIDCPreLoginTTL
	}
	return &oidcPreLoginStore{now: time.Now, ttl: ttl, entries: map[string]oidcPreLoginEntry{}}
}

func (s *oidcPreLoginStore) create(state, nonce, verifier, clientIP, userAgent string) (string, error) {
	id, err := auth.RandomState()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	s.entries[id] = oidcPreLoginEntry{
		State: state, Nonce: nonce, PKCEVerifier: verifier,
		ClientIP: clientIP, UserAgent: userAgent, ExpiresAt: now.Add(s.ttl),
	}
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
	delete(s.entries, id)
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
		}
	}
}

func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
