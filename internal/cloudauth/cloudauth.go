// SPDX-License-Identifier: MPL-2.0

// Package cloudauth owns the provider-neutral short-lived cloud credential
// minter used by bounded outbox workers. It keeps authority-bearing bytes in
// locked, non-dumpable buffers, caches them only until a refresh-before-expiry
// boundary, and destroys every cached or caller-owned copy explicitly.
//
// Provider packages contribute only thin HTTP request/response encoders. AWS is
// the first served encoder; GCP and Azure must instantiate this same cache and
// exchange seam rather than grow parallel authentication stacks.
package cloudauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ErrOfflineDisabled is returned before any network request when the deployment
// has air-gap enforcement enabled. The outbox treats it as a terminal, honestly
// reported disabled state instead of retrying a connection that policy forbids.
var ErrOfflineDisabled = errors.New("cloud workload identity is disabled by air-gap policy")

// ErrInvalidWorkloadProof is deliberately closed and content-free. A rejected
// JWT is attacker-controlled authority material and must never flow into durable
// outbox errors, logs, receipts, or problem details.
var ErrInvalidWorkloadProof = errors.New("cloud workload identity proof failed validation")

// Material is one provider exchange result before it enters locked memory.
// Primary and Secondary are mutable secret bytes and are always wiped by Mint,
// including when validation or locked allocation fails. Identifier is a
// provider-visible credential identifier (AWS access key id), not a secret.
type Material struct {
	Identifier string
	Primary    []byte
	Secondary  []byte
	ExpiresAt  time.Time
}

// Credential is a caller-owned locked copy of one cached short-lived result.
// Callers must call Destroy after the single external operation completes.
type Credential struct {
	Identifier string
	Primary    *secret.Buffer
	Secondary  *secret.Buffer
	ExpiresAt  time.Time
}

// Destroy wipes both secret buffers. It is safe to call more than once.
func (c *Credential) Destroy() {
	if c == nil {
		return
	}
	if c.Primary != nil {
		c.Primary.Destroy()
		c.Primary = nil
	}
	if c.Secondary != nil {
		c.Secondary.Destroy()
		c.Secondary = nil
	}
}

type cachedCredential struct {
	identifier string
	primary    *secret.Buffer
	secondary  *secret.Buffer
	expiresAt  time.Time
}

func (c *cachedCredential) destroy() {
	if c == nil {
		return
	}
	if c.primary != nil {
		c.primary.Destroy()
		c.primary = nil
	}
	if c.secondary != nil {
		c.secondary.Destroy()
		c.secondary = nil
	}
}

type cacheEntry struct {
	mu         sync.Mutex
	credential *cachedCredential
	expiry     *time.Timer
}

// Minter provides one shared, per-source refresh cache. Distinct source keys do
// not share a network lock, so a slow provider cannot block another connector.
type Minter struct {
	mu            sync.Mutex
	entries       map[string]*cacheEntry
	refreshBefore time.Duration
	now           func() time.Time
	closed        bool
}

// NewMinter constructs a cache that refreshes credentials before their provider
// expiry. A non-positive duration uses a conservative two-minute window.
func NewMinter(refreshBefore time.Duration) *Minter {
	if refreshBefore <= 0 {
		refreshBefore = 2 * time.Minute
	}
	return &Minter{
		entries:       make(map[string]*cacheEntry),
		refreshBefore: refreshBefore,
		now:           time.Now,
	}
}

// Mint returns a locked caller-owned credential. exchange runs only on a cache
// miss or inside the refresh window, so it is the sole closure that may perform
// the provider POST. key is non-secret tenant/source identity.
func (m *Minter) Mint(ctx context.Context, key string, exchange func(context.Context) (Material, error)) (*Credential, bool, error) {
	if m == nil {
		return nil, false, errors.New("cloudauth: minter is not configured")
	}
	if key == "" || exchange == nil {
		return nil, false, errors.New("cloudauth: cache key and exchange are required")
	}
	entry, err := m.entry(key)
	if err != nil {
		return nil, false, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := m.now().UTC()
	if entry.credential != nil && now.Add(m.refreshBefore).Before(entry.credential.expiresAt) {
		out, err := cloneCredential(entry.credential)
		return out, true, err
	}

	material, err := exchange(ctx)
	defer secret.Wipe(material.Primary)
	defer secret.Wipe(material.Secondary)
	if err != nil {
		return nil, false, err
	}
	if material.Identifier == "" || len(material.Primary) == 0 || material.ExpiresAt.IsZero() {
		return nil, false, errors.New("cloudauth: exchange returned incomplete credential material")
	}
	if !material.ExpiresAt.After(now.Add(m.refreshBefore)) {
		return nil, false, errors.New("cloudauth: exchange returned a credential inside the refresh window")
	}
	primary, err := secret.NewFrom(material.Primary)
	if err != nil {
		return nil, false, fmt.Errorf("cloudauth: lock primary credential: %w", err)
	}
	var secondary *secret.Buffer
	if len(material.Secondary) > 0 {
		secondary, err = secret.NewFrom(material.Secondary)
		if err != nil {
			primary.Destroy()
			return nil, false, fmt.Errorf("cloudauth: lock secondary credential: %w", err)
		}
	}
	next := &cachedCredential{
		identifier: material.Identifier,
		primary:    primary,
		secondary:  secondary,
		expiresAt:  material.ExpiresAt.UTC(),
	}
	out, err := cloneCredential(next)
	if err != nil {
		next.destroy()
		return nil, false, err
	}
	if entry.credential != nil {
		entry.credential.destroy()
	}
	entry.credential = next
	if entry.expiry != nil {
		entry.expiry.Stop()
	}
	// A cache miss is not required to clean up authority. Even if this source is
	// never used again, provider expiry destroys the locked cached copy.
	entry.expiry = time.AfterFunc(next.expiresAt.Sub(now), func() {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.credential == next {
			next.destroy()
			entry.credential = nil
			entry.expiry = nil
		}
	})
	return out, false, nil
}

func (m *Minter) entry(key string) (*cacheEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("cloudauth: minter is closed")
	}
	entry := m.entries[key]
	if entry == nil {
		entry = &cacheEntry{}
		m.entries[key] = entry
	}
	return entry, nil
}

func cloneCredential(in *cachedCredential) (*Credential, error) {
	primary, err := secret.NewFrom(in.primary.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cloudauth: clone primary credential: %w", err)
	}
	var secondary *secret.Buffer
	if in.secondary != nil && in.secondary.Len() > 0 {
		secondary, err = secret.NewFrom(in.secondary.Bytes())
		if err != nil {
			primary.Destroy()
			return nil, fmt.Errorf("cloudauth: clone secondary credential: %w", err)
		}
	}
	return &Credential{
		Identifier: in.identifier,
		Primary:    primary,
		Secondary:  secondary,
		ExpiresAt:  in.expiresAt,
	}, nil
}

// Close destroys every cached credential and prevents future exchanges.
func (m *Minter) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	entries := m.entries
	m.entries = nil
	m.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		if entry.expiry != nil {
			entry.expiry.Stop()
			entry.expiry = nil
		}
		entry.credential.destroy()
		entry.credential = nil
		entry.mu.Unlock()
	}
}

// ValidateOIDCProof verifies a byte-native JWT against tenant-owned public JWKS
// and enforces exact issuer, audience, subject, and validity-window bindings.
// Every failure collapses to ErrInvalidWorkloadProof so token content cannot be
// reflected into a durable error.
func ValidateOIDCProof(proof, jwksJSON []byte, expectedIssuer, expectedAudience, expectedSubject string, now time.Time) error {
	if len(proof) == 0 || len(jwksJSON) == 0 || expectedIssuer == "" || expectedAudience == "" || expectedSubject == "" {
		return ErrInvalidWorkloadProof
	}
	jwks, err := crypto.ParseJWKS(jwksJSON)
	if err != nil {
		return ErrInvalidWorkloadProof
	}
	claimsJSON, err := crypto.VerifyJWTBytes(proof, jwks)
	if err != nil {
		return ErrInvalidWorkloadProof
	}
	defer secret.Wipe(claimsJSON)
	var claims struct {
		Issuer    string          `json:"iss"`
		Subject   string          `json:"sub"`
		Audience  json.RawMessage `json:"aud"`
		ExpiresAt json.Number     `json:"exp"`
		NotBefore json.Number     `json:"nbf"`
	}
	decoder := json.NewDecoder(bytes.NewReader(claimsJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return ErrInvalidWorkloadProof
	}
	if claims.Issuer != expectedIssuer || claims.Subject != expectedSubject || !audienceContains(claims.Audience, expectedAudience) {
		return ErrInvalidWorkloadProof
	}
	exp, err := claims.ExpiresAt.Int64()
	if err != nil || exp <= now.UTC().Unix() {
		return ErrInvalidWorkloadProof
	}
	if claims.NotBefore != "" {
		nbf, err := claims.NotBefore.Int64()
		if err != nil || nbf > now.UTC().Add(30*time.Second).Unix() {
			return ErrInvalidWorkloadProof
		}
	}
	return nil
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == expected
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, audience := range many {
		if audience == expected {
			return true
		}
	}
	return false
}
