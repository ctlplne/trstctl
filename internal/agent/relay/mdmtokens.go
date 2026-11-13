// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"net/http"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/mdm"
)

const (
	// mdmTokenMargin is how much of a cached token's life must be left
	// for a job to reuse it.
	mdmTokenMargin = 2 * time.Minute
	// mdmTokenMaxLife bounds how long a token is kept, whatever the
	// identity provider says.
	mdmTokenMaxLife = time.Hour
	// mdmTokenCacheMax bounds the cache; the entry closest to expiry is
	// evicted first.
	mdmTokenCacheMax = 64
)

// mdmTokenCache keeps the MDM access tokens a relay exchanged across
// mdm.sync jobs (A156-L2), so a relay polling every few minutes makes one
// exchange per token lifetime instead of one per read. A token lives in
// locked memory, keyed by the token endpoint, the client ID and a digest of
// the client secret, so a rotated secret never reuses the old secret's
// token; it is reused only while more than mdmTokenMargin of its life is
// left, and wiped when it expires, is replaced, is refused by the MDM, or is
// evicted.
type mdmTokenCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*mdmCachedToken
}

type mdmCachedToken struct {
	buf     *secret.Buffer
	expires time.Time
}

func newMDMTokenCache(now func() time.Time) *mdmTokenCache {
	return &mdmTokenCache{now: now, entries: map[string]*mdmCachedToken{}}
}

// mdmTokens is the relay process's cache.
var mdmTokens = newMDMTokenCache(time.Now)

// mdmTokenKey names one credential: the endpoint it is exchanged at, the
// client ID and a digest of the secret.
func mdmTokenKey(endpoint, clientID string, clientSecret []byte) string {
	material := make([]byte, 0, len(endpoint)+len(clientID)+len(clientSecret)+2)
	material = append(material, endpoint...)
	material = append(material, 0)
	material = append(material, clientID...)
	material = append(material, 0)
	material = append(material, clientSecret...)
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material)
}

// get returns a copy of the cached token for key while enough of its life
// is left; the caller wipes the copy.
func (c *mdmTokenCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Add(mdmTokenMargin).Before(entry.expires) {
		entry.buf.Destroy()
		delete(c.entries, key)
		return nil, false
	}
	return append([]byte(nil), entry.buf.Bytes()...), true
}

// put keeps token for key for its lifetime (bounded); a lifetime too short
// to reuse keeps nothing. A failure to lock the memory keeps nothing either.
func (c *mdmTokenCache) put(key string, token []byte, lifetime time.Duration) {
	if lifetime > mdmTokenMaxLife {
		lifetime = mdmTokenMaxLife
	}
	if lifetime <= mdmTokenMargin || len(token) == 0 {
		return
	}
	buf, err := secret.NewFrom(token)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[key]; ok {
		old.buf.Destroy()
		delete(c.entries, key)
	}
	now := c.now()
	for key, entry := range c.entries {
		if !now.Before(entry.expires) {
			entry.buf.Destroy()
			delete(c.entries, key)
		}
	}
	for len(c.entries) >= mdmTokenCacheMax {
		var soonest string
		for key, entry := range c.entries {
			if soonest == "" || entry.expires.Before(c.entries[soonest].expires) {
				soonest = key
			}
		}
		c.entries[soonest].buf.Destroy()
		delete(c.entries, soonest)
	}
	c.entries[key] = &mdmCachedToken{buf: buf, expires: now.Add(lifetime)}
}

// drop forgets key's token, as when the MDM refused it.
func (c *mdmTokenCache) drop(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		entry.buf.Destroy()
		delete(c.entries, key)
	}
}

// len reports how many tokens are kept.
func (c *mdmTokenCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// mdmBearer is the bearer an MDM call carries (A156, A156-L1, A156-L2): the
// redeemed token itself, or the access token the redeemed client secret is
// exchanged for, taken from mdmTokens when one is kept.
type mdmBearer struct {
	token     []byte
	key       string
	exchange  func() (mdm.Grant, error)
	failure   func(error) string
	fromCache bool
	held      [][]byte
}

// newMDMBearer resolves the bearer for one job. A refusal is the job's
// failure detail.
func newMDMBearer(ctx context.Context, client *http.Client, kind, baseURL string, cc *mdm.ClientCredentials, jamf *mdm.JamfAPIClient,
	redeemed []byte) (*mdmBearer, string) {
	b := &mdmBearer{token: redeemed}
	switch {
	case cc != nil:
		if kind != mdm.MDMIntune {
			return nil, "client credentials are only valid for an Intune read"
		}
		endpoint, err := cc.TokenEndpoint()
		if err != nil {
			return nil, clientCredentialsFailure(err)
		}
		b.key = mdmTokenKey(endpoint, cc.Normalize().ClientID, redeemed)
		b.exchange = func() (mdm.Grant, error) { return mdm.ExchangeClientCredentialsGrant(ctx, client, *cc, redeemed) }
		b.failure = clientCredentialsFailure
	case jamf != nil:
		if kind != mdm.MDMJamf {
			return nil, "a Jamf Pro API client is only valid for a Jamf read"
		}
		endpoint, err := mdm.JamfTokenEndpoint(baseURL)
		if err != nil {
			return nil, jamfClientFailure(err)
		}
		b.key = mdmTokenKey(endpoint, jamf.ClientID, redeemed)
		b.exchange = func() (mdm.Grant, error) {
			return mdm.ExchangeJamfClientCredentialsGrant(ctx, client, baseURL, *jamf, redeemed)
		}
		b.failure = jamfClientFailure
	default:
		return b, ""
	}
	if cached, ok := mdmTokens.get(b.key); ok {
		b.token, b.fromCache = cached, true
		b.held = append(b.held, cached)
		return b, ""
	}
	if refusal := b.exchangeNow(); refusal != "" {
		b.close()
		return nil, refusal
	}
	return b, ""
}

func (b *mdmBearer) exchangeNow() string {
	grant, err := b.exchange()
	if err != nil {
		return b.failure(err)
	}
	b.held = append(b.held, grant.Token)
	mdmTokens.put(b.key, grant.Token, grant.Lifetime)
	b.token, b.fromCache = grant.Token, false
	return ""
}

// refused handles the MDM answering 401: a kept token is forgotten and
// exchanged once more (it reports whether to ask again, or the refusal);
// any other bearer stays refused.
func (b *mdmBearer) refused() (bool, string) {
	if !b.fromCache || b.exchange == nil {
		return false, ""
	}
	mdmTokens.drop(b.key)
	if refusal := b.exchangeNow(); refusal != "" {
		return false, refusal
	}
	return true, ""
}

// close wipes the copies this job held.
func (b *mdmBearer) close() {
	for _, held := range b.held {
		secret.Wipe(held)
	}
	b.held = nil
}
