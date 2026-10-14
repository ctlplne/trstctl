// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

var (
	ErrLogoutTokenReplay  = errors.New("auth: logout_token jti replay")
	ErrLogoutTokenInvalid = errors.New("auth: invalid logout_token")
)

type LogoutTokenClaims struct {
	Issuer    string
	ClientID  string
	Subject   string
	SID       string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
}

type logoutTokenClaims struct {
	Iss    string                     `json:"iss"`
	Aud    any                        `json:"aud"`
	Sub    string                     `json:"sub"`
	SID    string                     `json:"sid"`
	JTI    string                     `json:"jti"`
	Nonce  string                     `json:"nonce"`
	Exp    int64                      `json:"exp"`
	Iat    int64                      `json:"iat"`
	Events map[string]json.RawMessage `json:"events"`
}

type OIDCLogoutVerifier struct {
	Issuer   string
	ClientID string
	Keys     *jose.JWKSet
	Replay   *LogoutReplayCache
	Now      func() time.Time
}

func (v OIDCLogoutVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v OIDCLogoutVerifier) Verify(raw string) (LogoutTokenClaims, error) {
	if v.Keys == nil {
		return LogoutTokenClaims{}, ErrLogoutTokenInvalid
	}
	payload, err := v.Keys.Verify(raw)
	if err != nil {
		return LogoutTokenClaims{}, err
	}
	var c logoutTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return LogoutTokenClaims{}, err
	}
	if c.Iss != v.Issuer || !audienceMatches(c.Aud, v.ClientID) {
		return LogoutTokenClaims{}, ErrLogoutTokenInvalid
	}
	if _, ok := c.Events[backChannelLogoutEvent]; !ok || c.Nonce != "" || c.JTI == "" || (c.Sub == "" && c.SID == "") {
		return LogoutTokenClaims{}, ErrLogoutTokenInvalid
	}
	now := v.now().Unix()
	if c.Exp == 0 || c.Exp <= now || c.Iat <= 0 || c.Iat > now+60 {
		return LogoutTokenClaims{}, ErrLogoutTokenInvalid
	}
	if v.Replay != nil && !v.Replay.Accept(c.JTI, time.Unix(c.Exp, 0), v.now()) {
		return LogoutTokenClaims{}, ErrLogoutTokenReplay
	}
	return LogoutTokenClaims{
		Issuer: c.Iss, ClientID: v.ClientID, Subject: c.Sub, SID: c.SID,
		JTI: c.JTI, IssuedAt: c.Iat, ExpiresAt: c.Exp,
	}, nil
}

type LogoutReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewLogoutReplayCache() *LogoutReplayCache {
	return &LogoutReplayCache{seen: map[string]time.Time{}}
}

func (c *LogoutReplayCache) Accept(jti string, expiresAt, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[jti]; ok {
		return false
	}
	c.seen[jti] = expiresAt
	return true
}

// Release makes a verified assertion retryable only when its authority removal
// failed. The handler must call it before returning a retryable store error.
func (c *LogoutReplayCache) Release(jti string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, jti)
}
