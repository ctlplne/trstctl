// Package mdm provides the dynamic SCEP challenge that MDM/EMM platforms (Microsoft
// Intune, JAMF) inject into a managed device's SCEP profile so that only a device the MDM
// provisioned can enroll (S8.5). The challenge is a short-lived, HMAC-authenticated token
// {expiry, nonce, mac} that trustctl validates with no server-side state — the SCEP server
// reads it from the request's challengePassword and calls Validate before issuing.
//
// This is the integration *mechanism* Intune/JAMF SCEP connectors rely on; the deeper
// Intune Graph / JAMF API provisioning flow (creating the device profile) is an
// out-of-band, account-specific step and is out of scope here.
package mdm

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"trustctl.io/trustctl/internal/crypto"
)

// Challenge issues and validates dynamic SCEP challenge passwords.
type Challenge struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// Option configures a Challenge.
type Option func(*Challenge)

// WithClock overrides the time source (for tests).
func WithClock(now func() time.Time) Option { return func(c *Challenge) { c.now = now } }

// New returns a Challenge that signs tokens with key and issues them valid for ttl.
func New(key []byte, ttl time.Duration, opts ...Option) *Challenge {
	c := &Challenge{key: append([]byte(nil), key...), ttl: ttl, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Challenge) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Issue returns a fresh challenge password valid for the configured TTL.
func (c *Challenge) Issue() (string, error) {
	nonce, err := crypto.RandomBytes(12)
	if err != nil {
		return "", err
	}
	return c.token(c.clock().Add(c.ttl).Unix(), nonce), nil
}

// Validate reports whether token is well-formed, MAC-authentic, and unexpired. It fails
// closed on any defect.
func (c *Challenge) Validate(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("mdm: malformed challenge")
	}
	dec := base64.RawURLEncoding.DecodeString
	expb, err1 := dec(parts[0])
	nonce, err2 := dec(parts[1])
	mac, err3 := dec(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(expb) != 8 {
		return errors.New("mdm: malformed challenge")
	}
	if !crypto.ConstantTimeEqual(mac, c.mac(expb, nonce)) {
		return errors.New("mdm: challenge authentication failed")
	}
	if c.clock().Unix() > int64(binary.BigEndian.Uint64(expb)) {
		return errors.New("mdm: challenge expired")
	}
	return nil
}

// Validator adapts Validate to the SCEP server's ChallengeValidator hook.
func (c *Challenge) Validator() func(string) error { return c.Validate }

func (c *Challenge) token(exp int64, nonce []byte) string {
	expb := make([]byte, 8)
	binary.BigEndian.PutUint64(expb, uint64(exp))
	enc := base64.RawURLEncoding.EncodeToString
	return enc(expb) + "." + enc(nonce) + "." + enc(c.mac(expb, nonce))
}

func (c *Challenge) mac(expb, nonce []byte) []byte {
	msg := make([]byte, 0, len(expb)+len(nonce))
	msg = append(msg, expb...)
	msg = append(msg, nonce...)
	return crypto.HMACSHA256(c.key, msg)
}
