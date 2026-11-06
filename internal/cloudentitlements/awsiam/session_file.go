// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// SessionFile borrows a fresh standard AWS STS JSON credential response from an
// owner-only local file for each call. The operator can atomically refresh the
// file; no long-lived access key or environment secret is accepted on this path.
func SessionFile(path string, now func() time.Time) func(context.Context, func(awssignin.Credentials) error) error {
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context, use func(awssignin.Credentials) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := secretfile.LoadBounded(path, 64<<10)
		defer secret.Wipe(raw)
		if err != nil {
			return errors.New("awsiam: session file custody/read failed")
		}
		if len(raw) > 64<<10 {
			return errors.New("awsiam: session file exceeds bound")
		}
		return useSessionJSON(raw, now(), use)
	}
}
func useSessionJSON(raw []byte, now time.Time, use func(awssignin.Credentials) error) error {
	if len(raw) == 0 || len(raw) > 64<<10 || use == nil {
		return errors.New("awsiam: invalid bounded session document")
	}
	var document struct {
		Credentials sessionValues `json:"Credentials"`
	}
	defer func() {
		secret.Wipe(document.Credentials.AccessKeyID)
		secret.Wipe(document.Credentials.SecretAccessKey)
		secret.Wipe(document.Credentials.SessionToken)
	}()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil {
		return errors.New("awsiam: invalid STS session document")
	}
	if len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return errors.New("awsiam: trailing STS session document")
	}
	return borrowSessionValues(document.Credentials, now, 36*time.Hour, use)
}

type sessionValues struct {
	AccessKeyID     secret.JSONBytes `json:"AccessKeyId"`
	SecretAccessKey secret.JSONBytes `json:"SecretAccessKey"`
	SessionToken    secret.JSONBytes `json:"SessionToken"`
	Expiration      time.Time        `json:"Expiration"`
}

func borrowSessionValues(c sessionValues, now time.Time, maxLifetime time.Duration, use func(awssignin.Credentials) error) error {
	if len(c.AccessKeyID) == 0 || len(c.AccessKeyID) > 256 || len(c.SecretAccessKey) == 0 || len(c.SecretAccessKey) > 1024 || len(c.SessionToken) == 0 || len(c.SessionToken) > 32<<10 || !now.Before(c.Expiration) || c.Expiration.After(now.Add(maxLifetime)) {
		return errors.New("awsiam: invalid or expired short-lived STS session")
	}
	for _, value := range [][]byte{c.AccessKeyID, c.SecretAccessKey, c.SessionToken} {
		if bytes.ContainsAny(value, "\r\n") {
			return errors.New("awsiam: invalid STS credential framing")
		}
	}
	id, err := secret.NewFrom(c.AccessKeyID)
	if err != nil {
		return err
	}
	defer id.Destroy()
	key, err := secret.NewFrom(c.SecretAccessKey)
	if err != nil {
		return err
	}
	defer key.Destroy()
	token, err := secret.NewFrom(c.SessionToken)
	if err != nil {
		return err
	}
	defer token.Destroy()
	secret.Wipe(c.AccessKeyID)
	secret.Wipe(c.SecretAccessKey)
	secret.Wipe(c.SessionToken)
	return id.Use(func(id []byte) error {
		return key.Use(func(key []byte) error {
			return token.Use(func(token []byte) error {
				return use(awssignin.Credentials{AccessKeyID: id, SecretAccessKey: key, SessionToken: token})
			})
		})
	})
}
