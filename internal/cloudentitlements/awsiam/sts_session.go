// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// UseLeaseCredential borrows the existing dynamic provider's reveal-once JSON
// payload. The parsed copies are locked before use and wiped before return.
// It accepts temporary STS credentials only, with exact unambiguous field names.
func UseLeaseCredential(raw []byte, now time.Time, use func(awssignin.Credentials) error) error {
	if len(raw) == 0 || len(raw) > 64<<10 || use == nil {
		return errors.New("awsiam: invalid bounded lease credential")
	}
	var c sessionValues
	defer func() { secret.Wipe(c.AccessKeyID); secret.Wipe(c.SecretAccessKey); secret.Wipe(c.SessionToken) }()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("awsiam: STS lease credential must be an object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("awsiam: duplicate or invalid STS credential field")
		}
		seen[name] = true
		switch name {
		case "access_key_id":
			err = decoder.Decode(&c.AccessKeyID)
		case "secret_access_key":
			err = decoder.Decode(&c.SecretAccessKey)
		case "session_token":
			err = decoder.Decode(&c.SessionToken)
		case "expiration":
			err = decoder.Decode(&c.Expiration)
		default:
			return errors.New("awsiam: unknown STS lease credential field")
		}
		if err != nil {
			return errors.New("awsiam: invalid STS lease credential value")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return errors.New("awsiam: incomplete or trailing STS lease credential")
	}
	return borrowSessionValues(c, now, 12*time.Hour, use)
}

type SessionIdentity struct{ ARN, AccountID, UserID string }

// VerifyAssumedRole signs GetCallerIdentity with the borrowed temporary session.
// It verifies the native caller against one of the configured allowed IAM roles;
// this proves native identity, not authorization to every downstream resource.
func VerifyAssumedRole(ctx context.Context, cfg Config, allowedRoles []string) (SessionIdentity, error) {
	if len(allowedRoles) == 0 || len(allowedRoles) > 128 {
		return SessionIdentity{}, errors.New("awsiam: bounded allowed role bindings required")
	}
	cfg.Endpoint = STSEndpoint(cfg.Region, cfg.Endpoint)
	client, err := New(cfg)
	if err != nil {
		return SessionIdentity{}, err
	}
	session := &captureSession{c: client}
	// The inventory query allowlist remains IAM-only. This separate read has a
	// fixed action, protocol version and signing scope, with the same byte custody.
	result, err := session.requestQuery(ctx, "GetCallerIdentity", url.Values{}, false, "sts", "2011-06-15")
	if err != nil {
		return SessionIdentity{}, err
	}
	var identity SessionIdentity
	identity.ARN, err = result.value("Arn")
	if err != nil {
		return SessionIdentity{}, err
	}
	identity.AccountID, err = result.value("Account")
	if err != nil {
		return SessionIdentity{}, err
	}
	identity.UserID, err = result.value("UserId")
	if err != nil || len(identity.ARN) > 2048 || len(identity.UserID) > 256 || len(identity.AccountID) != 12 || !strings.Contains(identity.UserID, ":") {
		return SessionIdentity{}, errors.New("awsiam: incomplete STS native caller")
	}
	for _, digit := range identity.AccountID {
		if digit < '0' || digit > '9' {
			return SessionIdentity{}, errors.New("awsiam: invalid native caller account")
		}
	}
	nativeRoleID, nativeSession, ok := strings.Cut(identity.UserID, ":")
	if !ok || !strings.HasPrefix(nativeRoleID, "AROA") || !validateName(nativeRoleID) || !validateName(nativeSession) {
		return SessionIdentity{}, errors.New("awsiam: invalid assumed role native ID")
	}
	for _, arn := range allowedRoles {
		fields := strings.SplitN(arn, ":", 6)
		if len(fields) != 6 || fields[0] != "arn" || (fields[1] != "aws" && fields[1] != "aws-us-gov" && fields[1] != "aws-cn") || fields[2] != "iam" || fields[3] != "" || fields[4] != identity.AccountID || !strings.HasPrefix(fields[5], "role/") {
			continue
		}
		name := fields[5][strings.LastIndex(fields[5], "/")+1:]
		if !validateName(name) {
			continue
		}
		prefix := "arn:" + fields[1] + ":sts::" + fields[4] + ":assumed-role/" + name + "/"
		if sessionName, ok := strings.CutPrefix(identity.ARN, prefix); ok && sessionName == nativeSession && len(sessionName) <= 64 && validateName(sessionName) {
			return identity, nil
		}
	}
	return SessionIdentity{}, errors.New("awsiam: STS caller is outside the configured allowed roles")
}

// STSEndpoint resolves the same fixed origin for egress admission and signing.
func STSEndpoint(region, endpoint string) string {
	if endpoint != "" {
		return endpoint
	}
	if region == "" {
		region = "us-east-1"
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix += ".cn"
	}
	return "https://sts." + region + "." + suffix
}
