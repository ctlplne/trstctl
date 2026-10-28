// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// The Vault-compatible API reports a database lease the way Vault's database
// engine does, as a username and a password, while the providers issue one
// connection credential. These helpers take the issued credential apart for that
// view; the provider's credential format stays the native API's.

// SplitCredentialUserinfo returns the user and password inside a credential a
// database provider issued: a PostgreSQL URI or keyword DSN, a MySQL DSN, or a
// MongoDB or Redis URI. The password is a new slice the caller wipes.
func SplitCredentialUserinfo(providerType string, credential []byte) (string, []byte, error) {
	switch providerType {
	case "postgresql":
		if _, _, _, _, ok := splitURIAuthority(credential); ok {
			return uriCredentialUserinfo(credential)
		}
		return postgresKeywordUserinfo(credential)
	case "mongodb":
		return uriCredentialUserinfo(credential)
	case "redis":
		return redisCredentialUserinfo(credential)
	case "mysql":
		// user:password@tcp(host)/database; generated names and passwords
		// carry no ':' or '@'.
		at := bytes.LastIndex(credential, []byte("@tcp("))
		colon := bytes.IndexByte(credential, ':')
		if at <= 0 || colon <= 0 || colon > at {
			return "", nil, errors.New("dynsecret mysql: credential is not a user:password DSN")
		}
		if colon+1 == at {
			return "", nil, errors.New("dynsecret mysql: credential has no password")
		}
		return string(credential[:colon]), bytes.Clone(credential[colon+1 : at]), nil
	default:
		return "", nil, fmt.Errorf("dynsecret: provider type %q issues no user and password", providerType)
	}
}

// uriCredentialUserinfo reads scheme://user:password@host... with both parts
// percent-decoded.
func uriCredentialUserinfo(credential []byte) (string, []byte, error) {
	_, authorityStart, _, hostStart, ok := splitURIAuthority(credential)
	if !ok || hostStart <= authorityStart {
		return "", nil, errors.New("dynsecret: credential URI has no user information")
	}
	userinfo := credential[authorityStart : hostStart-1]
	colon := bytes.IndexByte(userinfo, ':')
	if colon <= 0 {
		return "", nil, errors.New("dynsecret: credential URI has no user and password")
	}
	user, okUser := percentDecode(userinfo[:colon])
	password, okPassword := percentDecode(userinfo[colon+1:])
	if !okUser || !okPassword || len(password) == 0 {
		secret.Wipe(password)
		return "", nil, errors.New("dynsecret: credential URI user information is malformed")
	}
	return string(user), password, nil
}

// postgresKeywordUserinfo reads the user= and password= keywords of a
// PostgreSQL keyword DSN.
func postgresKeywordUserinfo(credential []byte) (string, []byte, error) {
	tokens, err := parsePGConnTokens(credential)
	if err != nil {
		return "", nil, errors.New("dynsecret postgres: credential is not a keyword DSN")
	}
	var user string
	var password []byte
	for _, token := range tokens {
		switch {
		case bytes.EqualFold(token.key, []byte("user")):
			value, ok := decodePGConnValue(token.raw)
			if !ok {
				secret.Wipe(password)
				return "", nil, errors.New("dynsecret postgres: credential user is malformed")
			}
			user = string(value)
		case bytes.EqualFold(token.key, []byte("password")):
			value, ok := decodePGConnValue(token.raw)
			if !ok {
				secret.Wipe(password)
				return "", nil, errors.New("dynsecret postgres: credential password is malformed")
			}
			secret.Wipe(password)
			password = value
		}
	}
	if user == "" || len(password) == 0 {
		secret.Wipe(password)
		return "", nil, errors.New("dynsecret postgres: credential has no user and password")
	}
	return user, password, nil
}

// KubernetesServiceAccountName is the ServiceAccount a Kubernetes lease's
// provider reference names.
func KubernetesServiceAccountName(backendRef string) (string, bool) {
	var ref kubernetesProviderRef
	if err := json.Unmarshal([]byte(backendRef), &ref); err == nil && ref.Name != "" {
		return ref.Name, true
	}
	// Leases from older builds stored the bare object name.
	if backendRef != "" && !strings.ContainsAny(backendRef, "{}\" /") {
		return backendRef, true
	}
	return "", false
}

// AWSSTSSessionARN is the assumed-role ARN of an AWS STS lease's session, as
// AWS reports it to the session's caller (sts:GetCallerIdentity).
func AWSSTSSessionARN(backendRef string) (string, bool) {
	var ref awsSTSRef
	if err := json.Unmarshal([]byte(backendRef), &ref); err != nil || ref.RoleARN == "" || ref.SessionName == "" {
		return "", false
	}
	// arn:<partition>:iam::<account>:role/<path/>name
	parts := strings.SplitN(ref.RoleARN, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return "", false
	}
	resource := strings.TrimPrefix(parts[5], "role/")
	name := resource[strings.LastIndexByte(resource, '/')+1:]
	if name == "" {
		return "", false
	}
	return "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/" + name + "/" + ref.SessionName, true
}
