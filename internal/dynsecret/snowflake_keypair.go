// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Snowflake key-pair rotation (A240): a role bound to "user <NAME>" rotates
// that existing user's key pair through the user's two key slots
// (RSA_PUBLIC_KEY and RSA_PUBLIC_KEY_2; Snowflake accepts a JWT signed by
// either key). The successor goes in the slot the predecessor is not in, so
// both keys work until retirement unsets the predecessor's slot, and only
// while that slot still holds the predecessor's key. The reference is
// "<NAME>/<slot>/<fingerprint>".

// snowflakeKeySlots are the user properties a key can occupy.
var snowflakeKeySlots = map[string]string{"1": "RSA_PUBLIC_KEY", "2": "RSA_PUBLIC_KEY_2"}

// SnowflakeKeyPairUser returns the user a role binding of "user <NAME>"
// names, and whether the binding is one.
func SnowflakeKeyPairUser(binding string) (string, bool) {
	fields := strings.Fields(binding)
	if len(fields) != 2 || fields[0] != "user" {
		return "", false
	}
	return strings.ToUpper(fields[1]), true
}

// userKeyFingerprints reads the fingerprints of the user's two key slots
// ("" for an empty slot).
func (b *SnowflakeBackend) userKeyFingerprints(ctx context.Context, user string) (map[string]string, error) {
	rows, err := b.query(ctx, fmt.Sprintf(`DESC USER "%s"`, user))
	if err != nil {
		return nil, err
	}
	slots := map[string]string{"1": "", "2": ""}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		for slot, property := range snowflakeKeySlots {
			if row[0] == property+"_FP" && row[1] != "null" {
				slots[slot] = row[1]
			}
		}
	}
	return slots, nil
}

// rotateKeyPair stages a new key pair for user in the slot the predecessor
// does not hold.
func (b *SnowflakeBackend) rotateKeyPair(ctx context.Context, user, predecessor string) (string, []byte, error) {
	slots, err := b.userKeyFingerprints(ctx, user)
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret snowflake: read %s's keys: %w", user, err)
	}
	target := ""
	switch keep, _, _ := strings.Cut(strings.TrimPrefix(predecessor, user+"/"), "/"); {
	case predecessor != "" && predecessor != "none" && strings.HasPrefix(predecessor, user+"/") && snowflakeKeySlots[keep] != "":
		// The predecessor's slot stays; the other takes the successor.
		target = map[string]string{"1": "2", "2": "1"}[keep]
	case slots["1"] == "":
		target = "1"
	case slots["2"] == "":
		target = "2"
	default:
		return "", nil, fmt.Errorf("dynsecret snowflake: both of %s's key slots are in use; name the one its consumers use in old_ref (%s/<1|2>/<fingerprint>)", user, user)
	}
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return "", nil, err
	}
	defer key.Destroy()
	privateKeyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(privateKeyPEM)
	fingerprint := SnowflakeKeyFingerprint(key.Public().DER)
	statement := fmt.Sprintf(`ALTER USER "%s" SET %s = '%s'`, user, snowflakeKeySlots[target], base64.StdEncoding.EncodeToString(key.Public().DER))
	if err := b.execute(ctx, statement); err != nil {
		return "", nil, fmt.Errorf("dynsecret snowflake: set %s's key: %w", user, err)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated key pair is this provider's output: the rotation seals it before storage (CWE-200)
		Account     string           `json:"account"`
		User        string           `json:"user"`
		PrivateKey  secret.JSONBytes `json:"private_key"`
		Fingerprint string           `json:"public_key_fingerprint"`
	}{Account: b.account, User: user, PrivateKey: privateKeyPEM, Fingerprint: fingerprint})
	if err != nil {
		return "", nil, err
	}
	return user + "/" + target + "/" + fingerprint, credential, nil
}

// retireKeyPair unsets the reference's slot if it still holds the
// reference's key; a slot already replaced or empty has nothing to retire.
func (b *SnowflakeBackend) retireKeyPair(ctx context.Context, ref string) error {
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) != 3 || !b.rotatesUser(parts[0]) || snowflakeKeySlots[parts[1]] == "" || !strings.HasPrefix(parts[2], "SHA256:") {
		return fmt.Errorf("dynsecret snowflake: refusing %q, which names no key slot of a user this provider rotates", ref)
	}
	slots, err := b.userKeyFingerprints(ctx, parts[0])
	if err != nil {
		return fmt.Errorf("dynsecret snowflake: read %s's keys: %w", parts[0], err)
	}
	if slots[parts[1]] != parts[2] {
		return nil
	}
	if err := b.execute(ctx, fmt.Sprintf(`ALTER USER "%s" UNSET %s`, parts[0], snowflakeKeySlots[parts[1]])); err != nil {
		return fmt.Errorf("dynsecret snowflake: unset %s's old key: %w", parts[0], err)
	}
	return nil
}

func (b *SnowflakeBackend) rotatesUser(user string) bool {
	for _, candidate := range b.keyPairUsers {
		if candidate == user {
			return true
		}
	}
	return false
}

// VerifyCredential proves a key pair by running SELECT 1 through the SQL API
// as its user, with a JWT the key signs.
func (b *SnowflakeBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Account    string           `json:"account"`
		User       string           `json:"user"`
		PrivateKey secret.JSONBytes `json:"private_key"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.User == "" || len(parsed.PrivateKey) == 0 {
		secret.Wipe(parsed.PrivateKey)
		return errors.New("dynsecret snowflake: the credential is not a user and private key")
	}
	defer secret.Wipe(parsed.PrivateKey)
	if !strings.EqualFold(parsed.Account, b.account) || !snowflakeUser.MatchString(strings.ToUpper(parsed.User)) {
		return errors.New("dynsecret snowflake: the credential names another account")
	}
	jwt, err := SnowflakeKeyPairJWT(b.account, parsed.User, parsed.PrivateKey, b.now())
	if err != nil {
		return fmt.Errorf("dynsecret snowflake: sign with the credential's key: %w", err)
	}
	body, _ := json.Marshal(map[string]any{"statement": "SELECT 1", "timeout": 30})
	status, _, err := b.call(ctx, http.MethodPost, "/api/v2/statements", jwt, body)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return fmt.Errorf("dynsecret snowflake: the key pair did not authenticate (HTTP %d)", status)
	}
	return nil
}

// query runs one statement as the administrator and returns its rows as
// strings (bounded: the SQL API's first partition).
func (b *SnowflakeBackend) query(ctx context.Context, statement string) ([][]string, error) {
	response, err := b.run(ctx, statement)
	if err != nil {
		return nil, err
	}
	var result struct {
		Data [][]*string `json:"data"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, errors.New("the SQL API's result is not the expected JSON")
	}
	rows := make([][]string, 0, len(result.Data))
	for _, raw := range result.Data {
		row := make([]string, len(raw))
		for i, cell := range raw {
			row[i] = "null"
			if cell != nil {
				row[i] = *cell
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
