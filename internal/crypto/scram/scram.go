// SPDX-License-Identifier: BUSL-1.1

// Package scram is the client side of SCRAM-SHA-256 (RFC 5802, RFC 7677),
// shared by the access gateway's database sign-ins (A254, A256). The
// password stays byte-backed; Wipe clears the keys derived from it. The
// password is used as given: a caller whose server applies SASLprep sends
// only passwords SASLprep leaves unchanged (printable ASCII).
package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Client holds one exchange's state; Wipe clears its keys.
type Client struct {
	nonce, firstBare  string
	password          []byte
	salted, authBlock []byte
}

// New starts an exchange for a SASL user name (escaped here) with a nonce;
// the user name may be empty when the server takes it from elsewhere
// (PostgreSQL).
func New(user string, password []byte, nonce string) *Client {
	name := strings.NewReplacer("=", "=3D", ",", "=2C").Replace(user)
	return &Client{nonce: nonce, password: password, firstBare: "n=" + name + ",r=" + nonce}
}

// NewRandom starts an exchange with a fresh 18-byte nonce.
func NewRandom(user string, password []byte) (*Client, error) {
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return New(user, password, base64.StdEncoding.EncodeToString(nonce)), nil
}

// First is the client-first message (no channel binding).
func (c *Client) First() []byte { return []byte("n,," + c.firstBare) }

// Final answers the server-first message with the client-final message and
// its proof.
func (c *Client) Final(serverFirst []byte) ([]byte, error) {
	attrs := attributes(string(serverFirst))
	serverNonce, saltText, iterText := attrs["r"], attrs["s"], attrs["i"]
	if !strings.HasPrefix(serverNonce, c.nonce) || len(serverNonce) == len(c.nonce) {
		return nil, errors.New("scram: the server nonce does not extend the client's")
	}
	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("scram: the salt is malformed")
	}
	iterations, err := strconv.Atoi(iterText)
	if err != nil || iterations < 1 || iterations > 10_000_000 {
		return nil, errors.New("scram: the iteration count is out of range")
	}
	c.salted = pbkdf2SHA256(c.password, salt, iterations)
	clientKey := hmacSHA256(c.salted, []byte("Client Key"))
	defer secret.Wipe(clientKey)
	storedKey := sha256.Sum256(clientKey)
	withoutProof := "c=biws,r=" + serverNonce
	c.authBlock = []byte(c.firstBare + "," + string(serverFirst) + "," + withoutProof)
	signature := hmacSHA256(storedKey[:], c.authBlock)
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ signature[i]
	}
	return []byte(withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

// Verify checks the server-final message: the server proves it knows the
// password too.
func (c *Client) Verify(serverFinal []byte) error {
	attrs := attributes(string(serverFinal))
	if attrs["e"] != "" {
		return errors.New("scram: the server rejected the proof")
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil || c.salted == nil {
		return errors.New("scram: the server signature is malformed")
	}
	serverKey := hmacSHA256(c.salted, []byte("Server Key"))
	defer secret.Wipe(serverKey)
	if !hmac.Equal(got, hmacSHA256(serverKey, c.authBlock)) {
		return errors.New("scram: the server did not prove it knows the password")
	}
	return nil
}

// Wipe clears the salted password.
func (c *Client) Wipe() { secret.Wipe(c.salted) }

func attributes(message string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(message, ",") {
		if len(part) >= 2 && part[1] == '=' {
			out[part[:1]] = part[2:]
		}
	}
	return out
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// pbkdf2SHA256 is PBKDF2-HMAC-SHA-256 for one 32-byte block (RFC 8018), over
// a byte-backed password the caller wipes.
func pbkdf2SHA256(password, salt []byte, iterations int) []byte {
	u := hmacSHA256(password, append(append([]byte(nil), salt...), 0, 0, 0, 1))
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		next := hmacSHA256(password, u)
		secret.Wipe(u)
		u = next
		for j := range out {
			out[j] ^= u[j]
		}
	}
	secret.Wipe(u)
	return out
}
