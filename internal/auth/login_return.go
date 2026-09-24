// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ErrLoginReturn means the short-lived login destination cannot be trusted.
var ErrLoginReturn = errors.New("auth: invalid login return context")

const maxLoginReturnToken = 7000

func validLoginReturnField(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

// SealLoginReturn binds a destination to one login attempt for ten minutes.
// The destination is authenticated, not encrypted; callers must validate it as
// a local UI path both before sealing and after opening. It is not a session.
// Instances sharing the session secret can open it without process affinity.
func (s *SessionIssuer) SealLoginReturn(purpose, state, requestID, destination string) (string, error) {
	if s == nil || len(s.secret) < 32 || !validLoginReturnField(purpose, 64) ||
		!validLoginReturnField(state, 128) || !validLoginReturnField(requestID, 512) ||
		!validLoginReturnField(destination, 4096) {
		return "", ErrLoginReturn
	}
	now := s.now().Unix()
	if now <= 0 {
		return "", ErrLoginReturn
	}
	// A bounded byte envelope preserves raw UTF-8 and avoids JSON escape growth.
	payload := make([]byte, 0, 32+len(state)+len(requestID)+len(destination))
	payload = append(payload, '1', 0)
	payload = strconv.AppendInt(payload, now, 10)
	for _, field := range []string{state, requestID, destination} {
		payload = append(payload, 0)
		payload = append(payload, field...)
	}
	defer secret.Wipe(payload)
	key := s.loginReturnKey(purpose)
	defer secret.Wipe(key)
	mac := crypto.HMACSHA256(key, payload)
	defer secret.Wipe(mac)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// OpenLoginReturn verifies the signature, age, purpose and login correlation.
// Missing legacy contexts are handled by the caller; a supplied invalid context
// must not be silently accepted or replaced with callback parameters.
func (s *SessionIssuer) OpenLoginReturn(purpose, state, requestID, token string) (string, error) {
	if s == nil || len(s.secret) < 32 || !validLoginReturnField(purpose, 64) ||
		!validLoginReturnField(state, 128) || !validLoginReturnField(requestID, 512) ||
		len(token) == 0 || len(token) > maxLoginReturnToken {
		return "", ErrLoginReturn
	}
	encoded, signature, ok := strings.Cut(token, ".")
	if !ok || len(signature) != 43 {
		return "", ErrLoginReturn
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", ErrLoginReturn
	}
	defer secret.Wipe(payload)
	mac, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(mac) != 32 {
		return "", ErrLoginReturn
	}
	defer secret.Wipe(mac)
	key := s.loginReturnKey(purpose)
	defer secret.Wipe(key)
	want := crypto.HMACSHA256(key, payload)
	defer secret.Wipe(want)
	if !crypto.ConstantTimeEqual(mac, want) {
		return "", ErrLoginReturn
	}
	fields := bytes.Split(payload, []byte{0})
	if len(fields) != 5 || string(fields[0]) != "1" {
		return "", ErrLoginReturn
	}
	issued, err := strconv.ParseInt(string(fields[1]), 10, 64)
	now := s.now().Unix()
	if err != nil || issued <= 0 || issued > now || now-issued >= 600 ||
		strconv.FormatInt(issued, 10) != string(fields[1]) ||
		!crypto.ConstantTimeEqual(fields[2], []byte(state)) ||
		!crypto.ConstantTimeEqual(fields[3], []byte(requestID)) ||
		len(fields[4]) == 0 || len(fields[4]) > 4096 {
		return "", ErrLoginReturn
	}
	return string(fields[4]), nil
}

func (s *SessionIssuer) loginReturnKey(purpose string) []byte {
	return crypto.HMACSHA256(s.secret, []byte("trstctl/login-return/v1\x00"+purpose))
}
