// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const signTokenCommandTimeout = 10 * time.Second

type signTokenCommand struct {
	path    string
	timeout time.Duration
}

type signTokenCommandIntent struct {
	KeyHandle string `json:"key_handle"`
	Purpose   int32  `json:"purpose"`
	Hash      string `json:"hash"`
	Padding   string `json:"padding"`
	DigestB64 string `json:"digest_b64"`
}

func newSignTokenCommand(path string) signTokenCommand {
	return signTokenCommand{path: path, timeout: signTokenCommandTimeout}
}

// Authorize asks an independent approval-token authority to mint the signer token
// for this exact digest tuple. The command receives structured intent JSON on
// stdin and writes the raw token as base64 on stdout.
func (p signTokenCommand) Authorize(intent crypto.SignIntent) ([]byte, error) {
	if strings.TrimSpace(p.path) == "" {
		return nil, errPrivilegedSignerAuthorizationRequired
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = signTokenCommandTimeout
	}
	payload, err := json.Marshal(signTokenCommandIntent{
		KeyHandle: intent.KeyHandle,
		Purpose:   intent.Purpose,
		Hash:      string(intent.Hash),
		Padding:   string(intent.Padding),
		DigestB64: base64.StdEncoding.EncodeToString(intent.Digest),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signer authorization intent: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.path) // #nosec G204 -- operator-configured token-helper command (CWE-78)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("signer authorization command timed out: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("signer authorization command: %w", err)
	}
	defer secret.Wipe(out)
	tokenB64 := bytes.TrimSpace(out)
	token := make([]byte, base64.StdEncoding.DecodedLen(len(tokenB64)))
	n, err := base64.StdEncoding.Decode(token, tokenB64)
	if err != nil {
		secret.Wipe(token)
		return nil, fmt.Errorf("decode signer authorization token: %w", err)
	}
	token = token[:n]
	if len(token) == 0 {
		secret.Wipe(token)
		return nil, fmt.Errorf("signer authorization command returned an empty token")
	}
	return token, nil
}
