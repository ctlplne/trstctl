// SPDX-License-Identifier: MPL-2.0

// Command notation-trstctl is a Notation plugin (plugin contract 1.0,
// SIGNATURE_GENERATOR.RAW) that signs with a key held in trstctl's isolated
// signer. Notation hands it the bytes to sign; it hashes them, asks trstctl's
// code-signing API to sign the digest — trstctl's policy and approvals apply,
// and the key never leaves the signer — and returns the signature with the
// certificate chain configured for the key.
//
//	notation plugin install --file notation-trstctl
//	notation key add release --plugin trstctl --id <code-signing key id>
//	TRSTCTL_URL=… TRSTCTL_TOKEN=… notation sign --key release registry.example/app@sha256:…
package main

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"trstctl.com/clients/signing/trstctlsign"
)

const contractVersion = "1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, trstctlsign.FromEnv))
}

type pluginError struct {
	Code    string `json:"errorCode"`
	Message string `json:"errorMessage"`
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, newClient func() (*trstctlsign.Client, error)) int {
	fail := func(code string, err error) int {
		_ = json.NewEncoder(stderr).Encode(pluginError{Code: code, Message: err.Error()})
		return 1
	}
	if len(args) != 1 {
		return fail("VALIDATION_ERROR", errors.New("usage: notation-trstctl get-plugin-metadata|describe-key|generate-signature"))
	}
	var response any
	switch args[0] {
	case "get-plugin-metadata":
		response = map[string]any{
			"name": "trstctl", "description": "Sign with a code-signing key held in trstctl's isolated signer",
			"version": "1.0.0", "url": "https://trstctl.com",
			"supportedContractVersions": []string{contractVersion},
			"capabilities":              []string{"SIGNATURE_GENERATOR.RAW"},
		}
	case "describe-key", "generate-signature":
		var req struct {
			ContractVersion string `json:"contractVersion"`
			KeyID           string `json:"keyId"`
			HashAlgorithm   string `json:"hashAlgorithm"`
			Payload         []byte `json:"payload"`
		}
		if err := json.NewDecoder(io.LimitReader(stdin, 8<<20)).Decode(&req); err != nil {
			return fail("VALIDATION_ERROR", fmt.Errorf("read the request: %w", err))
		}
		if req.ContractVersion != contractVersion {
			return fail("UNSUPPORTED_CONTRACT_VERSION", fmt.Errorf("plugin contract %q is not supported; this plugin speaks %s", req.ContractVersion, contractVersion))
		}
		if strings.TrimSpace(req.KeyID) == "" {
			return fail("VALIDATION_ERROR", errors.New("keyId is required"))
		}
		client, err := newClient()
		if err != nil {
			return fail("VALIDATION_ERROR", err)
		}
		// A signing approval may be pending: the client holds the request open
		// for up to TRSTCTL_APPROVAL_WAIT, so the deadline allows for it.
		ctx, cancel := context.WithTimeout(context.Background(), client.ApprovalWait+2*time.Minute)
		defer cancel()
		cert, err := client.KeyCertificate(ctx, req.KeyID)
		if err != nil {
			return fail("ERROR", err)
		}
		spec, sigAlg, size, err := keySpec(cert.Algorithm)
		if err != nil {
			return fail("VALIDATION_ERROR", err)
		}
		if args[0] == "describe-key" {
			response = map[string]any{"keyId": req.KeyID, "keySpec": spec}
			break
		}
		digest, err := hashPayload(req.HashAlgorithm, req.Payload)
		if err != nil {
			return fail("VALIDATION_ERROR", err)
		}
		// The mechanism is part of what trstctl approves and records.
		signed, err := client.SignDigest(ctx, req.KeyID, "notation:"+sigAlg, digest)
		if err != nil {
			var refused *trstctlsign.APIError
			if errors.As(err, &refused) && refused.Denied() {
				return fail("ACCESS_DENIED", err)
			}
			return fail("ERROR", err)
		}
		raw, err := ecdsaDERToP1363(signed.Signature, size)
		if err != nil {
			return fail("ERROR", err)
		}
		response = map[string]any{
			"keyId": req.KeyID, "signature": raw, "signingAlgorithm": sigAlg, "certificateChain": cert.ChainDER(),
		}
	default:
		return fail("VALIDATION_ERROR", fmt.Errorf("unknown command %q", args[0]))
	}
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		return fail("ERROR", err)
	}
	return 0
}

// keySpec maps trstctl's key algorithm to Notation's key spec. trstctl's
// code-signing API signs SHA-256 digests; Notation pairs P-256 with SHA-256,
// P-384 with SHA-384 and RSA with RSASSA-PSS, so the plugin offers P-256 keys.
func keySpec(algorithm string) (spec, sigAlg string, size int, err error) {
	if strings.EqualFold(algorithm, "ECDSA-P256") {
		return "EC-256", "ECDSA-SHA-256", 32, nil
	}
	return "", "", 0, fmt.Errorf("key algorithm %q: Notation signs through trstctl with an ECDSA P-256 key", algorithm)
}

func hashPayload(name string, payload []byte) ([]byte, error) {
	if name != "SHA-256" {
		return nil, fmt.Errorf("hash algorithm %q is not supported; an EC-256 key signs SHA-256", name)
	}
	sum := sha256.Sum256(payload)
	return sum[:], nil
}

// ecdsaDERToP1363 turns an ASN.1 ECDSA signature into the fixed-size r||s
// form JWS and COSE carry.
func ecdsaDERToP1363(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, errors.New("trstctl returned a signature that is not an ASN.1 ECDSA signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("trstctl returned an ECDSA signature out of range for the key")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
