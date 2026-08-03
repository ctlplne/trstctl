// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// Detached statement signatures for the agent channel (epic A1).
//
// mTLS already proves who is on the connection, so it is worth being precise
// about what this adds — otherwise it is ceremony. mTLS authenticates a
// SESSION. It leaves behind nothing an auditor can check: the server writes
// "agent-7 reported this deploy executed" into the event log, and the only
// evidence for that sentence is the server's own record of a TLS session that
// ended. Anyone who can write to the event store can write that sentence.
//
// A detached signature over the report is evidence AT REST. It survives the
// connection, it is verifiable by anyone holding the agent's certificate, and
// it is not producible by the control plane — which is exactly the property you
// want in the record that says a machine you do not control changed a
// certificate on a load balancer you cannot see.
//
// The signature is over a canonical statement built by the caller. This file
// deliberately knows nothing about job receipts: it signs and verifies bytes,
// and the wire contract that defines those bytes lives with the wire contract.

// receiptSignatureDomain separates these signatures from every other use of an
// agent's key. Without a domain tag, a signature produced for one purpose can be
// presented as one produced for another — a CSR self-signature replayed as a
// receipt, say. The tag is hashed in, so the two can never collide.
const receiptSignatureDomain = "trstctl/agent-statement/v1\n"

// SignStatement signs a canonical statement with the agent's own key.
//
// The key never leaves this boundary (AN-3): the caller hands over bytes and
// receives a signature, exactly as it does for a CSR.
func (a *AgentIdentity) SignStatement(statement []byte) ([]byte, error) {
	if a == nil || a.key == nil {
		return nil, errors.New("mtls: agent identity is destroyed")
	}
	if len(statement) == 0 {
		return nil, errors.New("mtls: refusing to sign an empty statement")
	}
	digest := statementDigest(statement)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("mtls: sign statement: %w", err)
	}
	return sig, nil
}

// VerifyStatement checks a detached signature against the public key in a peer
// certificate.
//
// certDER is the certificate the caller AUTHENTICATED WITH, read off the
// verified TLS peer chain — never a certificate carried in the request. That is
// the whole binding: a receipt verifies only against the identity that
// presented it, so a receipt signed by one agent cannot be replayed on another
// agent's connection, and one signed for a different tenant cannot be replayed
// here because the tenant is inside the statement.
func VerifyStatement(certDER, statement, signature []byte) error {
	if len(certDER) == 0 {
		return errors.New("mtls: no peer certificate to verify against")
	}
	if len(statement) == 0 {
		return errors.New("mtls: empty statement")
	}
	if len(signature) == 0 {
		return errors.New("mtls: no signature")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("mtls: parse peer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("mtls: peer certificate does not carry an ECDSA key")
	}
	digest := statementDigest(statement)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return errors.New("mtls: statement signature does not verify against the peer certificate")
	}
	return nil
}

// statementDigest hashes the domain tag and the statement together, so a
// signature is bound to the purpose as well as the content.
func statementDigest(statement []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(receiptSignatureDomain))
	h.Write(statement)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
