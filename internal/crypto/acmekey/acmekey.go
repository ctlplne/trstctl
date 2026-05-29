// Package acmekey builds an ACME client with a fresh account key inside the AN-3
// crypto boundary (a subpackage of internal/crypto). The ACME account key is an
// ECDSA private key; constructing it and wiring it into the client here means the
// Let's Encrypt plugin never imports crypto/* and never names crypto.Signer.
package acmekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"golang.org/x/crypto/acme"
)

// NewClient returns an ACME client for the directory at directoryURL, with a
// freshly generated ECDSA P-256 account key.
func NewClient(directoryURL string) (*acme.Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, DirectoryURL: directoryURL}, nil
}
