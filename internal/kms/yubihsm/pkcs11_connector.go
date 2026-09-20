// SPDX-License-Identifier: BUSL-1.1

package yubihsm

// The supported production YubiHSM 2 transport is Yubico's
// yubihsm_pkcs11 module. That module talks to yubihsm-connector and exposes the
// standard non-extractable object/sign/destroy operations. Reusing the audited
// PKCS#11 session adapter exercises the actual vendor ABI rather than inventing
// a second HTTP protocol implementation.

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

type PKCS11Config = pkcs11.ModuleConfig

type pkcs11Connector struct{ session pkcs11.Session }

var _ Connector = (*pkcs11Connector)(nil)
var _ LifecycleConnector = (*pkcs11Connector)(nil)
var _ OperationLifecycleConnector = (*pkcs11Connector)(nil)

// OpenPKCS11Connector loads Yubico's PKCS#11 module and authenticates to the
// selected connector-backed token. Static builds fail closed; the shipped cgo
// signer artifact includes this binding.
func OpenPKCS11Connector(cfg PKCS11Config) (Connector, error) {
	session, err := pkcs11.OpenModuleSession(cfg)
	if err != nil {
		return nil, fmt.Errorf("yubihsm2: open vendor PKCS#11 connector: %w", err)
	}
	return &pkcs11Connector{session: session}, nil
}

func (c *pkcs11Connector) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	return c.session.GenerateKey(alg)
}

func (c *pkcs11Connector) GenerateKeyForOperation(operationID string, alg crypto.Algorithm) (string, []byte, error) {
	session, ok := c.session.(pkcs11.OperationSession)
	if !ok {
		return "", nil, fmt.Errorf("yubihsm2: vendor session does not support durable operation generation")
	}
	return session.GenerateKeyForOperation(operationID, alg)
}

func (c *pkcs11Connector) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return c.session.SignDigest(handle, digest, opts)
}

func (c *pkcs11Connector) RevokeKey(handle string) error {
	lifecycle, ok := c.session.(pkcs11.LifecycleSession)
	if !ok {
		return fmt.Errorf("yubihsm2: vendor session does not support revoke")
	}
	return lifecycle.RevokeKey(handle)
}

func (c *pkcs11Connector) ZeroizeKey(handle string) error {
	lifecycle, ok := c.session.(pkcs11.LifecycleSession)
	if !ok {
		return fmt.Errorf("yubihsm2: vendor session does not support zeroize")
	}
	return lifecycle.ZeroizeKey(handle)
}

func (c *pkcs11Connector) RevokeKeyForOperation(operationID, handle string) error {
	session, ok := c.session.(pkcs11.OperationSession)
	if !ok {
		return fmt.Errorf("yubihsm2: vendor session does not support durable operation revoke")
	}
	return session.RevokeKeyForOperation(operationID, handle)
}

func (c *pkcs11Connector) ZeroizeKeyForOperation(operationID, handle string) error {
	session, ok := c.session.(pkcs11.OperationSession)
	if !ok {
		return fmt.Errorf("yubihsm2: vendor session does not support durable operation zeroize")
	}
	return session.ZeroizeKeyForOperation(operationID, handle)
}

func (c *pkcs11Connector) Close() error { return c.session.Close() }
