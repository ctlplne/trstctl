// SPDX-License-Identifier: BUSL-1.1

//go:build !cgo

package pkcs11

import "errors"

// ModuleConfig describes a logged-in PKCS#11 module session. The concrete opener
// lives in session_cgo.go; static no-cgo builds keep the type available so config
// parsing can fail closed with an actionable message.
type ModuleConfig struct {
	ModulePath     string
	TokenLabel     string
	UserPIN        []byte
	KeyLabelPrefix string
}

// OpenModuleSession fails closed in static builds. Operators that use local HSMs
// build the managed-key package with cgo so the native PKCS#11 module can be loaded.
func OpenModuleSession(ModuleConfig) (Session, error) {
	return nil, errors.New("pkcs11: native module support requires a cgo-enabled build")
}
