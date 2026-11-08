// SPDX-License-Identifier: MPL-2.0

package main

import "unicode/utf16"

// The CNG configuration values (bcrypt.h, ncrypt.h) a key storage provider's
// registration uses, as the Cryptographic Provider Development Kit's sample
// provider registers itself.
const (
	cryptLocal                = 0x00000001    // CRYPT_LOCAL: this machine's configuration table
	cryptOverwrite            = 0x00000001    // CRYPT_OVERWRITE: replace an earlier registration
	cryptPriorityBottom       = 0xFFFFFFFF    // CRYPT_PRIORITY_BOTTOM: after the built-in providers
	ncryptKeyStorageInterface = 0x00010001    // NCRYPT_KEY_STORAGE_INTERFACE
	keyStorageFunction        = "KEY_STORAGE" // NCRYPT_KEY_STORAGE_ALGORITHM
)

// cryptInterfaceReg, cryptImageReg and cryptProviderReg are bcrypt.h's
// CRYPT_INTERFACE_REG, CRYPT_IMAGE_REG and CRYPT_PROVIDER_REG. Go lays these
// fields out as C does on 64-bit Windows; registration_test.go checks every
// offset.
type cryptInterfaceReg struct {
	Interface uint32
	Flags     uint32
	Functions uint32
	Names     **uint16
}

type cryptImageReg struct {
	Image      *uint16
	Interfaces uint32
	List       **cryptInterfaceReg
}

type cryptProviderReg struct {
	Aliases    uint32
	AliasList  **uint16
	UserMode   *cryptImageReg
	KernelMode *cryptImageReg
}

// registration is one provider registration with the memory its pointers
// reference, kept together so all of it stays reachable while
// BCryptRegisterProvider reads it.
type registration struct {
	provider  cryptProviderReg
	image     cryptImageReg
	iface     cryptInterfaceReg
	ifaces    [1]*cryptInterfaceReg
	functions [1]*uint16
	imageName []uint16
	function  []uint16
}

// newRegistration describes a user-mode image that implements the key
// storage interface, as BCryptRegisterProvider takes it. A key storage
// provider has no kernel-mode image and no aliases.
func newRegistration(image string) *registration {
	r := &registration{imageName: utf16z(image), function: utf16z(keyStorageFunction)}
	r.functions[0] = &r.function[0]
	r.iface = cryptInterfaceReg{Interface: ncryptKeyStorageInterface, Flags: cryptLocal, Functions: 1, Names: &r.functions[0]}
	r.ifaces[0] = &r.iface
	r.image = cryptImageReg{Image: &r.imageName[0], Interfaces: 1, List: &r.ifaces[0]}
	r.provider = cryptProviderReg{UserMode: &r.image}
	return r
}

// utf16z encodes s as a NUL-terminated UTF-16 string.
func utf16z(s string) []uint16 { return append(utf16.Encode([]rune(s)), 0) }
