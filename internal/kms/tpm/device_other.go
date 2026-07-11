// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package tpm

import "errors"

type DeviceConfig struct {
	Path                 string
	OwnerAuth            []byte
	KeyAuth              []byte
	PersistentHandleBase uint32
}

func OpenDevice(DeviceConfig) (Device, error) {
	return nil, errors.New("tpm: production TPM 2.0 device binding is supported on Linux")
}
