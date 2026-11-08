// SPDX-License-Identifier: MPL-2.0

// Package kspinfo names the trstctl Windows key storage provider: the name
// CNG registers and signing tools open it by, and the DLL file name it is
// installed under in System32. The provider (ksp) and its registration tool
// (cmd/trstctl-ksp-register) share them.
package kspinfo

const (
	// ProviderName is the CNG provider name: signtool's /csp and
	// NCryptOpenStorageProvider take it.
	ProviderName = "trstctl Key Storage Provider"
	// ImageName is the provider DLL's file name in System32.
	ImageName = "trstctl-ksp.dll"
)
