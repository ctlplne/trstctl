// SPDX-License-Identifier: MPL-2.0

//go:build linux || darwin

package workloadapi

func peerAttestationSupported() bool { return true }
