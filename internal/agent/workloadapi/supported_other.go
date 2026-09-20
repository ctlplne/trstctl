// SPDX-License-Identifier: BUSL-1.1

//go:build !linux && !darwin

package workloadapi

func peerAttestationSupported() bool { return false }
