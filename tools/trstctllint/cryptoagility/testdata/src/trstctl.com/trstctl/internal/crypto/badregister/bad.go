// SPDX-License-Identifier: MPL-2.0

package badregister

func RegisterCryptoSuite(name string, implementation any) { // want `runtime crypto suite/provider registration function`
	_, _ = name, implementation
}
