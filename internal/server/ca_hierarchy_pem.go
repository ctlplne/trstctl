// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/pem"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/api"
)

func csrDERFromPEM(csrPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: csr_pem must contain one CERTIFICATE REQUEST PEM block", api.ErrCAHierarchyInvalid)
	}
	return block.Bytes, nil
}

func certificateChainPEM(raw string) ([][]byte, string, error) {
	rest := []byte(raw)
	var chain [][]byte
	var normalized []byte
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, "", fmt.Errorf("%w: certificate_pem contains trailing non-PEM data", api.ErrCAHierarchyInvalid)
			}
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, "", fmt.Errorf("%w: certificate_pem must not contain private key material", api.ErrCAHierarchyInvalid)
		}
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("%w: certificate_pem contains unsupported PEM block %q", api.ErrCAHierarchyInvalid, block.Type)
		}
		der := append([]byte(nil), block.Bytes...)
		chain = append(chain, der)
		normalized = append(normalized, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		rest = next
	}
	if len(chain) == 0 {
		return nil, "", fmt.Errorf("%w: certificate_pem must contain at least one CERTIFICATE PEM block", api.ErrCAHierarchyInvalid)
	}
	return chain, string(normalized), nil
}

func singleCertificatePEM(raw string) ([]byte, string, error) {
	rest := []byte(raw)
	var der []byte
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, "", fmt.Errorf("%w: certificate_pem contains trailing non-PEM data", api.ErrCAHierarchyInvalid)
			}
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, "", fmt.Errorf("%w: certificate_pem must not contain private key material", api.ErrCAHierarchyInvalid)
		}
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("%w: certificate_pem contains unsupported PEM block %q", api.ErrCAHierarchyInvalid, block.Type)
		}
		if der != nil {
			return nil, "", fmt.Errorf("%w: certificate_pem must contain exactly one CERTIFICATE block", api.ErrCAHierarchyInvalid)
		}
		der = append([]byte(nil), block.Bytes...)
		rest = next
	}
	if der == nil {
		return nil, "", fmt.Errorf("%w: certificate_pem must contain one CERTIFICATE PEM block", api.ErrCAHierarchyInvalid)
	}
	normalized := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return der, normalized, nil
}
