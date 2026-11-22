// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// KeyClassTenantCA is the only signer key class a tenant CA import may bind.
// Platform, PCAS, AGID and unclassified legacy keys are never in this class.
const KeyClassTenantCA = "tenant-ca"

const (
	mdKeyOwnerTenant = "trstctl-key-owner-tenant"
	mdKeyClass       = "trstctl-key-class"
)

var errInvalidKeyOwnership = errors.New("signing: key ownership must name one canonical tenant and the tenant-ca class")

func canonicalKeyOwnerTenant(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := range value {
		c := value[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// These signer namespaces belong to platform or custody services, even when
// a tenant knows the handle. A caller cannot label one as an importable CA.
func reservedTenantCAHandle(handle string) bool {
	return handle == "issuing-ca" || handle == "agent-ca" ||
		strings.HasPrefix(handle, "pcas:") || strings.HasPrefix(handle, "agid-")
}

// requestedKeyOwnership reads an atomic owner/class pair on GenerateKey or
// GetPublicKey. A missing pair keeps generic key operations compatible; a
// partial or duplicated pair cannot silently become an unowned key.
func requestedKeyOwnership(ctx context.Context) (string, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", nil
	}
	owners, classes := md.Get(mdKeyOwnerTenant), md.Get(mdKeyClass)
	if len(owners) == 0 && len(classes) == 0 {
		return "", "", nil
	}
	if len(owners) != 1 || len(classes) != 1 || !canonicalKeyOwnerTenant(owners[0]) || classes[0] != KeyClassTenantCA {
		return "", "", errInvalidKeyOwnership
	}
	return owners[0], classes[0], nil
}

func (kc keyConstraints) isTenantCAFor(tenantID string) bool {
	return kc.ownerTenantID == tenantID && kc.keyClass == KeyClassTenantCA &&
		kc.requireAuth && !kc.offlineOnly && !kc.custodyOnly && !kc.genericPCAS && !kc.artifactOnly &&
		len(kc.purposes) == 1 && kc.purposes[signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN] && len(kc.hashes) == 0
}
