// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"encoding/json"
	"sort"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/crypto"
)

// AuthorityFingerprint excludes mutable usage timestamps while retaining exact
// policy source digests/versions and canonical trust. A later native read must
// still name the approved role and authority before replacement can proceed.
func AuthorityFingerprint(identity awsiam.Identity) (string, error) {
	type receipt struct{ ID, Category, Version, SHA256 string }
	values := make([]receipt, 0, len(identity.PolicyReceipts))
	for _, p := range identity.PolicyReceipts {
		values = append(values, receipt{p.ID, p.Category, p.Version, p.SHA256})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Category != values[j].Category {
			return values[i].Category < values[j].Category
		}
		if values[i].ID != values[j].ID {
			return values[i].ID < values[j].ID
		}
		if values[i].Version != values[j].Version {
			return values[i].Version < values[j].Version
		}
		return values[i].SHA256 < values[j].SHA256
	})
	raw, err := json.Marshal(struct {
		ARN, NativeID string
		Policies      []receipt
		Trust         json.RawMessage
	}{identity.Principal.ARN, identity.NativeID, values, identity.TrustDocument})
	if err != nil {
		return "", err
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(canonical), nil
}
