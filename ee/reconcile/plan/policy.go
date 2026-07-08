// SPDX-License-Identifier: LicenseRef-trstctl-EE

package plan

import (
	"strings"

	"trstctl.com/trstctl/ee/reconcile/witness"
)

type OperationPolicy interface {
	Allows(divergenceClass, operation string) bool
}

type classPolicy map[string]map[string]struct{}

func DefaultOperationPolicy() OperationPolicy {
	return classPolicy{
		witness.ClassPresence: {
			"create": {}, "delete": {}, "sync": {},
		},
		witness.ClassAttributeConflict: {
			"update": {}, "revoke": {},
		},
		witness.ClassPolicyViolation: {
			"update": {}, "revoke": {},
		},
		witness.ClassStaleness: {
			"refresh": {}, "sync": {},
		},
	}
}

func (p classPolicy) Allows(divergenceClass, operation string) bool {
	ops, ok := p[strings.TrimSpace(divergenceClass)]
	if !ok {
		return false
	}
	_, ok = ops[strings.ToLower(strings.TrimSpace(operation))]
	return ok
}
