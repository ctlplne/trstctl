// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"encoding/base64"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/jobmodel"
)

type JobKind = jobmodel.JobKind

const (
	JobKindReEncrypt   = jobmodel.JobKindReEncrypt
	JobKindReWrap      = jobmodel.JobKindReWrap
	JobKindReIssue     = jobmodel.JobKindReIssue
	JobKindRevokeLease = jobmodel.JobKindRevokeLease
	JobKindReDerive    = jobmodel.JobKindReDerive
)

var (
	ErrInvalidState             = jobmodel.ErrInvalidState
	ErrUnsupportedDependentType = jobmodel.ErrUnsupportedDependentType
)

type Job = jobmodel.Job

func PlanFromState(state depstate.KeyState) ([]Job, error) {
	return jobmodel.PlanFromState(state)
}

func validateJob(job Job) error {
	return jobmodel.ValidateJob(job)
}

func dependentKey(dep depstate.Dependent) string {
	return jobmodel.DependentKey(dep)
}

func encodePart(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
