// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

const DestinationJob = "vdec.reprotect.job"

var ErrExecutorUnavailable = errors.New("reprotect: job executor is delivered by a later VDEC card")

type Handler struct{}

func NewLicensedOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		return Handler{}, nil
	}
}

func (Handler) DeliverLicensed(_ context.Context, m orchestrator.Message) (bool, error) {
	if m.Destination != DestinationJob {
		return false, nil
	}
	var job Job
	if err := json.Unmarshal(m.Payload, &job); err != nil {
		return true, fmt.Errorf("reprotect: decode job payload: %w", err)
	}
	return true, ErrExecutorUnavailable
}
