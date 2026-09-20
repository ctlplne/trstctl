// SPDX-License-Identifier: BUSL-1.1

package quarantine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

const DestinationCompletion = "xrec.reconciliation-completion"

type Handler struct {
	manager *Manager
}

func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

func NewLicensedOutboxFactory(state *MemoryState) editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		manager := NewManager(Options{
			Log:         d.Log,
			Idempotency: d.Idempotency,
			State:       state,
			Policy:      ReferencePolicy(),
		})
		return NewHandler(manager), nil
	}
}

func (h *Handler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	if m.Destination != DestinationCompletion {
		return false, nil
	}
	if h == nil || h.manager == nil {
		return true, ErrInvalidCompletion
	}
	req, err := DecodeCompletionJob(m.Payload)
	if err != nil {
		return true, err
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		req.IdempotencyKey = strings.TrimSpace(m.IdempotencyKey)
	}
	if strings.TrimSpace(req.Witness.Body.TenantID) != strings.TrimSpace(m.TenantID) {
		return true, fmt.Errorf("%w: tenant mismatch", ErrInvalidCompletion)
	}
	_, err = h.manager.Complete(ctx, req)
	return true, err
}

func EncodeCompletionJob(req CompletionRequest) ([]byte, error) {
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return nil, ErrInvalidCompletion
	}
	return json.Marshal(req)
}

func DecodeCompletionJob(raw []byte) (CompletionRequest, error) {
	if len(raw) == 0 {
		return CompletionRequest{}, ErrInvalidCompletion
	}
	var req CompletionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CompletionRequest{}, fmt.Errorf("%w: decode job: %v", ErrInvalidCompletion, err)
	}
	return req, nil
}
