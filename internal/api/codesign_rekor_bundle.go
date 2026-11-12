// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// A signature's transparency-log entry as a cosign bundle (P9-L2). trstctl
// publishes each signature to Rekor through the outbox and keeps the receipt
// once it verifies; a release pipeline attaches the bundle to the signature
// (cosign attach signature --rekor-response), and stock cosign verify then
// checks the log's signed entry timestamp offline against the log's key
// instead of skipping the transparency log.

// CodeSigningRekorBundle is a signing operation's recorded Rekor entry.
type CodeSigningRekorBundle struct {
	OperationID    string    `json:"operation_id"`
	EntryUUID      string    `json:"entry_uuid"`
	LogIndex       int64     `json:"log_index"`
	LogID          string    `json:"log_id"`
	IntegratedTime int64     `json:"integrated_time"`
	RecordedAt     time.Time `json:"recorded_at"`
	// CosignBundle is the bundle document, as cosign reads it (the file
	// cosign sign-blob --bundle writes: the signature and its Rekor bundle):
	// save it and pass it to cosign attach signature --rekor-response, or to
	// cosign verify-blob --bundle.
	CosignBundle string `json:"cosign_bundle"`
}

// ErrCodeSigningTransparencyNotRecorded reports an operation whose
// transparency entry has not been recorded (yet: publication rides the outbox).
var ErrCodeSigningTransparencyNotRecorded = errors.New("no transparency-log entry is recorded for this signing operation yet")

// CodeSigningRekorBundleProvider reads an operation's recorded entry.
type CodeSigningRekorBundleProvider func(ctx context.Context, tenantID, operationID string) (CodeSigningRekorBundle, error)

// WithCodeSigningRekorBundles wires the transparency-entry reader (P9-L2).
func WithCodeSigningRekorBundles(fn CodeSigningRekorBundleProvider) Option {
	return func(c *config) { c.codeSigningRekorBundles = fn }
}

func (a *API) getCodeSigningRekorBundle(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	operationID := strings.TrimSpace(r.PathValue("operation_id"))
	if operationID == "" || len(operationID) > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "operation_id is required"))
		return
	}
	if a.codeSigningRekorBundles == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	bundle, err := a.codeSigningRekorBundles(r.Context(), tenantID, operationID)
	if errors.Is(err, ErrCodeSigningTransparencyNotRecorded) {
		a.writeError(w, errStatusFrom(http.StatusNotFound, err))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, bundle)
}
