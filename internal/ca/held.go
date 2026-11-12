// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"context"
	"errors"
	"fmt"
)

// A request a CA holds for a manager's approval (AD CS's "taken under
// submission") outlives the issuance attempt that submitted it (N1-L1). The
// CA's own request id is the handle: reading the request back by it is safe
// however often it is done, because a read cannot issue a second certificate.

// ErrIssuanceHeld matches a *HeldError: the CA holds the request for approval.
var ErrIssuanceHeld = errors.New("ca: the CA holds the request for approval")

// ErrRequestRefused matches a CA's definitive refusal of a request (for
// example a denial), as opposed to a failure to reach the CA.
var ErrRequestRefused = errors.New("ca: the CA refused the request")

// ErrHeldRetrievalUnsupported means the authority cannot read a held request
// back by its request id.
var ErrHeldRetrievalUnsupported = errors.New("ca: this authority cannot read a held request back")

// HeldError is a request the CA holds for approval, named by the CA's request
// id.
type HeldError struct {
	RequestID int
}

func (e *HeldError) Error() string {
	return fmt.Sprintf("ca: the CA holds request %d for approval", e.RequestID)
}

// Is matches ErrIssuanceHeld.
func (e *HeldError) Is(target error) bool { return target == ErrIssuanceHeld }

// HeldRequestID returns the CA request id of a request the CA holds for
// approval, when err says so.
func HeldRequestID(err error) (int, bool) {
	var held *HeldError
	if errors.As(err, &held) && held.RequestID > 0 {
		return held.RequestID, true
	}
	return 0, false
}

// HeldRetriever reads a held request back by the CA's request id: the issued
// certificate once the request is approved, a *HeldError while the CA still
// holds it, or the CA's refusal (matching ErrRequestRefused) once denied.
type HeldRetriever interface {
	RetrieveHeld(ctx context.Context, requestID int) (Certificate, error)
}

// RetrieveHeldThrough reads a held request back via c when it can, and returns
// ErrHeldRetrievalUnsupported when it cannot.
func RetrieveHeldThrough(ctx context.Context, c CA, requestID int) (Certificate, error) {
	if requestID <= 0 {
		return Certificate{}, errors.New("ca: a held request needs its CA request id")
	}
	r, ok := c.(HeldRetriever)
	if !ok {
		return Certificate{}, ErrHeldRetrievalUnsupported
	}
	return r.RetrieveHeld(ctx, requestID)
}
