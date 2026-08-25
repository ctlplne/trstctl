// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteErrorClassifiesClientCancellationWithoutAFalse500(t *testing.T) {
	a := New(nil, nil, nil)
	rec := httptest.NewRecorder()

	a.writeError(rec, context.Canceled)

	if rec.Code != 499 {
		t.Fatalf("client cancellation status = %d, want 499", rec.Code)
	}
	var body struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if body.Status != 499 || body.Title != "Client Closed Request" || body.Detail != "request canceled by client" {
		t.Fatalf("client cancellation problem = %+v", body)
	}
}
