// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSecretImportRequestWipesPartialValuesOnEveryDecodeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{
			name: "later map value has wrong type",
			body: `{"values":{"decoded-first":"must-be-wiped","invalid":123}}`,
		},
		{
			name: "second JSON document",
			body: `{"values":{"decoded-first":"must-be-wiped"}} {}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := decodeSecretImportRequest(httptest.NewRequest("POST", "/api/v1/secrets/store/import", strings.NewReader(tc.body)))
			if err == nil {
				t.Fatal("decode unexpectedly succeeded")
			}
			if len(req.Values) != 0 {
				t.Fatalf("decode error retained %d secret values", len(req.Values))
			}
		})
	}
}
